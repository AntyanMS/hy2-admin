# -*- mode: python ; coding: utf-8 -*-
import os
from pathlib import Path

spec_dir = os.path.dirname(os.path.abspath(SPEC))
root = Path(spec_dir)

block_cipher = None

templates_dir = root / "templates"
datas = []
if templates_dir.is_dir():
    datas.append((str(templates_dir), "templates"))

a = Analysis(
    ["launcher.py"],
    pathex=[str(root)],
    binaries=[],
    datas=datas,
    hiddenimports=[
        "PIL._imagingtk",
        "PIL._tkinter_finder",
        "pyotp",
        "asgiref.wsgi",
        "hypercorn.protocol",
        "hypercorn.logging",
        "hypercorn.events",
        "h11",
        "wsproto",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="hy2-admin-panel",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
