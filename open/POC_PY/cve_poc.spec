# -*- mode: python ; coding: utf-8 -*-


from PyInstaller.utils.hooks import collect_data_files
import os

a = Analysis(
    ['poc_gui.py'],
    pathex=[],
    binaries=[],
    # include payloads and mapping json plus PyQt5 plugin data (Qt plugins)
    datas=[('payloads', 'payloads'), ('fingerprint_cve_mapping.json', '.')] + collect_data_files('PyQt5', subdir='Qt/plugins'),
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=['rth_qt_plugins.py'],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='cve_poc',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
