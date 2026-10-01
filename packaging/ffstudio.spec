# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for a single-file, windowed FFStudio.exe with Python, numpy, Pillow, pywebview and the UI.

Build:   pyinstaller ffstudio.spec          (or run build_exe.bat)
Output:  dist/FFStudio.exe

ACTS, the BO3 Mod Tools and hksc are not bundled; FF Studio looks for acts/bin/acts.exe and tools/hksc.exe next
to the exe.
"""
import os
from PyInstaller.utils.hooks import collect_submodules

SPEC_DIR = os.path.abspath(SPECPATH)         # PyInstaller sets SPECPATH to this spec file's dir (packaging/)
SRC = os.path.join(SPEC_DIR, '..', 'src')    # all FF Studio source lives in ../src

# Data files read at runtime (not imported): the front-end resources served by the local HTTP layer, plus
# fwalk.py which grow_engine loads via open()+exec relative to its own folder (bundle root when frozen).
datas = [(os.path.join(SRC, 'ffstudio.html'), '.'),
         (os.path.join(SRC, 'three.min.js'), '.'),
         (os.path.join(SRC, 'ffstudio.ico'), '.'),
         (os.path.join(SRC, 'fwalk.py'), '.')]

# Local modules, listed explicitly so PyInstaller always collects them (all live in ../src).
hiddenimports = [
    'ffbuild', 'ffassets', 'ffbo3', 'grow_engine', 'gsc_remap', 'ff_deserialize', 'reserializer',
    'foreach_convert', 'resolve_externals', 'ternary_convert', 't7hash', 'bootstrap', 'steamlib',
    'fx_decode', 'fx_to_efx', 'fx_curves', 'xpak', 'base_assets', 'xanim_decode', 'ffstudio',
    'hks_disasm', 'hks_decompile', 'hks_reserialize', 'hks_compile',
    'PIL.Image', 'PIL.DdsImagePlugin', 'PIL.PngImagePlugin', 'PIL.BmpImagePlugin', 'PIL.JpegImagePlugin',
] + collect_submodules('numpy', filter=lambda n: '.tests' not in n and not n.endswith('conftest'))

a = Analysis(
    [os.path.join(SRC, 'ffstudio_app.py')],
    pathex=[SRC],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=['tkinter', 'matplotlib', 'PyQt5', 'PySide2', 'pytest'],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz, a.scripts, a.binaries, a.datas, [],
    name='FFStudio',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    runtime_tmpdir=None,
    console=False,          # windowed app; falls back to the browser version if WebView2 is absent
    disable_windowed_traceback=False,
    icon=os.path.join(SRC, 'ffstudio.ico'),
)
