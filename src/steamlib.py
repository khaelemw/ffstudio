"""Locate Steam library folders and the Black Ops III / Mod Tools installs."""
import os
import re
import sys

BO3_DIR = 'Call of Duty Black Ops III'
MODTOOLS_DIR = 'Call of Duty Black Ops III 455130'
BO3_APPID = '311210'


def _steam_root():
    """The main Steam install folder, from the registry on Windows, else common default locations."""
    if sys.platform == 'win32':
        try:
            import winreg
            for hive, key, val in ((winreg.HKEY_CURRENT_USER, r'Software\Valve\Steam', 'SteamPath'),
                                   (winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\WOW6432Node\Valve\Steam', 'InstallPath'),
                                   (winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Valve\Steam', 'InstallPath')):
                try:
                    with winreg.OpenKey(hive, key) as k:
                        p = winreg.QueryValueEx(k, val)[0]
                    if p and os.path.isdir(p):
                        return os.path.normpath(p)
                except OSError:
                    pass
        except ImportError:
            pass
    for p in (r'C:\Program Files (x86)\Steam', r'C:\Program Files\Steam', os.path.expanduser('~/.steam/steam')):
        if os.path.isdir(p):
            return os.path.normpath(p)
    return None


def libraries():
    """Every Steam library folder (each one contains steamapps/), main install first."""
    root = _steam_root()
    libs = []
    if root:
        libs.append(root)
        vdf = os.path.join(root, 'steamapps', 'libraryfolders.vdf')
        try:
            text = open(vdf, encoding='utf-8', errors='replace').read()
        except OSError:
            text = ''
        for m in re.finditer(r'"path"\s+"([^"]+)"', text):
            p = os.path.normpath(m.group(1).replace('\\\\', '\\'))
            if os.path.normcase(p) not in {os.path.normcase(x) for x in libs} and os.path.isdir(p):
                libs.append(p)
    return libs


def find_app_dir(name):
    """steamapps/common/<name> in the first library that has it, else None."""
    for lib in libraries():
        p = os.path.join(lib, 'steamapps', 'common', name)
        if os.path.isdir(p):
            return p
    return None


def workshop_dirs():
    """The BO3 workshop content folder in each library that has one."""
    out = []
    for lib in libraries():
        p = os.path.join(lib, 'steamapps', 'workshop', 'content', BO3_APPID)
        if os.path.isdir(p):
            out.append(p)
    return out
