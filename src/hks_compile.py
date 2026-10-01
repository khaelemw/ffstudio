"""Lua source -> T7 HKS bytecode, using the external hksc compiler (github.com/Jake-NotTheMuss/hksc, built for
COD T7). Finds an hksc binary and compiles source into an HKS rawfile buffer. hksc isn't bundled; if it can't be
found, the result includes build instructions. Bytecode-level edits are in hks_reserialize.
"""
import os, sys, subprocess, tempfile, shutil

# hksc build for T7 (Black Ops 3). autotools flow; the game variant is selected at configure/build time.
BUILD_HELP = (
    "No hksc compiler found. To enable source-level Lua recompile, build Jake-NotTheMuss/hksc for T7:\n"
    "  git clone https://github.com/Jake-NotTheMuss/hksc\n"
    "  cd hksc && ./configure --enable-cod=t7   (or set LUA_CODT6+LUA_CODT7 in hkscconf.h)\n"
    "  make                                     (needs a C toolchain: MinGW gcc or MSVC)\n"
    "Then point this bridge at the binary: set env HKSC_PATH=<path to hksc(.exe)>, or pass hksc_path=.\n"
    "Verify: `hksc -h` should list -c/--compile and, for COD builds, -s (strip) / -g (--with-debug)."
)

def find_hksc(hksc_path=None):
    """Locate an hksc binary: explicit arg, $HKSC_PATH, PATH, or common local build dirs. Returns path or None."""
    cands = []
    if hksc_path: cands.append(hksc_path)
    if os.environ.get('HKSC_PATH'): cands.append(os.environ['HKSC_PATH'])
    for nm in ('hksc', 'hksc.exe'):
        w = shutil.which(nm)
        if w: cands.append(w)
    # look in hksc/ and tools/ next to the code and in the repo root
    ffdir = os.path.dirname(os.path.abspath(__file__))
    bases = [ffdir, os.path.dirname(ffdir)]
    if getattr(sys, 'frozen', False):                # standalone exe: look next to the exe too
        bases.insert(0, os.path.dirname(sys.executable))
    for base in bases:
        for rel in ('hksc/hksc.exe', 'hksc/hksc', 'hksc/src/hksc.exe', 'hksc/src/hksc', 'tools/hksc.exe', 'tools/hksc'):
            cands.append(os.path.join(base, rel))
    for c in cands:
        if c and os.path.isfile(c):
            return c
    return None

def compile_source(lua_text, hksc_path=None, strip=True, extra_args=None):
    """Compile Lua source text to a T7 HKS bytecode buffer. Returns dict:
       {ok, buffer(bytes|None), hksc(path|None), error, stderr, build_help}."""
    exe = find_hksc(hksc_path)
    if exe is None:
        return {'ok': False, 'buffer': None, 'hksc': None, 'error': 'hksc not found',
                'stderr': '', 'build_help': BUILD_HELP}
    tmp = tempfile.mkdtemp(prefix='hkscompile_')
    src = os.path.join(tmp, 'in.lua'); out = os.path.join(tmp, 'out.bin')
    try:
        with open(src, 'w', encoding='latin1', errors='replace') as f:
            f.write(lua_text)
        args = [exe, '-c', ('-s' if strip else '-g'), '-o', out] + (extra_args or []) + [src]
        _nw = 0x08000000 if sys.platform == 'win32' else 0   # CREATE_NO_WINDOW (no console flash in windowed app)
        p = subprocess.run(args, capture_output=True, text=True, timeout=60, creationflags=_nw)
        if p.returncode != 0 or not os.path.isfile(out):
            return {'ok': False, 'buffer': None, 'hksc': exe,
                    'error': f'hksc exit {p.returncode}', 'stderr': (p.stderr or p.stdout)[:4000],
                    'build_help': ''}
        with open(out, 'rb') as f:
            buf = f.read()
        ok = buf[:5] == b'\x1bLuaQ'
        return {'ok': ok, 'buffer': buf, 'hksc': exe,
                'error': '' if ok else 'output is not a LuaQ chunk', 'stderr': p.stderr[:2000], 'build_help': ''}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
