"""ffbuild.py — one-call orchestrator behind the FF Studio app.

Turns "load ff -> edit script source -> build" into a single pipeline, hiding: ACTS decompile, prep (foreach->
for, #using backslashes, resolve externals, HEX-namespace fix), linker-project scaffolding, the official linker
build, source-only hash remap, and the grow/delta-0 splice (grow_engine). Returns a new, self-validated ff.

Public API used by the GUI:
    check_deps(game_root=None, acts=None) -> {name: {ok, path, hint}}
    open_ff(ff_path)                       -> {info, scripts:[...]}
    decompile(ff_path, name, ...)          -> source_text (cached)
    build(ff_path, edits, out_path, ...)   -> {out_path, log, per_script:[...]}
"""
import os, sys, re, glob, shutil, struct, subprocess, hashlib
import ffbo3
import grow_engine
import steamlib
from gsc_remap import build_map_from_source, remap_gsc, hasht7
import foreach_convert, resolve_externals, ternary_convert

HERE = os.path.dirname(os.path.abspath(__file__))
def _find_acts():
    """Locate acts.exe: $ACTS_PATH, acts/bin next to the exe (when frozen) or in the repo root, then PATH.
    Returns the first that exists, else the repo-root default so check_deps can report where it should go."""
    cands = []
    if os.environ.get('ACTS_PATH'):
        cands.append(os.environ['ACTS_PATH'])
    if getattr(sys, 'frozen', False):
        exe_dir = os.path.dirname(sys.executable)
        cands += [os.path.join(exe_dir, 'acts', 'bin', 'acts.exe'),          # acts shipped next to the exe
                  os.path.join(exe_dir, '..', 'acts', 'bin', 'acts.exe'),    # exe in dist/, acts in ffstudio/
                  os.path.join(getattr(sys, '_MEIPASS', exe_dir), 'acts', 'bin', 'acts.exe')]
    cands += [os.path.join(HERE, '..', 'acts', 'bin', 'acts.exe'),           # repo root: ffstudio/acts/bin (code in src/)
              os.path.join(HERE, 'acts', 'bin', 'acts.exe')]                 # alongside the code
    w = shutil.which('acts.exe') or shutil.which('acts')
    if w: cands.append(w)
    for c in cands:
        c = os.path.normpath(c)
        if os.path.isfile(c):
            return c
    return os.path.normpath(os.path.join(HERE, '..', 'acts', 'bin', 'acts.exe'))  # repo-root default (may be absent)
DEFAULT_ACTS = _find_acts()

# On Windows, keep child processes (ACTS, the linker, mklink) from popping console windows when FF Studio runs
# as a windowed app (the bundled exe or pythonw). Applied to every subprocess call below.
_NO_WINDOW = 0x08000000 if sys.platform == 'win32' else 0   # CREATE_NO_WINDOW
def _data_dir():
    """Writable cache dir: next to the source, or next to the exe when frozen (never inside the PyInstaller
    bundle, which is a temp dir removed on exit)."""
    base = os.path.dirname(sys.executable) if getattr(sys, 'frozen', False) else HERE
    return os.path.join(base, '_studio_cache')
CACHE = _data_dir()


# Decompressed payload (+header) per ff, keyed by path+size+mtime, keeping the last few ffs so repeated calls and
# switching mods don't decompress again.
_PAY_CACHE = {}           # abspath -> (sig, payload, header)
_PAY_ORDER = []           # LRU of abspaths
_PAY_KEEP = 3


def _payload(ff_path):
    """(payload_bytes, header) for `ff_path`, decompressed once and cached in memory."""
    key = os.path.abspath(ff_path)
    try:
        st = os.stat(key); sig = (st.st_size, int(st.st_mtime_ns))
    except OSError:
        sig = None
    hit = _PAY_CACHE.get(key)
    if hit and hit[0] == sig:
        if _PAY_ORDER and _PAY_ORDER[-1] != key:
            try: _PAY_ORDER.remove(key)
            except ValueError: pass
            _PAY_ORDER.append(key)
        return hit[1], hit[2]
    pay, h = ffbo3.decompress(open(ff_path, 'rb').read())
    _PAY_CACHE[key] = (sig, pay, h)
    if key in _PAY_ORDER: _PAY_ORDER.remove(key)
    _PAY_ORDER.append(key)
    while len(_PAY_ORDER) > _PAY_KEEP:                # evict oldest to bound memory
        _PAY_CACHE.pop(_PAY_ORDER.pop(0), None)
    return pay, h


def find_game_root(game_root=None):
    """The BO3 Mod Tools folder: the given path if it exists, else found through the Steam libraries."""
    if game_root and os.path.isdir(game_root):
        return game_root
    return steamlib.find_app_dir(steamlib.MODTOOLS_DIR) or game_root


def check_deps(game_root=None, acts=None):
    acts = acts or DEFAULT_ACTS
    gr = find_game_root(game_root)
    linker = os.path.join(gr, 'bin', 'linker_modtools.exe') if gr else None
    raw = os.path.join(gr, 'share', 'raw') if gr else None
    d = {}
    d['acts'] = {'ok': os.path.isfile(acts), 'path': acts,
                 'hint': 'ACTS (atian-cod-tools) acts.exe not found. Download v3.2.1 — '
                         'https://github.com/ate47/atian-cod-tools/releases/download/3.2.1/acts.zip — and extract '
                         'it so acts/bin/acts.exe sits next to FF Studio (or in the repo root). Only needed for '
                         'GSC script decompile/rebuild; everything else works without it.'}
    d['modtools'] = {'ok': bool(linker) and os.path.isfile(linker), 'path': linker or '(game root not found)',
                     'hint': 'BO3 Mod Tools (Steam app 455130) — install "Call of Duty: Black Ops III - Mod Tools" '
                             'from your Steam Library > Tools. Needed: bin/linker_modtools.exe.'}
    d['share_raw'] = {'ok': bool(raw) and os.path.isdir(raw), 'path': raw or '(game root not found)',
                      'hint': 'Mod Tools base scripts (share/raw) — comes with the Mod Tools install above.'}
    d['game_root'] = {'ok': bool(gr), 'path': gr or '(not found)',
                      'hint': 'Could not locate the "Call of Duty Black Ops III 455130" (Mod Tools) folder — '
                              'set it manually.'}
    # Python packages the viewers need. numpy + Pillow are required (image/mesh decode); pywebview is optional
    # (only the native desktop window — the browser version runs without it). `pip install -r requirements.txt`
    # (or the bundled bootstrap) installs them. Reported here so the in-app Dependencies panel is complete.
    import importlib.util as _u
    for pkg, spec, req, why in (('numpy', 'numpy', True, 'image & mesh decoding'),
                                ('Pillow', 'PIL', True, 'texture decode/encode (image viewer + replace)'),
                                ('pywebview', 'webview', False, 'native desktop window (optional — browser mode works without it)')):
        present = _u.find_spec(spec) is not None
        d['py_' + pkg.lower()] = {'ok': present, 'optional': not req,
                                  'path': f'{pkg} (installed)' if present else f'{pkg} (not installed)',
                                  'hint': f'Python package for {why}. Install with:  pip install {pkg}'}
    # _all_ok ignores optional deps (pywebview) and the Mod-Tools group needed only for GSC rebuilds.
    d['_all_ok'] = all(v['ok'] for k, v in d.items()
                       if not k.startswith('_') and not v.get('optional'))
    d['_game_root'] = gr
    d['_acts'] = acts
    return d


def list_ffs(game_root=None, min_size=4096):
    """Enumerate installed mods (Steam workshop + local mods/usermaps) with their DISPLAY NAMES and the .ff files
    each contains, so the GUI can show a navigator by name instead of by workshop id. Localization stub ffs
    (< min_size, e.g. the 896B/2176B en_/fr_/… placeholders) are hidden. Returns {game_root, mods:[{name, id,
    source, path, ffs:[{name, path, size}]}]}."""
    import json as _json
    gr = find_game_root(game_root)
    out = {'game_root': gr, 'mods': []}

    def ffs_in(folder):
        pats = ['*.ff', os.path.join('zone', '*.ff'), os.path.join('*', 'zone', '*.ff'),
                os.path.join('mods', '*', 'zone', '*.ff'), os.path.join('usermaps', '*', 'zone', '*.ff')]
        found = {}
        for pat in pats:
            for fp in glob.glob(os.path.join(folder, pat)):
                if fp.lower().endswith('.studio.ff'):
                    continue                       # skip FF Studio's own build outputs
                try:
                    sz = os.path.getsize(fp)
                except OSError:
                    continue
                if sz < min_size:
                    continue
                found[os.path.abspath(fp)] = {'name': os.path.basename(fp), 'path': fp, 'size': sz}
        return sorted(found.values(), key=lambda f: -f['size'])

    def add(folder, name, source, wid):
        ffs = ffs_in(folder)
        if ffs:
            out['mods'].append({'name': name, 'id': wid, 'source': source, 'path': folder, 'ffs': ffs})

    # Steam workshop mods, in every Steam library
    for ws in steamlib.workshop_dirs():
        for wid in os.listdir(ws):
            d = os.path.join(ws, wid)
            if not os.path.isdir(d):
                continue
            title = wid
            wj = os.path.join(d, 'workshop.json')
            if os.path.isfile(wj):
                try:
                    j = _json.load(open(wj, encoding='utf-8', errors='replace'))
                    title = (j.get('Title') or j.get('title') or wid).strip() or wid
                except Exception:
                    pass
            add(d, title, 'workshop', wid)
    # local mods and usermaps, in the Mod Tools folder and the game folder
    seen = set()
    for root in (gr, steamlib.find_app_dir(steamlib.BO3_DIR)):
        for sub, source in (('mods', 'local mod'), ('usermaps', 'usermap')):
            base = os.path.join(root, sub) if root else None
            if not base or not os.path.isdir(base):
                continue
            for entry in os.listdir(base):
                d = os.path.join(base, entry)
                if os.path.isdir(d) and os.path.normcase(d) not in seen:
                    seen.add(os.path.normcase(d))
                    add(d, entry, source, entry)
    out['mods'].sort(key=lambda m: (m['source'] != 'workshop', m['name'].lower()))
    out['base'] = base_ffs(gr)
    return out


def base_ffs(game_root=None, min_size=1 << 20):
    """Retail BASE-GAME fastfiles from <game_root>/zone, grouped by category for the navigator. They stream their
    high-res assets from the shared base.xpak/initial.xpak (which FF Studio now decodes), so this is browse-only —
    you view base assets to see what a mod links against; you don't rebuild retail ffs here. Localization
    string-table ffs (en_*), tiny patch stubs (< min_size) and FF Studio's own .studio.ff outputs are skipped.
    Returns navigator groups shaped like list_ffs()'s mods: [{name, source:'base game', id, ffs:[{name,path,size}]}].
    The zone is resolved via ffassets.bo3_zone_dir() — the SAME retail install whose base.xpak/initial.xpak the codec
    streams from — NOT find_game_root() (which can resolve to the Mod Tools install `…III 455130`, a different zone
    whose ffs wouldn't pair with the game's xpaks)."""
    zone = None
    try:
        import ffassets
        zone = ffassets.bo3_zone_dir()
    except Exception:
        zone = None
    if not zone:
        gr = find_game_root(game_root)
        zone = os.path.join(gr, 'zone') if gr else None
    if not zone or not os.path.isdir(zone):
        return []
    cats = [('Core', 'core_'), ('Zombies', 'zm_'), ('Multiplayer', 'mp_'), ('Campaign', 'cp_')]
    buckets = {name: [] for name, _ in cats}
    other = []
    for fp in glob.glob(os.path.join(zone, '*.ff')):
        bn = os.path.basename(fp); low = bn.lower()
        if low.endswith('.studio.ff') or low.startswith('en_'):
            continue                                   # skip our own outputs + localized string tables
        try:
            sz = os.path.getsize(fp)
        except OSError:
            continue
        if sz < min_size:
            continue                                   # drop the sub-1MB patch/stub ffs (no browsable assets)
        row = {'name': bn, 'path': os.path.abspath(fp), 'size': sz}
        for name, pfx in cats:
            if low.startswith(pfx):
                buckets[name].append(row); break
        else:
            other.append(row)
    groups = []
    for name, _ in cats:
        rows = sorted(buckets[name], key=lambda f: f['name'])
        if rows:
            groups.append({'name': 'Base · ' + name, 'source': 'base game', 'id': '__base_' + name, 'ffs': rows})
    if other:
        groups.append({'name': 'Base · Other', 'source': 'base game', 'id': '__base_other',
                       'ffs': sorted(other, key=lambda f: f['name'])})
    return groups


# ---------------- symbol aliases (friendly names for function_HEX / var_HEX / namespace_HEX) ----------------
# The user renames a `<kind>_HEX` token to a friendly name. We store {hex_token: friendly} per ff. On display we
# swap hex->friendly; at BUILD we do NOT touch the text — instead the remap gets `hasht7(friendly) -> HEX` so the
# friendly name compiles straight back to the original hash. New (never-hex) names the user invents are left
# alone (they keep hasht7(name)). This can't break links: an existing symbol always resolves to its real hash.
_TOK = re.compile(r'\b(function|var|namespace|method|hash|script)_([0-9a-fA-F]+)\b')


def _names_path(ff_path):
    os.makedirs(CACHE, exist_ok=True)
    return os.path.join(CACHE, hashlib.md5(os.path.abspath(ff_path).encode()).hexdigest()[:12] + '_names.json')


def load_names(ff_path):
    p = _names_path(ff_path)
    if os.path.isfile(p):
        import json
        try: return json.load(open(p))
        except Exception: return {}
    return {}


def save_names(ff_path, m):
    import json
    json.dump(m, open(_names_path(ff_path), 'w'), indent=0)


_AUTO = {}          # cached {hash32: name} from ACTS's hash DBs (static; built once)
_AUTO_BUILT = [False]


def _auto_dict():
    """Best-effort {hash32: name} from ACTS package_index hash DBs. Coverage is limited (custom mod names are
    unrecoverable) and always BUILD-SAFE (hasht7(name)==hash by construction). Filtered to len>=4 to avoid
    short-string hash collisions."""
    if _AUTO_BUILT[0]:
        return _AUTO
    _AUTO_BUILT[0] = True
    idx = os.path.join(os.path.dirname(DEFAULT_ACTS), 'package_index')
    if os.path.isdir(idx):
        for f in glob.glob(os.path.join(idx, 'hashes-scr-bo3.cdb')) + glob.glob(os.path.join(idx, 'hashes-xassets-*.cdb')):
            try:
                data = open(f, 'rb').read()
                for m in re.finditer(rb'[A-Za-z_][A-Za-z0-9_]{3,127}', data):
                    s = m.group(0).decode('latin1')
                    _AUTO.setdefault(hasht7(s), s)
            except Exception:
                pass
    return _AUTO


_AUTO_MAP_CACHE = {}


def safe_auto_map(ff_path):
    """{hex_token: dict_name} auto-names that are SAFE to display+build: the dict name's HashT7 equals the token
    hash (so it compiles back to the same hash) AND the name isn't a keyword and isn't already used as a plain
    identifier anywhere in the ff (which would make the name ambiguous / break a builtin). Cached per ff."""
    key = os.path.abspath(ff_path)
    if key in _AUTO_MAP_CACHE:
        return _AUTO_MAP_CACHE[key]
    ad = _auto_dict()
    m = {}
    try:
        used_plain = set(); hex_tokens = set()
        for name in open_ff(ff_path)['scripts']:
            src = _decompile_raw(ff_path, name)      # raw (no names); decompiles+caches all scripts once
            for mo in _TOK.finditer(src): hex_tokens.add(mo.group(0))
            for mo in re.finditer(r'\b[A-Za-z_]\w*\b', src):
                w = mo.group(0)
                if not _TOK.fullmatch(w): used_plain.add(w)
        for tok in hex_tokens:
            nm = ad.get(int(tok.split('_', 1)[1], 16))
            if nm and len(nm) >= 4 and nm not in _KEYWORDS and nm not in used_plain and not _TOK.fullmatch(nm):
                m[tok] = nm
    except Exception:
        pass
    _AUTO_MAP_CACHE[key] = m
    return m


def apply_names(src, name_map, auto_map=None):
    """Display form: each `<kind>_HEX` token -> user alias (wins) else a safe dictionary auto-name, else the hex."""
    def repl(mo):
        tok = mo.group(0)
        if name_map and tok in name_map: return name_map[tok]
        if auto_map and tok in auto_map: return auto_map[tok]
        return tok
    return _TOK.sub(repl, src)


# ---------------- symbols / cross-references / diagnostics (navigation like an RE tool) ----------------
_DEF = re.compile(r'^\s*function\s+((?:autoexec|private)\s+)*([A-Za-z_]\w*)\s*\(([^)]*)\)', re.M)


def decompile_all(ff_path, log=None):
    """{script_name: DISPLAY source} for every script in the ff (cached per script)."""
    return {n: decompile(ff_path, n, log=log) for n in open_ff(ff_path)['scripts']}


def prepare(ff_path, progress=None):
    """Do all the heavy first-open work UP FRONT with progress reporting, so the UI shows a real loading bar and
    no per-script call ever blocks: (1) decompile+cache every script (the slow part — ACTS), (2) build the
    auto-name map (now fast, scripts cached), (3) index symbols. progress(stage, i, n, detail)."""
    scripts = open_ff(ff_path)['scripts']; n = len(scripts)
    for i, name in enumerate(scripts):
        if progress: progress('decompile', i, n, name)
        try: _decompile_raw(ff_path, name)
        except Exception: pass
    if progress: progress('autonames', n, n, 'resolving hash names')
    safe_auto_map(ff_path)                      # fast now — reuses cached decompiles
    if progress: progress('symbols', n, n, 'indexing functions')
    nsym = len(symbols(ff_path))
    if progress: progress('done', n, n, f'{n} scripts, {nsym} functions')
    return {'scripts': n, 'symbols': nsym}


def symbols(ff_path, log=None):
    """Every function definition across the ff, for a Go-to-Symbol list."""
    out = []
    for name, src in decompile_all(ff_path, log).items():
        for m in _DEF.finditer(src):
            flags = (m.group(1) or '').strip()
            params = [p.strip() for p in m.group(3).split(',') if p.strip()]
            out.append({'name': m.group(2), 'script': name, 'line': src.count('\n', 0, m.start()) + 1,
                        'params': len(params), 'flags': flags})
    out.sort(key=lambda s: (s['script'], s['name']))
    return out


def xrefs(ff_path, symbol, log=None):
    """All references to `symbol` (display name) across the ff — definition, calls, other references."""
    out = []
    wb = re.compile(r'\b' + re.escape(symbol) + r'\b')
    defre = re.compile(r'\bfunction\s+(?:autoexec\s+|private\s+)*' + re.escape(symbol) + r'\s*\(')
    callre = re.compile(re.escape(symbol) + r'\s*\(')
    for name, src in decompile_all(ff_path, log).items():
        for i, line in enumerate(src.split('\n'), 1):
            if wb.search(line):
                kind = 'def' if defre.search(line) else ('call' if callre.search(line) else 'ref')
                out.append({'script': name, 'line': i, 'kind': kind, 'text': line.strip()[:220]})
    out.sort(key=lambda r: (r['kind'] != 'def', r['script'], r['line']))
    return out


def diagnostics(ff_path, edits, game_root=None, acts=None):
    """Pre-build problems for the edited scripts: unresolved externals + likely-uncompilable HEX-namespace
    tokens. Returns [{script, severity, message}]."""
    gr = find_game_root(game_root)
    raw_root = os.path.join(gr, 'share', 'raw') if gr else None
    probs = []
    for name, src in edits.items():
        if not raw_root:
            probs.append({'script': name, 'severity': 'error', 'message': 'Mod Tools not found — cannot resolve externals'})
            continue
        try:
            _p, st = prep(src, raw_root)
        except Exception as e:
            probs.append({'script': name, 'severity': 'error', 'message': f'prep failed: {e}'}); continue
        for u in st['unresolved']:
            probs.append({'script': name, 'severity': 'warning', 'message': f'unresolved external {u} — may fail to compile'})
    return probs


def _tok_hash(hex_token):
    return int(hex_token.split('_', 1)[1], 16)


def rename_hash_map(name_map):
    """For the remap: {hasht7(friendly): original_hash} so friendly names compile back to the original hash."""
    return {hasht7(friendly): _tok_hash(hx) for hx, friendly in (name_map or {}).items()}


def ff_symbol_hashes(ff_path):
    """Every name/namespace hash used across the ff's scripts (export+import tables) — for collision checks."""
    pay, _ = ffbo3.decompress(open(ff_path, 'rb').read())
    hashes = set()
    q = 0
    while True:
        m = pay.find(ffbo3.MAGIC, q)
        if m < 0: break
        try:
            eo = struct.unpack_from('<I', pay, m + 0x20)[0]; ec = struct.unpack_from('<H', pay, m + 0x3A)[0]
            for i in range(ec):
                hashes.add(struct.unpack_from('<I', pay, m + eo + i * 20 + 8)[0])
                hashes.add(struct.unpack_from('<I', pay, m + eo + i * 20 + 12)[0])
            io = struct.unpack_from('<I', pay, m + 0x24)[0]; ic = struct.unpack_from('<H', pay, m + 0x3C)[0]; o = m + io
            for _ in range(ic):
                nm, ns, num = struct.unpack_from('<IIH', pay, o); hashes.add(nm); hashes.add(ns); o += 12 + num * 4
        except Exception:
            pass
        q = m + 8
    return hashes


_KEYWORDS = set("function autoexec private if else for foreach while switch case default return break continue "
                "wait waittill notify endon thread self level game world undefined true false isdefined new in "
                "var const class struct do".split())


def validate_rename(ff_path, canonical_hex, new_name, name_map):
    """Return None if OK, else an error string. new_name must be a clean identifier that won't collide with
    another symbol the ff already uses (which would misdirect calls)."""
    if not re.fullmatch(r'[A-Za-z_]\w*', new_name or ''):
        return "name must be a valid identifier (letters/digits/underscore, not starting with a digit)"
    if new_name in _KEYWORDS:
        return f"'{new_name}' is a reserved keyword"
    if _TOK.fullmatch(new_name):
        return "that looks like a raw hash token; pick a readable name"
    # not already an alias for a DIFFERENT symbol
    for hx, fr in (name_map or {}).items():
        if fr == new_name and hx != canonical_hex:
            return f"'{new_name}' is already used to rename {hx}"
    # hasht7(new_name) must not collide with a DIFFERENT existing symbol hash used by the ff
    h = hasht7(new_name); canon = _tok_hash(canonical_hex)
    if h != canon and h in ff_symbol_hashes(ff_path):
        return f"'{new_name}' collides with an existing symbol in this ff (same hash) — pick another name"
    return None


# ---------------- load / decompile ----------------

def open_ff(ff_path):
    pay, h = _payload(ff_path)
    scripts = []
    for m in re.finditer(rb'scripts/[\w/]+\.gs[hc]', pay):
        name = m.group(0).decode()
        if name.endswith('.gsc') and name not in scripts:
            info = ffbo3.find_script(pay, name.encode())
            if info and info['oldlen'] >= 16:
                scripts.append(name)
    scripts = sorted(set(scripts))
    return {'ff': ff_path, 'file_size': os.path.getsize(ff_path), 'payload': len(pay),
            'bs5': h['blockSize'][5], 'bs6': h['blockSize'][6], 'scripts': scripts, 'is_base': is_base_ff(ff_path)}


def is_base_ff(ff_path):
    """True if ff_path is a RETAIL base-game fastfile (directly in the game's <install>/zone folder), as opposed to
    a workshop/local mod or usermap. Base ffs are browse-only: FF Studio doesn't auto-decompile or treat their
    zone-folder siblings as one workspace (the zone holds ~all 188 retail ffs, not a single mod's set)."""
    low = os.path.abspath(ff_path).lower().replace('/', os.sep)
    return (os.path.basename(os.path.dirname(low)) == 'zone'
            and 'workshop' not in low and (os.sep + 'mods' + os.sep) not in low
            and (os.sep + 'usermaps' + os.sep) not in low)


def _run(cmd, cwd=None, env=None, log=None):
    r = subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True, creationflags=_NO_WINDOW)
    if log:
        for ln in ((r.stdout or '') + (r.stderr or '')).splitlines():
            log(ln)
    return r


def _decompile_raw(ff_path, name, acts=None, log=None):
    """ACTS-decompiled RAW source (function_HEX names), cached. No alias/auto-name substitution."""
    acts = acts or DEFAULT_ACTS
    pay, h = _payload(ff_path)
    info = ffbo3.find_script(pay, name.encode())
    if info is None:
        raise RuntimeError(f"script not found in ff: {name}")
    obj = pay[info['bc_off']:info['bc_off'] + info['oldlen']]
    os.makedirs(CACHE, exist_ok=True)
    key = hashlib.md5((os.path.abspath(ff_path) + '|' + name + '|' + str(len(obj))).encode()).hexdigest()[:12]
    outdir = os.path.join(CACHE, key + '_dec'); src_out = os.path.join(outdir, 'out.gsc')
    if os.path.isfile(src_out):
        return open(src_out, encoding='utf-8', errors='replace').read()
    gscc = os.path.join(CACHE, key + '.gscc'); open(gscc, 'wb').write(obj)
    if os.path.isdir(outdir): shutil.rmtree(outdir, ignore_errors=True)
    r = _run([acts, 'gscd', '-g', '-o', outdir, gscc], log=log)
    found = glob.glob(os.path.join(outdir, '**', '*.gsc'), recursive=True)
    if not found:
        raise RuntimeError(f"ACTS decompile produced no source (rc={r.returncode})")
    txt = open(found[0], encoding='utf-8', errors='replace').read()
    with open(src_out, 'w', encoding='utf-8') as f:
        f.write(txt)
    return txt


def decompile(ff_path, name, acts=None, log=None):
    """DISPLAY source: raw decompile with user aliases + safe dictionary auto-names applied."""
    raw = _decompile_raw(ff_path, name, acts, log)
    return apply_names(raw, load_names(ff_path), safe_auto_map(ff_path))


# ---------------- prep (the 4 fixups, incl. auto HEX-namespace) ----------------

def _hex_namespace_map(src):
    """Map every `namespace_HEX::` token to the real namespace whose HashT7 == HEX, inferred from the #using
    list (a used file's namespace is normally its filename stem). Handles the case ACTS emits the hash form."""
    used = re.findall(r'#using\s+([^;]+);', src)
    stems = set()
    for u in used:
        stem = re.split(r'[\\/]', u.strip())[-1]
        stem = re.sub(r'\.gs[hc]$', '', stem)
        stems.add(stem)
        if stem.startswith('_'):
            stems.add(stem[1:])   # ACTS usually drops the leading '_' for the namespace (e.g. _zm_hud -> zm_hud)
    want = set(int(h, 16) for h in re.findall(r'namespace_([0-9a-fA-F]+)', src))
    m = {}
    for stem in stems:
        hv = hasht7(stem)
        if hv in want:
            m['namespace_%x' % hv] = stem
    return m


def prep(src, raw_root, log=None, self_stem=None):
    src, nfe = foreach_convert.convert(src)
    src, ntc, ntr = ternary_convert.convert(src)     # ternary ?: -> if/else (T7 compiler lacks ternary)
    bs = '\\'
    src = re.sub(r'(#using\s+)([^;]+)', lambda mm: mm.group(1) + mm.group(2).replace('/', bs), src)
    src = re.sub(r'(#insert\s+)([^;]+)', lambda mm: mm.group(1) + mm.group(2).replace('/', bs), src)
    src, unresolved = resolve_externals.resolve(src, raw_root)
    nsmap = _hex_namespace_map(src)
    for hx, real in nsmap.items():
        src = src.replace(hx + '::', real + '::')
    # a file may DECLARE its own namespace as hex (ACTS couldn't name it); if the filename stem hashes to
    # that hex, rewrite the declaration to the real name so callers (which use the resolved name) match.
    if self_stem:
        for hx in set(re.findall(r'#namespace\s+(namespace_[0-9a-fA-F]+)\s*;', src)):
            hv = int(hx.split('_')[1], 16)
            for cand in (self_stem, self_stem[1:] if self_stem.startswith('_') else self_stem):
                if hasht7(cand) == hv:
                    src = src.replace(f'#namespace {hx};', f'#namespace {cand};'); break
    if log:
        log(f"    prep: {nfe} foreach->for, {ntc} ternary->if/else ({ntr} left for manual), "
            f"{len(nsmap)} hex-namespaces resolved, {len(unresolved)} externals still unresolved")
        for u in list(unresolved)[:10]:
            log(f"      unresolved (may fail): {u}")
    return src, dict(foreach=nfe, ternary=ntc, ternary_manual=ntr, hexns=len(nsmap), unresolved=sorted(unresolved))


# ---------------- linker project scaffold + build ----------------

def _scaffold(game_root, name, log=None):
    """Persistent scratch linker project under <game_root>/usermaps/<name> with the base-subtree junctions."""
    mod = os.path.join(game_root, 'usermaps', name)
    os.makedirs(os.path.join(mod, 'scripts'), exist_ok=True)
    os.makedirs(os.path.join(mod, 'zone_source'), exist_ok=True)
    os.makedirs(os.path.join(mod, 'share'), exist_ok=True)
    os.makedirs(os.path.join(mod, 'mods', name, 'zone'), exist_ok=True)
    for rel in ('share\\raw', 'share\\zone_source', 'gamedata', 'deffiles', 'source_data'):
        link = os.path.join(mod, rel); tgt = os.path.join(game_root, rel)
        if not os.path.exists(link) and os.path.exists(tgt):
            subprocess.run(['cmd', '/c', 'mklink', '/J', link, tgt], capture_output=True, text=True,
                           creationflags=_NO_WINDOW)
    # base assetlists
    for sub in ('all', 'english'):
        srcd = os.path.join(game_root, 'zone_source', sub, 'assetlist')
        dstd = os.path.join(mod, 'zone_source', sub, 'assetlist')
        if os.path.isdir(srcd):
            os.makedirs(dstd, exist_ok=True)
            for f in glob.glob(os.path.join(srcd, '*.csv')):
                if os.path.basename(f) != f'{name}.csv':
                    try: shutil.copy2(f, os.path.join(dstd, os.path.basename(f)))
                    except Exception: pass
    return mod


def linker_build(game_root, prepped, name='ffstudio_build', log=None):
    """prepped: {script_name (scripts/zm/x.gsc): prepped_source}. Compiles them and returns the built ff path."""
    mod = _scaffold(game_root, name, log)
    # clean prior scripts, write the edited ones
    for f in glob.glob(os.path.join(mod, 'scripts', '**', '*.gsc'), recursive=True):
        try: os.remove(f)
        except Exception: pass
    zlines = ['>class,zm_mod_level', '>group,modtools', f'>title,{name}', '', '// Server Scripts']
    for sname, psrc in prepped.items():
        dst = os.path.join(mod, sname.replace('/', os.sep))
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        with open(dst, 'w', encoding='utf-8', newline='') as f:
            f.write(psrc)
        zlines.append(f'scriptparsetree,{sname}')
    with open(os.path.join(mod, 'zone_source', f'{name}.zone'), 'w', newline='') as f:
        f.write('\n'.join(zlines) + '\n')
    linker = os.path.join(game_root, 'bin', 'linker_modtools.exe')
    env = os.environ.copy()
    env['TA_GAME_PATH'] = mod + os.sep
    env['TA_TOOLS_PATH'] = game_root + os.sep
    env['TA_LOCAL_ASSET_CACHE'] = os.path.join(game_root, 'share', 'assetconvert') + os.sep
    out = os.path.join(mod, 'mods', name, 'zone', f'{name}.ff')
    if os.path.exists(out):
        try: os.remove(out)
        except Exception: pass
    if log: log(f"    linking {len(prepped)} script(s) with linker_modtools.exe ...")
    r = _run([linker, '-language', 'english', '-fs_game', name, name], cwd=game_root, env=env, log=None)
    tail = (r.stdout or '') + (r.stderr or '')
    for ln in tail.splitlines():
        if any(k in ln for k in ('ERROR', 'Could not', 'done:', 'Linking', 'terminate', 'WARNING')):
            if log: log('      ' + ln.strip())
    if not os.path.exists(out):
        raise RuntimeError("linker did not produce an ff — see log (a script error usually)")
    return out


# ---------------- remap ----------------

def _exports(bc):
    eo = struct.unpack_from('<I', bc, 0x20)[0]; ec = struct.unpack_from('<H', bc, 0x3A)[0]
    return set(struct.unpack_from('<I', bc, eo + i * 20 + 8)[0] for i in range(ec))


def remap(orig_obj, linker_obj, prepped_source, extra_map=None):
    m = build_map_from_source(prepped_source) if os.path.isfile(prepped_source) else _map_from_text(prepped_source)
    if extra_map:
        m = dict(m); m.update(extra_map)   # friendly-alias mappings: hasht7(friendly) -> original hash
    out, ie, cseg = remap_gsc(bytearray(linker_obj), m)
    wrong = set(m.keys())
    imp_names = set()
    io = struct.unpack_from('<I', out, 0x24)[0]; ic = struct.unpack_from('<H', out, 0x3C)[0]; o = io
    for _ in range(ic):
        nm, ns, num = struct.unpack_from('<IIH', out, o); imp_names |= {nm, ns}; o += 12 + num * 4
    surv = len(( _exports(out) | imp_names) & wrong)
    missing = _exports(orig_obj) - _exports(out)
    return bytes(out), dict(ie=ie, cseg=cseg, survivors=surv, missing=len(missing),
                            new_funcs=len(_exports(out) - _exports(orig_obj)))


def _map_from_text(src):
    import gsc_remap
    tmp = os.path.join(CACHE, 'tmp_src.gsc'); os.makedirs(CACHE, exist_ok=True)
    open(tmp, 'w', encoding='utf-8').write(src)
    return gsc_remap.build_map_from_source(tmp)


# ---------------- the one-call BUILD ----------------

def build(ff_path, edits, out_path, game_root=None, acts=None, log=None, names=None):
    """edits: {script_name: EDITED source (with friendly aliases as displayed)}. `names` = {hex_token: friendly}
    alias map (defaults to the saved one). Friendly aliases resolve back to their original hash via the remap, so
    renaming never changes what a symbol links to. Returns {out_path, per_script:[...]}; raises on any failure."""
    log = log or (lambda *_: None)
    names = names if names is not None else load_names(ff_path)
    alias_hashes = rename_hash_map(names)
    if names: log(f"  {len(names)} friendly alias(es) active")
    deps = check_deps(game_root, acts)
    if not deps['_all_ok']:
        missing = [k for k in ('acts', 'modtools', 'share_raw') if not deps[k]['ok']]
        raise RuntimeError("missing dependencies: " + ", ".join(missing) + " — see the dependency panel")
    gr = deps['_game_root']; acts = deps['_acts']; raw_root = os.path.join(gr, 'share', 'raw')
    # 1. prep every edited script
    prepped = {}
    for name, src in edits.items():
        log(f"  prep {name}")
        stem = re.sub(r'\.(gsc|csc|gsh)$', '', name.replace('\\', '/').split('/')[-1])
        psrc, st = prep(src, raw_root, log=log, self_stem=stem)
        prepped[name] = psrc
    # 2. one linker build for all of them
    built_ff = linker_build(gr, prepped, log=log)
    lpay, _ = ffbo3.decompress(open(built_ff, 'rb').read()) if _is_ff(built_ff) else (open(built_ff, 'rb').read(), None)
    # 3. per-script: remap + splice (chained on the growing ff)
    cur = open(ff_path, 'rb').read()
    per = []
    for name in edits:
        pay, _h = ffbo3.decompress(cur)
        oinfo = ffbo3.find_script(pay, name.encode())
        orig_obj = pay[oinfo['bc_off']:oinfo['bc_off'] + oinfo['oldlen']]
        linfo = ffbo3.find_script(lpay, name.encode())
        if linfo is None:
            raise RuntimeError(f"'{name}' missing from linker output (did it compile?)")
        linker_obj = lpay[linfo['bc_off']:linfo['bc_off'] + linfo['oldlen']]
        new_obj, rst = remap(orig_obj, linker_obj, prepped[name], extra_map=alias_hashes)
        log(f"  remap {name}: survivors={rst['survivors']} missing={rst['missing']} new_funcs={rst['new_funcs']}")
        if rst['survivors']:
            raise RuntimeError(f"{name}: {rst['survivors']} wrong hashes survived remap — aborting")
        if rst['missing']:
            raise RuntimeError(f"{name}: remap dropped {rst['missing']} original exports — aborting")
        comp, gst = grow_engine.grow_patch(cur, name, new_obj, verbose=False)
        cur = comp
        log(f"  splice {name}: len {gst['oldlen']}->{gst['newlen']} (+{gst['delta']}), {gst['patched']} ptrs")
        per.append({'script': name, **{k: gst[k] for k in ('oldlen', 'newlen', 'delta', 'patched')},
                    'remap': rst})
    open(out_path, 'wb').write(cur)
    log(f"DONE -> {out_path} ({len(cur):,} bytes)")
    return {'out_path': out_path, 'size': len(cur), 'per_script': per}


def _is_ff(p):
    with open(p, 'rb') as f:
        return f.read(8) == b'TAff0000'


# ---------------- multi-ff mod workspace + one-click ff swap ----------------
_LANGS = {'en', 'fr', 'ge', 'it', 'ja', 'po', 'ru', 'sc', 'tc', 'bp', 'ea', 'es'}
def mod_ffs(ff_path):
    """The fastfiles that belong to the SAME mod as ff_path (same folder), so the editor can open a mod like
    core_mod + zm_mod as one workspace. Excludes localization stubs (<lang>_*.ff), tagged copies
    (<stem>.<TAG>.ff), backups, and FF Studio's own .studio.ff outputs. Returns [{name,path,size}], ff_path first."""
    if is_base_ff(ff_path):                                               # retail zone ff: browse it alone, NOT the
        return [{'name': os.path.basename(ff_path), 'path': os.path.abspath(ff_path),  # ~188 sibling zone ffs
                 'size': os.path.getsize(ff_path)}]
    d = os.path.dirname(os.path.abspath(ff_path))
    out = []
    for f in sorted(glob.glob(os.path.join(d, '*.ff'))):
        b = os.path.basename(f)
        if b.endswith('.studio.ff'):
            continue
        if len(b) > 3 and b[2] == '_' and b[:2] in _LANGS:                 # localization stub
            continue
        if '.' in b[:-3]:                                                  # <stem>.<TAG>.ff tagged copy
            continue
        try: sz = os.path.getsize(f)
        except OSError: continue
        if sz < 50000:                                                     # skip stubs/placeholders
            continue
        out.append({'name': b, 'path': os.path.abspath(f), 'size': sz})
    out.sort(key=lambda x: (os.path.abspath(x['path']) != os.path.abspath(ff_path), -x['size']))
    return out

def toggle_studio_ff(ff_path, built_path=None):
    """One-click swap: install a built .studio.ff in place of the pristine ff (backing the pristine up first), or
    restore the pristine. Idempotent — call again to toggle back. Returns {state, active, backup, msg}."""
    ff_path = os.path.abspath(ff_path)
    pristine = ff_path + '.pristine_backup'
    if built_path is None:
        built_path = os.path.splitext(ff_path)[0] + '.studio.ff'
    if os.path.exists(pristine):                                          # currently running the studio ff -> restore
        shutil.copy2(pristine, ff_path); os.remove(pristine)
        return {'state': 'pristine', 'active': ff_path, 'backup': None,
                'msg': 'Restored the original fastfile.'}
    if not os.path.exists(built_path):
        raise RuntimeError('No built .studio.ff to install — build a patched version first.')
    shutil.move(ff_path, pristine)                                        # back up pristine, install studio
    shutil.copy2(built_path, ff_path)
    return {'state': 'studio', 'active': ff_path, 'backup': pristine,
            'msg': 'Installed the Studio fastfile. Original backed up — toggle again to restore.'}

def studio_ff_state(ff_path):
    """Which ff is currently active + whether a built .studio.ff exists to install."""
    ff_path = os.path.abspath(ff_path)
    built = os.path.splitext(ff_path)[0] + '.studio.ff'
    return {'state': 'studio' if os.path.exists(ff_path + '.pristine_backup') else 'pristine',
            'hasBuild': os.path.exists(built), 'built': built if os.path.exists(built) else None}
