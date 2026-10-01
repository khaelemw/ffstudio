"""Base-game asset classifier: tells whether an asset in a mod's ff is stock BO3 (the ff just links to a base
asset) or mod-added (a custom asset, or a base one the mod replaced).

The reference is the Mod Tools' stock asset lists, <mod tools>/zone_source/all/assetlist/{core,cp,mp,zm}_*.csv.
Names are compared after stripping the ff's packaging quirks: a leading category dir (mc/ ei/ ...), a trailing
content hash or _lodN / _col / _hitbox suffix on meshes, and a techset '#hash' suffix.

Without the Mod Tools there is no reference list, so classify() returns 'unknown'. Assets from DLC that isn't in
the stock lists can read as 'custom'.

Public:
  classify(type, name) -> 'custom' | 'base' | 'unknown'
  is_base(name, type=None) -> bool
  split(items) -> {'custom': [(type,name)...], 'base': [(type,name)...], 'base_db': int}
"""
import os, glob, csv, re
import steamlib

_STOCK_PREFIX = ('core_', 'cp_', 'mp_', 'zm_')
_CATEGORY_DIR = re.compile(r'^[a-z]{1,3}/')                 # leading  mc/ ei/ ec/ el/ vd/ ...
_HASH_SUF = re.compile(r'(_lod\d+|_col|_hitbox\d*|_fxanim_lod\d+)?[0-9a-f]{6,}$')
_TS_SUF = re.compile(r'#[0-9a-f]+$')                        # techset  ...#e6142445
_CACHE = {}

def _game_roots(game_root):
    roots = [game_root] if game_root else []
    mt = steamlib.find_app_dir(steamlib.MODTOOLS_DIR)
    if mt:
        roots.append(mt)
    return roots

def load(game_root=None):
    """The stock asset names and (type, name) pairs from the Mod Tools asset lists."""
    key = game_root or '_default'
    if key in _CACHE:
        return _CACHE[key]
    names = set(); pairs = set(); files = []
    for gr in _game_roots(game_root):
        ald = os.path.join(gr, 'zone_source', 'all', 'assetlist')
        if not os.path.isdir(ald):
            continue
        for fp in glob.glob(os.path.join(ald, '*.csv')):
            base = os.path.basename(fp).lower()
            if not base.startswith(_STOCK_PREFIX):
                continue
            files.append(base)
            try:
                for row in csv.reader(open(fp, encoding='latin1', errors='replace')):
                    if len(row) >= 2 and row[1].strip() and ',' not in row[1]:
                        names.add(row[1].strip()); pairs.add((row[0].strip(), row[1].strip()))
            except Exception:
                pass
        break
    res = {'names': names, 'pairs': pairs, 'csv_files': sorted(files)}
    _CACHE[key] = res
    return res

def _variants(name):
    """Name forms to test against the stock set, tolerant of ff packaging quirks."""
    if not name:
        return
    seen = set(); forms = [name]
    m = _CATEGORY_DIR.match(name)
    if m:
        forms.append(name[m.end():])
    ts = _TS_SUF.sub('', name)
    if ts != name:
        forms.append(ts)
    for f in list(forms):
        s = _HASH_SUF.sub('', f)
        if s and s != f:
            forms.append(s)
    for f in forms:
        if f and f not in seen:
            seen.add(f); yield f

def is_base(name, type=None, game_root=None):
    b = load(game_root)
    for v in _variants(name):
        if v in b['names'] or (type is not None and (type, v) in b['pairs']):
            return True
    return False

def classify(type, name, game_root=None):
    if not load(game_root)['names']:
        return 'unknown'
    return 'base' if is_base(name, type, game_root) else 'custom'

def split(items, game_root=None):
    b = load(game_root); custom = []; base = []
    for t, nm in items:
        (base if is_base(nm, t, game_root) else custom).append((t, nm))
    return {'custom': custom, 'base': base, 'base_db': len(b['names'])}
