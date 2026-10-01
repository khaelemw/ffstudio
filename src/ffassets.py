"""FF Studio asset backend: the asset inventory of a fastfile and the per-type viewers and editors.

Main entry points:
  inventory(ff)      -> {'assets': [{type,name,offset,size}], 'containers': [...]}
  image_png(ff,off)  -> PNG bytes for the GfxImage at `off`
  fx_view(ff,off)    -> decoded effect element tree + .efx source
  lua_view(ff,off)   -> disassembly and pseudo-Lua for an HKS rawfile at `off`
Assets are located by structural signatures, so any fastfile can be scanned.
"""
import os, sys, io, struct
import numpy as np
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import ffbo3
import steamlib
try:
    import ff_deserialize as _fd      # XAssetList -> per-type asset counts
except Exception:
    _fd = None
import fx_decode, fx_to_efx, hks_disasm, xpak, fx_curves
import xanim_decode   # T7 XAnimParts keyframe decoder (half-float quats + Min/Size translations)
import hks_decompile   # HKS -> readable pseudo-Lua source (layer above hks_disasm)
import hks_reserialize  # HKS byte-level re-serializer / assembler (round-trip + bytecode edits)
import hks_compile      # HKS source -> bytecode (external hksc compiler)
try:
    import base_assets                                     # base-vs-custom classifier
except Exception:
    base_assets = None

F = 0xFFFFFFFFFFFFFFFF
_cache = {}
def _pay(ff):
    st = os.path.getmtime(ff)
    if _cache.get('_k') != (ff, st):
        pay, h = ffbo3.decompress(open(ff, 'rb').read()); _cache.clear(); _cache.update(_k=(ff, st), pay=pay)
    return _cache['pay']

def _vn(d, q, mx=128):
    e = q
    while e < len(d) and 32 <= d[e] < 127 and e-q < mx: e += 1
    return d[q:e].decode('latin1') if (e < len(d) and d[e] == 0 and e > q) else None
_NAMECHARS = frozenset(b'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_/.-')
def _vn_back(d, q, mx=160, maxback=96):
    """Read an inline asset name whose FIXED read offset `q` can land MID-string. The XModel name is inline after a
    variable-size preamble, so a constant offset (0x188) sometimes points into the middle of the name and truncates
    the front (e.g. 'wpn_t7_zmb_lil_arnie_projectile…' read as 'rnie_projectile…'). Back up through name-chars to the
    preceding null (the true string start), then read the whole null-terminated name. When q is already the start
    (the common case), d[q-1] is the previous field's null, so no back-up happens and this equals _vn."""
    if q <= 0 or q >= len(d): return None
    b = q
    while b > 0 and b > q - maxback and d[b-1] in _NAMECHARS: b -= 1
    e = b
    while e < len(d) and d[e] in _NAMECHARS and e - b < mx: e += 1
    return d[b:e].decode('latin1') if (e < len(d) and d[e] == 0 and e > b) else None
def _u(d, o, n): return int.from_bytes(d[o:o+n], 'little')
def _f(d, o):
    try: return struct.unpack('<f', d[o:o+4])[0]
    except Exception: return 0.0

def _is_img(d, P):
    return P+0x110 < len(d) and _u(d, P+0xF8, 8) == F and _u(d, P+0xCC, 4) == 16 and d[P+0xA0] <= 8 and _vn(d, P+0x108)
def _is_raw(d, P):
    if _u(d, P, 8) != F or _u(d, P+0x10, 8) != F or _u(d, P+0xC, 4) != 0: return False
    ln = _u(d, P+8, 4); nm = _vn(d, P+0x18)
    return bool(0 <= ln < 0x4000000 and nm and '/' in nm and '.' in nm)
def _is_kvp(d, P):
    return _u(d, P, 8) == F and 0 < _u(d, P+8, 4) < 100000 and _u(d, P+0x10, 8) == F and _vn(d, P+0x18)
def _is_stringtable(d, P):
    """StringTable {name*(-1)@0, i32 columnCount@8, i32 rowCount@0xC, StringTableCell* values(-1)@0x10,
    cellIndices*@0x18}; name inline @0x20. Distinguished from kvp (which also has -1 name@0 + -1 ptr@0x10) by TWO
    nonzero count fields (cols@8 small, rows@0xC) and a gamedata/.csv name."""
    if _u(d, P, 8) != F or _u(d, P+0x10, 8) != F: return None
    cols = _u(d, P+8, 4); rows = _u(d, P+0xC, 4)
    if not (0 < cols < 128 and 0 < rows < 1000000 and 0 < cols*rows < 5000000): return None
    nm = _vn(d, P+0x20)
    return nm if (nm and ('/' in nm or nm.lower().endswith('.csv'))) else None

def _good_name(nm):
    """A plausible asset name: >=4 chars, contains a letter, only name-ish characters. Filters the junk
    ('/', '$', '1J', …) that internal -1 pointers produce when a detector matches by coincidence."""
    import re
    return bool(nm and len(nm) >= 4 and re.search(r'[A-Za-z]', nm) and re.fullmatch(r'[A-Za-z0-9_./#:$~\-]+', nm))

# --- structural asset detectors -----------------------------------------------------------------------
# All of these begin with a -1 name pointer @0, so the \xff*8 scan lands on the struct start. Each reads its
# name at a type-specific offset and checks a couple of distinguishing fields (keeps false positives low).
_MTOK = ('mtl', 'wpn', 'veh', 'gfx', 'decal', 'skin', 'cush', '_zmb', 'ai_', 'fx', 'ei/', 'mc/', 'lit')
def _mat_name(d, P):
    """The material's inline name sits ~P+0x2A0, but a preceding variable field shifts it by a byte or two
    (so a fixed read drops the first char: 'player/...' -> 'ayer/...'). Walk back to the field boundary
    (first non-printable byte) to find the true start."""
    o = P + 0x2A0
    if o >= len(d): return None
    s = o
    while s > P + 0x290 and 32 <= d[s-1] < 127:          # back up over the name to its first char
        s -= 1
    return _vn(d, s)
def _is_mat(d, P):
    if _u(d, P, 8) != F: return None
    nm = _mat_name(d, P)
    if not nm or '.hlsl' in nm: return None
    if '/' not in nm and not any(t in nm for t in _MTOK): return None
    if not all(d[P+0x270+k] < 64 for k in range(3)): return None
    ts = _u(d, P+0x278, 8)
    return nm if (ts == 0 or (ts >> 60) == 5) else None
def _is_ts(d, P):
    if _u(d, P, 8) != F: return None
    nm = _vn(d, P+0x70)
    return nm if (nm and ('#' in nm or '.hlsl' in nm)) else None   # real techset names carry a '#<hash>' or shader path
def _is_mesh(d, P):
    if _u(d, P, 8) != F: return None
    nm = _vn(d, P+0x78)
    if not nm or not (1 <= d[P+0x3C] <= 64): return None
    sp = _u(d, P+0x68, 8); sh = _u(d, P+0x70, 8)
    return nm if ((sp == F or sp == 0 or (sp >> 60) == 5) and (sh == F or sh == 0 or (sh >> 60) == 5)) else None
def _is_xmodel(d, P):
    if _u(d, P, 8) != F: return None
    nm = _vn_back(d, P+0x188); nb = d[P+8]; nc = _u(d, P+0xA, 2); nr = d[P+9]; nl = d[P+0x40]
    # reject junk names (sound/file-path fragments like '.LN100.pc.snd' — model names have no basename dot)
    if not (nm and _good_name(nm) and nm[0] != '.' and '.' not in nm.rsplit('/', 1)[-1] and 'scripts/' not in nm):
        return None
    # bone counts must be sane: nb (root) + nc (children) is the skeleton size; the view uses nb+nc, so bound it
    if not (0 < nb <= 200 and nr <= nb and nc <= 800 and 0 < nb+nc <= 900 and 1 <= nl <= 8):
        return None
    return nm
def _is_xanim(d, P):
    if P < 0 or P+0xF8 >= len(d) or _u(d, P, 8) != F: return None
    fc = _u(d, P+0x20, 2); bc = _u(d, P+0x22, 2)
    if not (1 <= fc <= 60000 and 1 <= bc <= 800): return None
    if not (1.0 <= _f(d, P+0x50) <= 2000.0): return None
    for off in (0x70, 0xF0):
        v = _u(d, P+off, 8)
        if not (v == F or v == 0 or (v >> 60) == 5): return None
    return _vn(d, P+0xF8)

# --- fonts: T7 TTFDef {name*, fileLen i32, file*} embeds a raw TrueType file inline (name string precedes it) ---
def _be(d, o, n): return int.from_bytes(d[o:o+n], 'big')      # sfnt/TrueType is big-endian
_TTF_TAGS = {b'cmap', b'glyf', b'head', b'hhea', b'hmtx', b'loca', b'maxp', b'name', b'post', b'OS/2', b'GDEF',
             b'GPOS', b'GSUB', b'cvt ', b'fpgm', b'gasp', b'prep', b'kern', b'DSIG', b'CFF ', b'FFTM', b'hdmx',
             b'VDMX', b'LTSH', b'PCLT', b'meta'}
def _ttf_at(d, off):
    """If a valid sfnt TrueType starts at off, return {len, glyphs, family, tables}; else None. Length and glyph
    count come from the font's OWN table directory + maxp (authoritative), so no external struct field is needed."""
    if d[off:off+4] != b'\x00\x01\x00\x00': return None
    nt = _be(d, off+4, 2)
    if not (3 <= nt <= 40) or off+12+nt*16 > len(d): return None
    import math
    if _be(d, off+6, 2) != (1 << int(math.log2(nt))) * 16: return None   # searchRange must match numTables
    tbl = {}; end = 0; known = 0
    for i in range(nt):
        e = off+12+i*16
        tag = d[e:e+4]; toff = _be(d, e+8, 4); tlen = _be(d, e+12, 4)
        tbl[tag] = (toff, tlen); end = max(end, toff+tlen)
        if tag in _TTF_TAGS: known += 1
    if known < nt*0.6 or off+end > len(d): return None                   # most tags must be real sfnt tags
    ng = _be(d, off+tbl[b'maxp'][0]+4, 2) if b'maxp' in tbl else None
    return {'len': (end+3) & ~3, 'glyphs': ng, 'family': _ttf_family(d, off, tbl.get(b'name')),
            'tables': sorted(t.decode('latin1') for t in tbl)}
def _ttf_family(d, off, nametbl):
    """family name (nameID 1, fallback full-name 4) from the sfnt 'name' table (Windows UTF-16BE or Mac ascii)."""
    if not nametbl: return None
    no = off+nametbl[0]; count = _be(d, no+2, 2); soff = no+_be(d, no+4, 2); full = None
    for i in range(count):
        r = no+6+i*12; pid = _be(d, r, 2); nid = _be(d, r+6, 2); ln = _be(d, r+8, 2); o2 = _be(d, r+10, 2)
        if nid not in (1, 4): continue
        raw = d[soff+o2:soff+o2+ln]
        try: s = raw.decode('utf-16-be') if pid == 3 else raw.decode('latin1')
        except Exception: continue
        s = ''.join(c for c in s if 32 <= ord(c) < 127).strip()
        if nid == 1 and s: return s
        if nid == 4 and s and not full: full = s
    return full
def _name_before(d, i):
    """the inline asset name (e.g. 'fonts/xxx.ttf') the linker writes just before the TTF blob."""
    e = i
    while e > 0 and d[e-1] == 0: e -= 1               # skip the name string's null terminator / pad
    s = e
    while s > 0 and 32 <= d[s-1] < 127 and e-s < 200: s -= 1
    txt = d[s:e].decode('latin1', 'replace')
    m = _re.search(r'fonts/[A-Za-z0-9_./#:\-]+\.ttf', txt) or _re.search(r'[A-Za-z0-9_./#:\-]{4,}$', txt)
    return m.group(0) if m else None
def _find_ttfs(d):
    """Locate every embedded TrueType font in the payload (by its sfnt header)."""
    out = []; off = 0
    while True:
        i = d.find(b'\x00\x01\x00\x00', off)
        if i < 0: break
        r = _ttf_at(d, i)
        if r:
            out.append({'type': 'ttf', 'name': _name_before(d, i) or r['family'] or 'font', 'offset': i,
                        'ttf_len': r['len'], 'glyphs': r['glyphs'], 'family': r['family'], 'tables': r['tables']})
            off = i + r['len']
        else:
            off = i + 4
    return out

_INV_CACHE = {}
def inventory(ff):
    """Cached wrapper — the full scan is ~4s, and the per-asset viewers (materials) also need the asset list."""
    try: st = os.path.getmtime(ff)
    except OSError: st = 0
    c = _INV_CACHE.get(ff)
    if c and c[0] == st: return c[1]
    r = _inventory_impl(ff)
    while len(_INV_CACHE) >= 4:                        # keep a few (mod + base ffs) so base-model views don't re-scan
        _INV_CACHE.pop(next(iter(_INV_CACHE)))
    _INV_CACHE[ff] = (st, r)
    return r
def _inventory_impl(ff):
    d = _pay(ff); N = len(d); assets = []; scan = 0x40
    while True:
        x = d.find(b'\xff'*8, scan, N)
        if x < 0: break
        t = nm = None
        # A long \xff run (padding / adjacent -1 fields) yields an \xff*8 match at EVERY byte of the run; each
        # non-start match reads a byte-shifted substring of the next inline name (e.g. scroll/croll/roll…) and
        # slips past _good_name. Real struct headers begin with a -1 name ptr whose preceding byte is NOT 0xFF,
        # so gate the struct-start detectors on run-start. (Images land 0xF8 INTO the struct, not at its start —
        # their own field checks are already exact at 1044 — so they are exempt.)
        rs = (x == 0) or d[x-1] != 0xFF
        # images have a POOLED name (name ptr @0 != -1) but an inline pixel ptr @0xF8 == -1, so the scan lands
        # 0xF8 into the struct; other types begin with a -1 name ptr @0 (scan lands on the struct start).
        if _is_img(d, x-0xF8): t, nm, base = 'image', _vn(d, x-0xF8+0x108), x-0xF8
        elif fx_decode.is_fx(d, x): t, nm, base = 'fx', fx_decode.is_fx(d, x), x
        elif _is_xmodel(d, x): t, nm, base = 'xmodel', _is_xmodel(d, x), x
        elif _is_xanim(d, x): t, nm, base = 'xanim', _is_xanim(d, x), x
        elif _is_mesh(d, x): t, nm, base = 'xmodelmesh', _is_mesh(d, x), x
        elif _is_mat(d, x): t, nm, base = 'material', _is_mat(d, x), x
        elif _is_ts(d, x): t, nm, base = 'techset', _is_ts(d, x), x
        elif _is_raw(d, x): t, nm, base = ('script' if (_vn(d, x+0x18) or '').startswith('scripts/') else 'rawfile'), _vn(d, x+0x18), x
        elif _is_stringtable(d, x): t, nm, base = 'stringtable', _is_stringtable(d, x), x
        elif _is_kvp(d, x): t, nm, base = 'kvp', _vn(d, x+0x18), x
        if t and t != 'image' and not rs: t = None   # struct-start detectors: reject mid-run substring hits
        if t and _good_name(nm):                # drop junk-named false hits (internal -1 pointers)
            assets.append({'type': t, 'name': nm, 'offset': base})
        scan = x+1
    # dedup by (type, name) — internal -1 pointers can re-hit the same asset; keep the first (lowest offset)
    seen = set(); uniq = []
    for a in sorted(assets, key=lambda a: a['offset']):
        k = (a['type'], a['name'])
        if k in seen: continue
        seen.add(k); uniq.append(a)
    assets = uniq
    # sizes = gap to next asset of interest (approx, for display)
    offs = sorted(set(a['offset'] for a in assets))
    for a in assets:
        nxt = next((o for o in offs if o > a['offset']), N)
        a['size'] = nxt - a['offset']
    # fonts: embedded TrueType (own their exact size); appended after the gap-size pass so it keeps ttf_len
    for a in _find_ttfs(d):
        a['size'] = a['ttf_len']; assets.append(a)
    # classify each: mod-added (custom) vs base-game linked (skip junk/short names some detectors emit).
    # Everything in a retail base-game fastfile is base game.
    zone = bo3_zone_dir()
    retail = bool(zone) and os.path.normcase(os.path.dirname(os.path.abspath(ff))) == os.path.normcase(zone)
    ncustom = nbase = 0
    for a in assets:
        nm = a['name'] or ''
        real = len(nm) >= 3 and _re.search(r'[A-Za-z]', nm) and _re.fullmatch(r'[A-Za-z0-9_./#:\-]+', nm)
        if not real:
            a['origin'] = 'unknown'
        elif retail:
            a['origin'] = 'base'
        else:
            a['origin'] = base_assets.classify(a['type'], nm) if base_assets else 'unknown'
        if a['origin'] == 'custom': ncustom += 1
        elif a['origin'] == 'base': nbase += 1
    assets.sort(key=lambda a: (a['type'], a['name'] or ''))
    # sibling containers on disk, categorized: streamed data (.xpak), localization (<lang>_<base>.ff),
    # and tagged copies (base.<TAG>.ff) that aren't part of the mod.
    _LANG = {'en': 'English', 'fr': 'French', 'ge': 'German', 'it': 'Italian', 'ja': 'Japanese',
             'po': 'Polish', 'ru': 'Russian', 'sc': 'Chinese (Simpl.)', 'tc': 'Chinese (Trad.)',
             'bp': 'Portuguese (BR)', 'ea': 'Spanish (LatAm)', 'es': 'Spanish'}
    dd = os.path.dirname(ff); mybase = os.path.basename(ff)
    stem = mybase[:-3] if mybase.endswith('.ff') else mybase          # e.g. 'zm_mod'
    stem = stem.split('.')[0]
    xpaks = []; langs = []; variants = []; other = []
    for fn in sorted(os.listdir(dd)) if os.path.isdir(dd) else []:
        if fn == mybase: continue
        if fn.endswith('.xpak') and fn.startswith(stem):
            xpaks.append(fn)
        elif fn.endswith('.ff') and len(fn) > 3 and fn[2] == '_' and fn[:2] in _LANG and fn[3:] == mybase:
            langs.append({'lang': _LANG[fn[:2]], 'code': fn[:2], 'file': fn})
        elif fn.endswith('.ff') and fn.startswith(stem + '.'):
            variants.append(fn)                                       # base.<TAG>.ff = tagged copy
        elif fn.endswith(('.ff', '.xpak')):
            other.append(fn)
    related = {'xpaks': xpaks, 'localizations': langs, 'variants': variants, 'other': other}
    sib = xpaks + [l['file'] for l in langs] + other                 # flat list of all sibling files
    # per-type counts from the XAssetList (every type, including ones with no viewer)
    from collections import Counter
    census = {}; census_source = 'none'
    if _fd is not None:
        try:
            _, _al, _ = _fd.parse_xassetlist(d)
            census = dict(Counter(a['name'] for a in _al))   # a['name'] is the type name
            census_source = 'xassetlist'                     # read from the contiguous directory
        except Exception:
            census = {}
    if not census:
        # Streamed ffs interleave the directory with inline headers, so there's no contiguous array to read.
        # Fall back to a tally of what the scanner found (approximate; only covers the detected types).
        _MAP = {'xanim': 'xanimparts', 'script': 'scriptparsetree', 'kvp': 'keyvaluepairs'}
        census = dict(Counter(_MAP.get(a['type'], a['type']) for a in assets))
        census_source = 'scan' if census else 'none'
    return {'assets': assets, 'count': len(assets), 'containers': sib[:40], 'related': related,
            'custom': ncustom, 'base': nbase, 'additions': {} if retail else mod_additions(ff, d),
            'type_census': census, 'census_source': census_source,
            'total_assets': sum(census.values()) or len(assets)}

# asset-name-token scan for the FULL mod-additions picture (models/materials/anims the mod adds, by name —
# these have no inline viewer yet, but classification tells you WHAT the mod contributes vs links to base).
import re as _re
_TOK = _re.compile(rb'[a-z_][a-z0-9_]{2,}(?:[/.#][a-z0-9_]+)*')
_CAT = _re.compile(r'^(mc|ei|ec|el|vd|i|ai|mi)/')
_HASHSUF = _re.compile(r'(_lod\d+|_col|_hitbox\d*)?[0-9a-f]{6,}$')
_APFX = ('mtl_', 'wpn_', 'c_', 'p6_', 'p7_', 'p8_', 't10_', 't7_', 't6_', 'veh_', 'hl_', 'vm_',
         'zombie_', 'gfx_', 'i_', 'a_', 'rr_', 'xmaterial_')
_APATH = ('scripts/', 'ui/', 'animtrees/', '_t10/', '_wetegg/', 'custom/', 'zombie/', 'weapon/', 'vehicle/')
def _asset_shaped(s):
    return bool(_CAT.match(s)) or s.startswith(_APFX) or any(p in s for p in _APATH) or ('/' in s and s.count('/') <= 6)
def _dedup(s):
    m = _CAT.match(s); core = s[m.end():] if m else s      # drop category dir for dedup
    return _HASHSUF.sub('', core)                           # collapse lod/hash variants
def _atype(s):
    if s.startswith('scripts/'): return 'script'
    if s.startswith('ui/') or s.endswith('.lua'): return 'lua'
    if s.startswith('animtrees/') or s.endswith('.atr'): return 'rawfile'
    if ('/fx_' in s) or s.startswith(('_t10/', '_wetegg/', 'custom/')) or s.split('/')[0] in ('zombie', 'weapon', 'vehicle', 'dlc1', 'dlc2', 'dlc3', 'dlc4', 'dlc5'): return 'fx'
    if s.startswith('mtl_') or _CAT.match(s): return 'material/image'
    if s.startswith(('c_', 'p6_', 'p7_', 'p8_', 'wpn_', 'veh_', 'hl_', 'zombie_')) or s.startswith('t10_zm'): return 'model'
    if s.startswith(('ai_', 'a_', 'vm_', 'o_')): return 'xanim'
    return 'other'
_ADD_CACHE = {}
def mod_additions(ff, payload=None):
    """The mod's own asset names (not found in base game), grouped by inferred type — the 'this mod adds'
    list, covering models/materials/anims that have no binary viewer yet. Deduped across lod/hash variants."""
    if not base_assets: return {}
    try: st = os.path.getmtime(ff)
    except OSError: st = 0
    if _ADD_CACHE.get('_k') == (ff, st):
        return _ADD_CACHE['v']
    d = payload if payload is not None else _pay(ff)
    toks = set()
    for m in _TOK.finditer(d):
        s = m.group(0)
        if 5 <= len(s) <= 120: toks.add(s.decode('latin1'))
    groups = {}
    seen = set()
    for s in toks:
        if not _asset_shaped(s) or base_assets.is_base(s): continue
        key = _dedup(s)
        t = _atype(key)
        if t == 'other': continue                          # drop unclassifiable noise
        if (t, key) in seen: continue
        seen.add((t, key))
        groups.setdefault(t, []).append(key)
    out = {t: sorted(v) for t, v in sorted(groups.items())}
    _ADD_CACHE.clear(); _ADD_CACHE.update(_k=(ff, st), v=out)
    return out

def _sibling_xpak(ff):
    dd = os.path.dirname(ff); base = os.path.basename(ff)
    for cand in (base.replace('.ff', '.xpak').split('.SEP7')[0], 'zm_mod.xpak', 'core_mod.xpak'):
        pth = os.path.join(dd, cand)
        if os.path.isfile(pth): return pth
    for fn in (os.listdir(dd) if os.path.isdir(dd) else []):
        if fn.endswith('.xpak'): return os.path.join(dd, fn)
    return None
def _img_xpaks(ff):
    """Candidate xpaks holding this image's streamed mips: the sibling (mods) plus the two big shared retail xpaks
    base.xpak + initial.xpak, where base-game mips live. Deliberately excludes the 3 DLC xpaks the mesh path scans
    (~15GB) — image lookups run per-thumbnail, and loading a DLC xpak's hash table just to answer "is this inline?"
    for a base-game UI image isn't worth it; the mesh path keeps the DLCs since a DLC model needs them."""
    out = []
    sib = _sibling_xpak(ff)
    if sib and os.path.exists(sib) and os.path.getsize(sib) > 2000: out.append(sib)
    zone = bo3_zone_dir()
    if zone and os.path.normpath(os.path.dirname(ff)) == os.path.normpath(zone):
        for b in ('base.xpak', 'initial.xpak'):
            p = os.path.join(zone, b)
            if os.path.exists(p): out.append(p)
    return out
_XPAK_BYHASH = {}
def _xpak_byhash(xp):
    """(mm, header, {hash: entry}) for an xpak, cached. Built from the mmap'd/cached _load_xpak so the big shared
    base.xpak/initial.xpak are read once and reused across every streamed image and mesh."""
    mm, h, ents, _sizes = _load_xpak(xp)
    st = os.path.getmtime(xp); c = _XPAK_BYHASH.get(xp)
    if c and c[0] == st: return mm, h, c[1]
    bh = {e['hash']: e for e in ents}
    while len(_XPAK_BYHASH) >= 6: _XPAK_BYHASH.pop(next(iter(_XPAK_BYHASH)))
    _XPAK_BYHASH[xp] = (st, bh); return mm, h, bh
def _xpak_entry_for(ff, I, need):
    """Locate the xpak entry that holds the base (full-res) mip for the GfxImage at struct offset I. The image
    struct stores its mip stream-hashes (one per mip: u64 at +0x08/+0x30/+0x58/+0x80 …), each an xpak entry key;
    we select BY HASH (not size — several images can share dimensions, so size-matching grabs the wrong one),
    taking the smallest referenced entry whose payload still holds `need` bytes. Searches the sibling xpak first,
    then the shared base.xpak/initial.xpak where retail base-game mips actually live (the per-ff sibling is empty
    for base fastfiles). Both the viewer (_xpak_pixels) and the editor (image_replace) go through here so they act
    on the SAME entry. Returns (xpath, mmap, header, entry) or None."""
    pay = _pay(ff)
    cand = {_u(pay, I+off, 8) for off in range(0, 0x120, 4)}      # mip stream-hashes in the image struct
    for xp in _img_xpaks(ff):                                     # sibling, then base.xpak + initial.xpak
        try: mm, h, bh = _xpak_byhash(xp)
        except Exception: continue
        mine = [bh[c] for c in cand if c in bh and (bh[c]['size'] - 0x80) >= need - 0x100]
        if mine:
            e = min(mine, key=lambda e: e['size'])                # base mip = smallest referenced entry that fits
            try:
                if len(xpak.entry_raw(mm, e, h)) >= need: return xp, mm, h, e
            except Exception: pass
    # fallback (no hash link found): size-match against raw entries in the sibling only (mod xpaks)
    sib = _sibling_xpak(ff)
    if sib:
        try:
            d = open(sib, 'rb').read(); h = xpak.parse_header(d)
            for e in sorted(xpak.entries(d, h), key=lambda x: abs((x['size']-0x80) - need)):
                if abs((e['size']-0x80) - need) <= 0x200 and xpak.is_raw(d, e, h):
                    if len(xpak.entry_raw(d, e, h)) >= need: return sib, d, h, e
        except Exception: pass
    return None
def _xpak_pixels(ff, I, need):
    """Fetch the base-mip pixel bytes for the GfxImage at struct offset I from whichever xpak holds it (sibling for
    mods, shared base.xpak/initial.xpak for retail base ffs). Decompresses transparently (raw or LZ4 block)."""
    got = _xpak_entry_for(ff, I, need)
    if not got: return None
    _xp, d, h, e = got
    return xpak.entry_raw(d, e, h)[:need]

_IMG_BPB = {9: 8, 7: 8, 3: 16, 4: 16, 2: 16, 1: 4}       # bytes per 4x4 block (RGBA8 counts per-pixel below)
def _img_need(w, h, fmt):
    if fmt == 1: return w*h*4
    return max(1, (w+3)//4) * max(1, (h+3)//4) * _IMG_BPB.get(fmt, 16)
def _img_streamed(ff, I):
    """True if this GfxImage's base mip is streamed in an xpak (any mip stream-hash matches an entry in the sibling
    OR the shared base.xpak/initial.xpak). The reliable inline-vs-streamed test — the payload-gap heuristic
    false-triggers on 0xff runs inside RGBA pixels, and base-ff mips live in the shared xpaks, not a sibling."""
    d = _pay(ff)
    cand = {_u(d, I+off, 8) for off in range(0, 0x120, 4)}
    for xp in _img_xpaks(ff):
        try: _mm, _h, bh = _xpak_byhash(xp)
        except Exception: continue
        if not cand.isdisjoint(bh.keys()): return True
    return False
def _encode_texture(im, fmt, w, h):
    """Encode a PIL image to the raw pixel bytes for GfxImage format `fmt` at w×h. Supports BC1/BC3/RGBA8
    (via Pillow); BC5/BC7 are not supported."""
    import io
    im = im.convert('RGBA').resize((w, h))
    if fmt in (9, 7):                                    # BC1 / DXT1
        b = io.BytesIO(); im.convert('RGB').save(b, 'DDS', pixel_format='DXT1'); return b.getvalue()[0x80:]
    if fmt == 3:                                         # BC3 / DXT5
        b = io.BytesIO(); im.save(b, 'DDS', pixel_format='DXT5'); return b.getvalue()[0x80:]
    if fmt == 1:                                         # RGBA8 (uncompressed)
        return im.tobytes()
    raise RuntimeError("BC5/BC7 textures can't be replaced yet.")
def _write_xpak_data(xd, base, size, data):
    """Overwrite an xpak entry's de-chunked payload IN PLACE: each 0x40000 block is [0x80 header][data]; write
    `data` across the data slots, leaving the block headers intact. Requires len(data) <= de-chunked capacity."""
    o = 0; di = 0
    while o < size and di < len(data):
        avail = min(0x40000, size - o) - 0x80
        if avail <= 0: break
        n = min(avail, len(data) - di)
        xd[base+o+0x80 : base+o+0x80+n] = data[di:di+n]
        di += n; o += 0x40000
    return di
def image_replace(ff, off, new_image_path, out_ff=None, out_xpak=None):
    """Replace a texture with a new image (same dimensions + format), producing a drop-in ff (inline textures) or
    xpak (streamed textures). Same-size in-place edit, so no pointers change. Re-decodes the result and raises on
    any mismatch. BC1/BC3/RGBA8 only."""
    from PIL import Image
    d = _pay(ff); I = off
    w = _u(d, I+0xC0, 2); h = _u(d, I+0xC2, 2); fmt = d[I+0xA1]
    need = _img_need(w, h, fmt)
    newpx = _encode_texture(Image.open(new_image_path), fmt, w, h)
    if len(newpx) < need:
        raise RuntimeError(f'Encoded texture is smaller than expected ({len(newpx)} < {need} bytes). Nothing was written.')
    newpx = newpx[:need]
    p = I+0x108
    if _u(d, I+0xF8, 8) == F: p = d.index(b'\x00', p) + 1
    avail = max(0, _next_asset(d, I) - p)
    if avail >= need:                                    # INLINE texture -> splice into the payload, new ff
        raw = open(ff, 'rb').read(); newpay = bytearray(d); newpay[p:p+need] = newpx
        comp, _nb, _nm = ffbo3.recompress(bytes(newpay), raw[:ffbo3.HEADER_SIZE])
        p2, _h = ffbo3.decompress(comp)
        if p2[p:p+need] != newpx: raise RuntimeError('Write check failed. Nothing was written.')
        out = out_ff or (os.path.splitext(ff)[0] + '.studio.ff'); open(out, 'wb').write(comp)
        return {'mode': 'inline', 'out': out, 'width': w, 'height': h, 'format': fmt, 'bytes': need}
    # STREAMED texture -> overwrite the same xpak entry the viewer decodes, in place, into a new xpak
    if not _sibling_xpak(ff): raise RuntimeError('This texture is streamed, but no matching .xpak was found next to the .ff.')
    got = _xpak_entry_for(ff, I, need)
    if not got: raise RuntimeError("Couldn't find this texture's data in the .xpak.")
    xp, _dx, xh, e = got
    xd = bytearray(open(xp, 'rb').read())
    if not xpak.is_raw(bytes(xd), e, xh):
        raise RuntimeError("This .xpak is compressed. Replacing streamed textures only works with uncompressed xpaks.")
    written = _write_xpak_data(xd, xh['dataOffset']+e['offset'], e['size'], newpx)
    if written < need: raise RuntimeError(f'The .xpak entry is too small for the new texture ({written} < {need} bytes).')
    out = out_xpak or (os.path.splitext(xp)[0] + '.studio.xpak'); open(out, 'wb').write(bytes(xd))
    chk = xpak.entry_raw(bytes(xd), e, xh)               # check: de-chunk the edited entry, compare
    if chk[:need] != newpx: raise RuntimeError('Write check failed. Nothing was written.')
    return {'mode': 'streamed', 'out': out, 'width': w, 'height': h, 'format': fmt, 'bytes': need}

def image_png(ff, off):
    from PIL import Image
    d = _pay(ff); I = off
    w = _u(d, I+0xC0, 2); h = _u(d, I+0xC2, 2); fmt = d[I+0xA1]
    # T7 GfxImage format byte -> (tag, DXGI, bytes-per-4x4-block):
    #   1 RGBA8 | 2/6 BC7 (color/linear) | 3 BC3 | 4 BC5 (normals) | 7/9 BC1 (gloss/mask)
    #   5/8/11/13 BC4 (single-channel: spec/occlusion/thickness)
    FMT = {1:('RGBA8',28,4), 2:('BC7',98,16), 3:('BC3',77,16), 4:('BC5',83,16),
           5:('BC4',80,8), 6:('BC7',98,16), 7:('BC1',71,8), 8:('BC4',80,8),
           9:('BC1',71,8), 11:('BC4',80,8), 13:('BC4',80,8)}
    tag, dxgi, bpb = FMT.get(fmt, ('BC7', 98, 16))
    if w == 0 or h == 0:                       # reference stub: the GfxImage struct is all-zero and the texture
        # is defined in another fastfile
        raise RuntimeError('This texture is stored in another fastfile. Open that fastfile to view it.')
    need = _img_need(w, h, fmt)               # RGBA8 is per-pixel (w*h*4), not block-compressed
    p = I+0x108
    if _u(d, I+0xF8, 8) == F: p = d.index(b'\x00', p)+1
    # Streamed images keep their base mip in the sibling xpak (keyed by mip hash); inline images carry the full
    # pixel payload right after the struct. Decide by the stream-hash link, not the payload gap — RGBA pixel data
    # contains 0xff runs that false-trigger the next-asset boundary and made inline RGBA8 icons look "streamed".
    if _img_streamed(ff, I):
        px = _xpak_pixels(ff, I, need) or b''
        if len(px) < need and p + need <= len(d):
            px = d[p:p+need]                 # last resort if the xpak entry is short/absent
    else:
        px = d[p:p+need] if p + need <= len(d) else b''
        if len(px) < need:                    # inline came up short — try the xpak by hash as a fallback
            xp2 = _xpak_pixels(ff, I, need)
            if xp2 and len(xp2) >= need: px = xp2
    if len(px) < need:
        raise RuntimeError("This texture's data is in the .xpak and couldn't be read.")
    hdr = struct.pack('<4sIIIIIII44s', b'DDS ', 124, 0x1|0x2|0x4|0x1000|0x80000, h, w, max(1,(w+3)//4)*16, 0, 1, b'\0'*44)
    pf = struct.pack('<II4sIIIII', 32, 0x4, b'DX10', 0, 0, 0, 0, 0)
    dds = hdr+pf+struct.pack('<IIIII', 0x1000, 0, 0, 0, 0)+struct.pack('<IIIII', dxgi, 3, 0, 1, 0)+px
    im = Image.open(io.BytesIO(dds)); im.load(); im = im.convert('RGBA')
    # composite onto checkerboard so alpha is visible
    import numpy as np
    a = np.array(im); bg = np.zeros_like(a[..., :3])
    c = 16
    for y in range(0, a.shape[0], c):
        for x in range(0, a.shape[1], c):
            bg[y:y+c, x:x+c] = (210,210,210) if ((x//c+y//c) % 2 == 0) else (130,130,130)
    al = a[..., 3:4]/255.0
    out = (a[..., :3]*al + bg*(1-al)).astype('uint8')
    buf = io.BytesIO(); Image.fromarray(out).save(buf, 'PNG')
    return buf.getvalue(), dict(width=w, height=h, format=tag)

def _next_asset(d, off):
    """True next-asset boundary after the fx at `off` — skip \\xff*8 runs that are internal fx sample data
    (colors/pointers) rather than a real asset header."""
    N = len(d); scan = off + 0x100
    while True:
        x = d.find(b'\xff'*8, scan, N)
        if x < 0: return N
        if fx_decode.is_fx(d, x) or _is_img(d, x-0xF8) or _is_raw(d, x) or _is_kvp(d, x):
            return x
        scan = x + 1

def fx_view(ff, off):
    d = _pay(ff)
    end = _next_asset(d, off)
    tree = fx_decode.decode(d, off, end)
    tree['efx'] = fx_to_efx.to_efx(d, off, end)   # decompiled .efx source
    tree['curves'] = fx_curves.curves(d, off, end)  # sampled color/alpha/size/velocity curves
    return tree

def font_bytes(ff, off):
    """Raw embedded TrueType file at struct offset `off`. Served as-is to the browser."""
    d = _pay(ff); r = _ttf_at(d, off)
    if not r: raise RuntimeError('no TrueType font at this offset')
    return d[off:off+r['len']], r

# --- materials: MaterialAsset(0x2A0) inline name@0x2A0, textureCount@0x270; inline GfxImages follow the struct
# (MaterialImage[] with ImagePointer==-1). We attribute the GfxImages that sit between this material and the next
# to it (capped at textureCount) and reuse the image decoder for thumbnails. ---
_TEX_ROLE = {'c': 'Color', 'col': 'Color', 'color': 'Color', 'n': 'Normal', 'nml': 'Normal', 'nrm': 'Normal',
             'g': 'Gloss', 'gloss': 'Gloss', 's': 'Specular', 'spec': 'Specular', 'o': 'Occlusion', 'ao': 'Occlusion',
             'r': 'Roughness', 'a': 'Alpha', 'e': 'Emissive', 'em': 'Emissive', 'mask': 'Mask', 'd': 'Detail',
             'anim': 'Animated', 'add': 'Additive'}
_IMG_FMT = {9: 'BC1', 3: 'BC3', 4: 'BC5', 2: 'BC7', 1: 'RGBA8', 7: 'BC1'}
def _tex_role(name):
    base = (name or '').rsplit('/', 1)[-1]
    if base.startswith('$'): return 'Engine default'
    if base.startswith('fxt_'): return 'FX texture'
    m = _re.search(r'_([a-z]{1,4})$', base)
    return _TEX_ROLE.get(m.group(1)) if m else None
def material_view(ff, off):
    """Decode a Material: name + counts + its inline texture set (real thumbnails) + best-effort shader name."""
    import bisect
    d = _pay(ff); inv = inventory(ff); M = off
    mats = sorted((a for a in inv['assets'] if a['type'] == 'material'), key=lambda a: a['offset'])
    imgs = sorted((a for a in inv['assets'] if a['type'] == 'image'), key=lambda a: a['offset'])
    mat_offs = [a['offset'] for a in mats]; img_offs = [a['offset'] for a in imgs]
    end = mat_offs[bisect.bisect_right(mat_offs, M)] if bisect.bisect_right(mat_offs, M) < len(mat_offs) else len(d)
    tc = d[M+0x270] if M+0x272 < len(d) else 0
    sc = d[M+0x271] if M+0x272 < len(d) else 0; cc = d[M+0x272] if M+0x273 < len(d) else 0
    nm = _mat_name(d, M) or next((a['name'] for a in mats if a['offset'] == M), 'material')
    textures = []
    j = bisect.bisect_right(img_offs, M)
    while j < len(img_offs) and img_offs[j] < end and len(textures) < tc:      # inline textures follow the struct
        io = img_offs[j]; im = next(a for a in imgs if a['offset'] == io)
        textures.append({'name': im['name'], 'offset': io, 'role': _tex_role(im['name']),
                         'width': _u(d, io+0xC0, 2), 'height': _u(d, io+0xC2, 2), 'format': _IMG_FMT.get(d[io+0xA1], '?')})
        j += 1
    seg = d[M:min(end, M+0x600)]                                              # best-effort inline shader/technique name
    mts = _re.search(rb'[a-z_][a-z0-9_/]*#[0-9a-f]{6,}', seg)
    return {'name': nm, 'textures': tc, 'samplers': sc, 'constants': cc, 'inline': textures,
            'referenced': max(0, tc - len(textures)), 'techset': mts.group(0).decode('latin1') if mts else None}

# --- techsets: a MaterialTechniqueSet references compiled DXBC (SM5.0) shaders. The shaders sit in the payload
# between this techset and the next one (grouped as vs/ps(/gs) sets), so link
# them positionally and introspect each DXBC container (type/SM + input signature + bound resources + instr count). ---
_SH_TYPE = {0: 'pixel', 1: 'vertex', 2: 'geometry', 3: 'hull', 4: 'domain', 5: 'compute'}
_RES_KIND = {0: 'cbuffer', 1: 'tbuffer', 2: 'texture', 3: 'sampler', 4: 'uav', 5: 'uav-struct', 6: 'byteaddr'}
_DXBC_CACHE = {}
def _dxbc_offsets(ff):
    """Sorted offsets of every valid DXBC shader container in the payload (cached — one 286MB scan per ff)."""
    d = _pay(ff)
    try: st = os.path.getmtime(ff)
    except OSError: st = 0
    c = _DXBC_CACHE.get(ff)
    if c and c[0] == st: return c[1]
    out = []; off = 0; N = len(d)
    while True:
        i = d.find(b'DXBC', off)
        if i < 0: break
        total = _u(d, i+0x18, 4)
        if _u(d, i+0x14, 4) == 1 and 0 < _u(d, i+0x1c, 4) < 32 and 0 < total < 0x200000 and i+total <= N:
            out.append(i)
        off = i + 4
    out.sort(); _DXBC_CACHE.clear(); _DXBC_CACHE[ff] = (st, out)
    return out
def _parse_dxbc(d, i):
    """Introspect a DXBC container: shader type + SM, input signature, bound resources, instruction count."""
    ch = {}
    for c in range(_u(d, i+0x1c, 4)):
        coff = i + _u(d, i+0x20+c*4, 4)
        ch[d[coff:coff+4]] = coff + 8
    out = {'type': '?', 'sm': '?', 'inputs': [], 'resources': [], 'instrs': None, 'size': _u(d, i+0x18, 4)}
    sh = ch.get(b'SHEX') or ch.get(b'SHDR')
    if sh is not None:
        v = _u(d, sh, 4); out['type'] = _SH_TYPE.get((v >> 16) & 0xffff, '?'); out['sm'] = f"{(v>>4)&0xf}.{v&0xf}"
    isg = ch.get(b'ISGN')
    if isg is not None:
        n = _u(d, isg, 4)
        for e in range(min(n, 32)):
            eo = isg + 8 + e*24
            nm = _vn(d, isg + _u(d, eo, 4)) or '?'; idx = _u(d, eo+4, 4); reg = _u(d, eo+16, 4); mask = d[eo+20]
            comps = ''.join(cc for cc, b in zip('xyzw', (1, 2, 4, 8)) if mask & b)
            out['inputs'].append({'semantic': nm + (str(idx) if idx else ''), 'reg': reg, 'comps': comps})
    rdef = ch.get(b'RDEF')
    if rdef is not None:
        rbc = _u(d, rdef+8, 4); rbo = _u(d, rdef+12, 4)
        for r in range(min(rbc, 64)):
            ro = rdef + rbo + r*32
            nm = _vn(d, rdef + _u(d, ro, 4)) or '?'; rt = _u(d, ro+4, 4); bind = _u(d, ro+24, 4)
            out['resources'].append({'name': nm, 'kind': _RES_KIND.get(rt, str(rt)), 'bind': bind})
    stat = ch.get(b'STAT')
    if stat is not None: out['instrs'] = _u(d, stat, 4)
    return out
def techset_view(ff, off):
    """Decode a techset: name + the DXBC shader set it owns (grouped positionally to the next techset)."""
    import bisect
    from collections import Counter
    d = _pay(ff); inv = inventory(ff); M = off
    ts = sorted((a for a in inv['assets'] if a['type'] == 'techset'), key=lambda a: a['offset'])
    to = [a['offset'] for a in ts]
    k = bisect.bisect_left(to, M); end = to[k+1] if k+1 < len(to) else len(d)
    blobs = _dxbc_offsets(ff)
    grp = blobs[bisect.bisect_right(blobs, M):bisect.bisect_left(blobs, end)]
    shaders = [_parse_dxbc(d, b) for b in grp]
    counts = Counter(s['type'] for s in shaders)
    nm = next((a['name'] for a in ts if a['offset'] == M), 'techset')
    # representative = the richest of each type (skip trivial null/depth-only variants with no signature)
    vsl = [s for s in shaders if s['type'] == 'vertex']; psl = [s for s in shaders if s['type'] == 'pixel']
    vs = max(vsl, key=lambda s: len(s['inputs']), default=None)
    ps = max(psl, key=lambda s: len(s['resources']), default=None)
    return {'name': nm, 'shader_count': len(shaders), 'by_type': dict(counts),
            'sm': next((s['sm'] for s in shaders if s['sm'] != '?'), '?'),
            'vertex_inputs': vs['inputs'] if vs else [], 'pixel_resources': ps['resources'] if ps else [],
            'shaders': [{'type': s['type'], 'instrs': s['instrs'], 'size': s['size'], 'resources': len(s['resources'])}
                        for s in shaders]}

# --- models: T7 XModelSurfs / XSurface mesh geometry (format from Scobalula/Greyhound GameBlackOps3.cpp) ---
# The mesh's shared vertex/index buffer (BO3XModelMeshInfo) is streamed in the sibling .xpak (one entry per LOD,
# key = payload of size == dataSize once de-chunked). Layout is STRUCTURE-OF-ARRAYS within that buffer:
#   FacesOffset  -> uint16 index list (triangle list)
#   VertexOffset -> float32 position array, stride 12 (POSITIONS ARE FLOAT32, not quantized)
#   UVOffset     -> per-vertex color/uv(half)/normal(10:10:10)/tangent, stride 16
#   WeightsOffset-> skin weights, stride 12
def _mesh_infos(d, X, limit=None):
    """Yield every self-consistent BO3XModelMeshInfo (0x2C) in [X, limit) — the 4 SoA sub-arrays must tile
    [0, dataSize) IN OFFSET ORDER with only forward alignment padding. `limit` is the next mesh (the inline data
    ends before it); bounding matters — an unbounded scan finds a NEIGHBOURING mesh's header and decodes garbage."""
    end = min(limit or X+0x400, X+0x4000)
    for o in range(X, end):
        flag = _u(d, o, 4)                       # StatusFlag is small (seen 1/2/9/10); the tiling + xpak-size
        if not (0 < flag < 0x100) or _u(d, o+4, 4) == 0: continue   # match + coherence gate do the real checking
        if not (_u(d, o+0x10, 8) == F or (_u(d, o+0x10, 8) >> 60) == 5): continue
        vc = _u(d, o+4, 4); fc = _u(d, o+0xC, 4); ds = _u(d, o+0x18, 4)
        vo = _u(d, o+0x1c, 4); uo = _u(d, o+0x20, 4); fo = _u(d, o+0x24, 4); wo = _u(d, o+0x28, 4)
        if not (8 < vc < 400000 and 8 < fc < 3000000 and vc*12 < ds < 0x2000000): continue
        # the SoA sub-arrays TILE [0, dataSize) in offset order. faces(fc*2)+positions(vc*12)+uv(vc*16) have known
        # sizes and must tile from 0; after them EITHER the buffer ends at dataSize (static mesh, no weights) OR a
        # WEIGHT/extra array [wo, dataSize) fills the rest — its size varies (variable-length skin weights on view
        # models), so don't check it. (We only render faces+positions; the ds consistency is re-checked by the
        # xpak-size match, and the coherence gate rejects any wrong header that slips through.)
        exp = 0; ok = True
        for off, sz in sorted([(fo, fc*2), (vo, vc*12), (uo, vc*16)]):
            if not (-16 <= off-exp < 0x200): ok = False; break
            exp = off+sz
        if ok and ((0 <= ds-exp < 0x200) or (-16 <= wo-exp < 0x200 and 0 < ds-wo < 0x400000)):
            yield {'so': o, 'vc': vc, 'fc': fc, 'ds': ds, 'vo': vo, 'uo': uo, 'fo': fo, 'wo': wo}
def _mesh_info(d, X, limit=None):
    return next(_mesh_infos(d, X, limit), None)
def _decode_mesh(d, off, mi, raw):
    """positions + per-surface-rebased triangles from a decoded (de-chunked) mesh buffer."""
    vc, fc, vo, fo = mi['vc'], mi['fc'], mi['vo'], mi['fo']; so = mi['so']
    P = np.frombuffer(raw[vo:vo+vc*12], dtype=np.float32).reshape(vc, 3).astype(np.float64)
    faces = np.frombuffer(raw[fo:fo+fc*2], dtype=np.uint16).astype(np.int64)
    numSurfs = d[off+0x3C]; parts = []
    for si in range(numSurfs):
        b = so+0x50+si*0x60; sfc = _u(d, b+6, 2); vi = _u(d, b+8, 4); fi = _u(d, b+0xC, 4)
        if fi + sfc*3 <= faces.size and vi + _u(d, b+4, 2) <= vc:
            parts.append(faces[fi:fi+sfc*3] + vi)
    tri = (np.concatenate(parts) if parts else faces[:fc//3*3]).reshape(-1, 3)
    tri = tri[np.all((0 <= tri) & (tri < vc), axis=1)]
    return P, tri, numSurfs
def _coherence(P, tri):
    """(p50, p90) = median and 90th-percentile triangle-edge length as a FRACTION of the model's bounding diagonal.
    A correctly-decoded surface has most edges tiny vs the model (small p50). A WRONG buffer (random float32) has
    edges scattered up to the diagonal (large p50). p90 alone rejects thin, elongated or low-poly geometry, whose
    real triangles include a few long edges while most stay short, so both are used: p50 for the coherent core,
    p90 for uniform meshes."""
    span = P.max(0) - P.min(0); diag = float(np.linalg.norm(span)) or 1.0
    e = np.linalg.norm(P[tri[:, 0]] - P[tri[:, 1]], axis=1)
    return float(np.percentile(e, 50) / diag), float(np.percentile(e, 90) / diag)
def _coherent(p50, p90):
    """Accept a decode as a real surface if the uniform test passes or the coherent-core test does (the latter
    keeps thin/elongated/low-poly meshes the p90 test rejects; random buffers sit well above p50 0.15)."""
    return p90 < 0.55 or p50 < 0.15
_XPAK_CACHE = {}
def _load_xpak(xp):
    """mmap an .xpak and cache its parsed entry table sorted by size. Keeps a few mapped at once (the retail base
    meshes stream from the big shared base.xpak/initial.xpak, reused across many base models)."""
    import mmap
    st = os.path.getmtime(xp); c = _XPAK_CACHE.get(xp)
    if c and c[0] == st: return c[1][1:]
    fh = open(xp, 'rb'); mm = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)   # keep fh alive in the cache
    h = xpak.parse_header(mm); ents = sorted(xpak.entries(mm, h), key=lambda e: e['size'])
    r = (fh, mm, h, ents, [e['size'] for e in ents])
    while len(_XPAK_CACHE) >= 6:                          # evict oldest to bound mapped files
        _XPAK_CACHE.pop(next(iter(_XPAK_CACHE)))
    _XPAK_CACHE[xp] = (st, r); return r[1:]
def _mesh_xpaks(ff):
    """Candidate xpaks holding this ff's streamed mesh buffers: the sibling first, then (for retail base ffs) the big
    shared xpaks where base-game meshes actually live (the per-ff sibling is empty for base fastfiles)."""
    out = []
    sib = _sibling_xpak(ff)
    if sib and os.path.exists(sib) and os.path.getsize(sib) > 2000: out.append(sib)
    zone = bo3_zone_dir()
    if zone and os.path.normpath(os.path.dirname(ff)) == os.path.normpath(zone):
        for b in ('base.xpak', 'initial.xpak', 'base_dlc1.xpak', 'base_dlc2.xpak', 'base_dlc3.xpak'):
            p = os.path.join(zone, b)
            if os.path.exists(p): out.append(p)
    return out
_MESHBUF_CACHE = {}
def _geom_valid_at(d, b, ds, vc, fc, vo, fo, minspan=0.01):
    """True if the buffer at d[b:b+ds] holds a coherent vertex/index mesh at the header's SoA offsets (indices in
    range, positions finite, spanning a real volume). Reads only the small face/position sub-ranges (no big slice),
    so scanning a large candidate window stays cheap even for multi-MB meshes."""
    if b < 0 or b + ds > len(d): return False
    faces = np.frombuffer(d[b+fo:b+fo+fc*2], dtype=np.uint16)
    pos = np.frombuffer(d[b+vo:b+vo+vc*12], dtype=np.float32)
    if not (faces.size and int(faces.max()) < vc and np.all(np.isfinite(pos))): return False
    sp = pos.reshape(-1, 3).astype(np.float64); span = sp.max(0) - sp.min(0)
    return bool(np.all(span > minspan) and np.all(span < 1e5))
def _geom_valid(raw, ds, vc, fc, vo, fo, minspan=0.01):
    """_geom_valid_at against a standalone buffer (the de-chunked xpak entry starts at 0)."""
    return _geom_valid_at(raw, 0, ds, vc, fc, vo, fo, minspan)
def _mesh_buffer(ff, ds, vc, fc, vo, fo, off=None, so=None):
    """The mesh's de-chunked vertex/index buffer, from wherever T7 put it, checked for valid indices/positions
    and cached. The buffer is always [u16 index list at fo][float32 positions at vo][uv at uo]. Sources:
      0. INLINE-SHARED — for an XSurfaceShared with shflags bit0 == 0, the buffer is serialized DETERMINISTICALLY
         right after the 0x50-byte shared header (at so+0x50). This is exact (no search) and correct.
      1. STREAMED-by-hash — a retail mesh carries a u64 xpak stream key at asset-offset +0x48 (same idea as a
         GfxImage's mip hash); resolve it straight to one xpak entry. Only consulted when the header carries a key,
         so a purely-inline mesh never loads the multi-GB base.xpak hash tables.
      2. INLINE-scan — bounded window fallback for meshes whose header offset shifts (name/surf-table size).
      3. STREAMED-by-size — mod/raw xpaks store chunks uncompressed, so an entry's size == ds (never the big base
         xpaks: hundreds of their entries pass the geometry check for any ds, so a size match there is meaningless).
    NOTE: shflags bit0 == 1 (e.g. weapon world LODs) store the buffer in a relocated block region NOT addressable
    from the header without a full loader replay — those are reported not-here rather than shown as a wrong mesh."""
    import bisect
    key = (ff, ds, vc, fo, vo)
    if key in _MESHBUF_CACHE: return _MESHBUF_CACHE[key]
    def _accept(raw):
        if len(_MESHBUF_CACHE) > 24: _MESHBUF_CACHE.clear()
        _MESHBUF_CACHE[key] = raw; return raw
    d = _pay(ff); xps = _mesh_xpaks(ff)
    # 0) inline-shared (exact): shflags bit0 == 0 -> buffer sits at so+0x50 (the deterministic, correct location)
    if so is not None and so + 0x50 + ds <= len(d) and (d[so] & 1) == 0:
        if _geom_valid_at(d, so + 0x50, ds, vc, fc, vo, fo, 0.001):
            return _accept(bytes(d[so + 0x50 : so + 0x50 + ds]))
    # 1) streamed-by-hash (only when the header actually carries a key)
    if off is not None and xps:
        cand = {_u(d, off+o, 8) for o in range(0x40, 0x58, 4)}; cand.discard(0); cand.discard(F)
        for xp in (xps if cand else []):
            try: mm, h, bh = _xpak_byhash(xp)
            except Exception: continue
            for c in cand:
                e = bh.get(c)
                if not e: continue
                try: raw = xpak.entry_raw(mm, e, h)
                except Exception: continue
                if _geom_valid(raw, ds, vc, fc, vo, fo, 0.001): return _accept(raw)
    # 2) inline: bounded window just past the header + surface table (the buffer follows the per-surface descriptor
    #    table, whose size grows with the surface count, so the start shifts out for multi-surface meshes)
    if off is not None:
        ns = d[off + 0x3C] if off + 0x3C < len(d) else 0        # numSurfs -> predicted buffer start after the table
        hi = min(len(d), off + 0x80 + max(ns, 1) * 0x60 + 0x400)
        for b in range(off + 0x80, hi, 4):
            if _geom_valid_at(d, b, ds, vc, fc, vo, fo, 0.001): return _accept(bytes(d[b:b+ds]))
    # 3) streamed-by-size — ONLY for a SMALL sibling/mod xpak, where an entry whose de-chunked size == ds is a
    #    discriminating match. Never for the big shared base xpaks: they hold tens of thousands of entries and
    #    hundreds pass the geometry check for any given ds. A base mesh with no stream hash (#1) and no inline
    #    copy (#2) is reported as not here rather than shown with the wrong buffer.
    for xp in xps:
        try: mm, h, ents, sizes = _load_xpak(xp)
        except Exception: continue
        if len(ents) > 8000: continue                       # base.xpak/initial.xpak/dlc — size-match is meaningless
        i = bisect.bisect_left(sizes, ds); tried = 0
        for j in range(i, len(ents)):
            if sizes[j] > ds + 0x8000 or tried > 160: break
            tried += 1
            try: raw = xpak.entry_raw(mm, ents[j], h)
            except Exception: continue
            if _geom_valid(raw, ds, vc, fc, vo, fo): return _accept(raw)
    raise RuntimeError("Couldn't find this mesh's geometry.")
def mesh_view(ff, off):
    """Decode a T7 mesh to positions + triangle indices for the in-browser three.js viewer. The index list is
    STORED PER-SURFACE and 0-based within each surface, so each surface's faces are re-based by its VerticiesIndex
    (BO3XModelSurface @ so+0x50: vertCount u16@4, faceCount u16@6, VerticiesIndex u32@8, FacesIndex u32@0xC)."""
    import bisect
    d = _pay(ff); nm = _is_mesh(d, off) or 'mesh'
    # meshes with no drawable surface get a plain note instead of an error: collision hulls (physics geometry,
    # different vertex layout) and the engine's null/placeholder models (e.g. viewmodel_usa_no_model).
    _low = (nm or '').lower()
    if 'collision' in _low or _low.startswith('collision_geo'):
        raise RuntimeError('Collision mesh (not displayed).')
    if 'no_model' in _low or _re.fullmatch(r'_[a-z]{6,}', nm or ''):
        raise RuntimeError('Placeholder model with no geometry.')
    moffs = sorted(a['offset'] for a in inventory(ff)['assets'] if a['type'] == 'xmodelmesh')  # bound to next MESH
    i = bisect.bisect_right(moffs, off); nxt = moffs[i] if i < len(moffs) else len(d)
    best = None; had_candidate = False; tried = 0
    for mi in _mesh_infos(d, off, nxt):           # try each candidate header; keep the one that decodes COHERENTLY
        had_candidate = True
        if tried >= 10: break                     # cap: the true header is the first few; don't grind
        tried += 1
        try: raw = _mesh_buffer(ff, mi['ds'], mi['vc'], mi['fc'], mi['vo'], mi['fo'], off, mi.get('so'))
        except Exception: continue
        P, tri, numSurfs = _decode_mesh(d, off, mi, raw)
        if len(tri) < 4: continue
        span = P.max(0) - P.min(0)
        p50, p90 = _coherence(P, tri)              # coherent surface: most edges small vs the model size
        if best is None or p50 < best[0]: best = (p50, p90, P, tri, numSurfs, span)
        if _coherent(p50, p90): break              # clearly coherent — accept immediately
    if best is None:
        hint = _ref_home_hint(nm)                  # header exists but no buffer here -> likely referenced elsewhere
        if not had_candidate:
            raise RuntimeError(hint or 'No geometry in this fastfile.')
        raise RuntimeError(hint or 'No geometry in this fastfile.')
    p50, p90, P, tri, numSurfs, span = best
    if not _coherent(p50, p90):                    # a scrambled decode (wrong header) -> refuse rather than show a mess
        raise RuntimeError("Couldn't decode this mesh.")
    mn = P.min(0); mx = P.max(0); c = (mn+mx)/2; s = float((mx-mn).max()) or 1.0
    Pn = ((P-c)/s)
    return {'name': nm, 'vertexCount': int(P.shape[0]), 'triCount': int(len(tri)), 'surfaces': int(numSurfs),
            'bounds': [float(v) for v in span],
            'positions': [round(float(v), 5) for v in Pn.reshape(-1)],
            'indices': [int(v) for v in tri.reshape(-1)]}

def _best_mesh(ff, off):
    """Shared mesh-header selection (same coherence gate as mesh_view). Returns (mi, raw, P, tri, numSurfs)."""
    import bisect
    d = _pay(ff)
    moffs = sorted(a['offset'] for a in inventory(ff)['assets'] if a['type'] == 'xmodelmesh')
    i = bisect.bisect_right(moffs, off); nxt = moffs[i] if i < len(moffs) else len(d)
    best = None; tried = 0
    for mi in _mesh_infos(d, off, nxt):
        if tried >= 10: break
        tried += 1
        try: raw = _mesh_buffer(ff, mi['ds'], mi['vc'], mi['fc'], mi['vo'], mi['fo'], off, mi.get('so'))
        except Exception: continue
        P, tri, numSurfs = _decode_mesh(d, off, mi, raw)
        if len(tri) < 4: continue
        p50, p90 = _coherence(P, tri)
        if best is None or p50 < best[0]: best = (p50, p90, mi, raw, P, tri, numSurfs)
        if _coherent(p50, p90): break
    if best is None or not _coherent(best[0], best[1]):
        raise RuntimeError('No usable mesh for this model.')
    return best[2], best[3], best[4], best[5], best[6]

def mesh_skin(ff, model_off):
    """Skinned mesh for a MODEL offset: RAW bind positions (model space) + indices + per-vertex bone indices/weights,
    for the animation viewer to deform with the posed skeleton. Skin data: GfxStreamWeight (12B/vertex) = 4 u8 weights
    then 4 u16 bone indices; a rigid vertex is w0=255,id0=bone. Weights are the vertex's own indices into the model
    skeleton, so no bone map is needed."""
    d = _pay(ff)
    name = _is_xmodel(d, model_off) or 'model'
    # linked drawable mesh (same name-prefix link as xmodel_view)
    inv = inventory(ff)
    meshes = sorted((a for a in inv['assets'] if a['type'] == 'xmodelmesh'), key=lambda a: a['offset'])
    linked = [m for m in meshes if _strip_hash(m['name']).startswith(name)]
    err = None; chosen = None
    for m in sorted(linked, key=lambda m: ('lod0' not in m['name'], m['offset'])):
        try:
            mi, raw, P, tri, numSurfs = _best_mesh(ff, m['offset']); chosen = m; break
        except Exception as e:
            err = str(e); continue
    if chosen is None:
        return {'error': 'no drawable mesh linked to this model' + (f' ({err})' if err else '')}
    vc = int(P.shape[0]); wo = mi['wo']
    if vc * 12 + wo > len(raw) or vc > 300000:
        return {'error': 'mesh too large or has no weight buffer'}
    W = np.frombuffer(raw[wo:wo + vc * 12], dtype=np.uint8).reshape(vc, 12)
    wts = W[:, 0:4]                                              # 4 u8 weights
    bones = np.frombuffer(raw[wo:wo + vc * 12], dtype=np.uint16).reshape(vc, 6)[:, 2:6]  # 4 u16 bone ids
    # raw model-space positions (the skeleton view uses the same CoD space; the frontend normalises identically)
    return {'name': chosen['name'], 'vertexCount': vc, 'triCount': int(len(tri)),
            'positions': [round(float(v), 5) for v in P.reshape(-1)],
            'indices': [int(v) for v in tri.reshape(-1)],
            'boneIdx': [int(v) for v in bones.reshape(-1)],
            'boneWt': [int(v) for v in wts.reshape(-1)]}

# --- animations: T7 XAnimParts. frameCount@0x20(u16), boneCount@0x22(u16), framerate@0x50(f32), name@0xF8. The
# bone-name array (boneCount ScrString_t, one u32 index into the ff string pool each) is the first inline array
# after the name (offset 0x68). Keyframes are decoded by xanim_decode. ---
def _djb2l(s):
    """T7 string hash: 32-bit DJB2 (seed 5381, mult 33) of the lowercased bytes, as stored in StringTableCell
    {string, hash}. `s` is bytes."""
    h = 5381
    for b in s.lower(): h = ((h * 33) + b) & 0xFFFFFFFF
    return h
_STRHASH_CACHE = {}
_CLEAN_STR = _re.compile(rb'^[A-Za-z0-9_./:$#\- ]+$')
def _str_hash_index(ff):
    """Cached {djb2l(string): (string_bytes, is_clean)} over EVERY null-terminated printable run in the payload,
    plus a set of hashes where two DISTINCT *clean* strings collide (genuine ambiguity). This resolves the block-5
    "pooled" references that T7 assets use for shared strings (e.g. StringTable cells) WITHOUT reconstructing the
    block partition: the referenced string lives in the payload, and its DJB2 hash is stored alongside the pointer,
    so a hash lookup recovers it. On collision a clean identifier beats a binary fragment, so real values win
    regardless of scan order. Built once per ff."""
    d = _pay(ff)
    try: st = os.path.getmtime(ff)
    except OSError: st = 0
    c = _STRHASH_CACHE.get(ff)
    if c and c[0] == st: return c[1], c[2]
    idx = {}; clean_coll = set()
    for m in _re.finditer(rb'[ -~]{1,128}\x00', d):
        s = m.group()[:-1]; hv = _djb2l(s); clean = bool(_CLEAN_STR.match(s))
        cur = idx.get(hv)
        if cur is None: idx[hv] = (s, clean)
        elif cur[0] != s:
            if clean and not cur[1]: idx[hv] = (s, True)       # clean gamedata beats binary garbage
            elif clean and cur[1]: clean_coll.add(hv)          # genuine clean-vs-clean ambiguity
    idx[_djb2l(b'')] = (b'', True)
    if len(_STRHASH_CACHE) > 3: _STRHASH_CACHE.clear()
    _STRHASH_CACHE[ff] = (st, idx, clean_coll); return idx, clean_coll
_STRPOOL_CACHE = {}
def _strpool(ff):
    d = _pay(ff)
    try: st = os.path.getmtime(ff)
    except OSError: st = 0
    c = _STRPOOL_CACHE.get(ff)
    if c and c[0] == st: return c[1]
    try:
        strings, _al, _o = _fd.parse_xassetlist(d)
        pool = [s.decode('latin1', 'replace') if isinstance(s, (bytes, bytearray)) else s for s in strings]
    except Exception:
        pool = []
    _STRPOOL_CACHE.clear(); _STRPOOL_CACHE[ff] = (st, pool); return pool
def _strip_hash(n): return _re.sub(r'[0-9a-f]{6,}$', '', n or '')
def _name_base(n):
    """Canonical base shared by an XModel and its LOD meshes: drop the `_lodN…` / `_col…` marker (and everything the
    content hash appends after it), any leftover trailing hash, and the render-variant suffix. An XModel is named
    after its lod0 surfs (…_lod0<hash>), so `_name_base(model) == _name_base(mesh)` links them exactly — robust where
    prefix matching fails (truncated/hash-only names) without the false links a bare substring test invites."""
    n = _re.sub(r'_(lod\d+|col)[0-9a-f]*$', '', n or '')       # LOD / collision marker + trailing hash
    n = _strip_hash(n)                                          # any remaining trailing content hash
    n = _re.sub(r'_(world|view|viewmodel|fp|third)$', '', n)   # render-variant suffix (variants share one base mesh)
    return n

# --- base-game model index: resolve a mod animation to the real base-game model (skeleton/mesh) it drives, even
# when that model lives in the installed retail fastfiles rather than the mod. Bone names are matched by resolved
# STRING (each ff has its own scriptString pool), and ranked by model-coverage (how much of the model the anim
# drives) so a viewmodel anim finds the right viewhands/weapon and not a humanoid that merely shares j_spine etc. ---
def _model_bone_names(d, X, pool):
    """Resolved bone-name set for the xmodel at X (inline boneNames @0x10), or None."""
    nb = d[X+8]; nc = _u(d, X+0xA, 2); tot = nb + nc
    if not (0 < tot < 4000) or _u(d, X+0x10, 8) != F: return None
    nend = d.index(b'\x00', X+0x188) + 1
    out = set()
    for i in range(tot):
        idx = _u(d, nend+4*i, 4)
        if 0 <= idx < len(pool) and pool[idx]: out.add(pool[idx])
    return out
def bo3_zone_dir():
    """Path to the installed retail BO3 zone/ folder (base fastfiles), or None."""
    game = steamlib.find_app_dir(steamlib.BO3_DIR)
    z = os.path.join(game, 'zone') if game else None
    return z if z and os.path.isdir(z) else None
def _base_index_path():
    base = os.path.dirname(sys.executable) if getattr(sys, 'frozen', False) else HERE
    return os.path.join(base, '_studio_cache', 'base_models.json')
def _base_index_ffs(zone):
    # The shared zombies models live in these: core_common holds the character viewhands; zm_levelcommon the common
    # weapons + zombie characters; zm_common the basics. This curated set covers the vast majority of "mod anim on a
    # base asset" cases while staying fast/low-memory to index (indexing every 100-228MB map ff is slow and OOM-prone).
    want = ['core_common.ff', 'zm_levelcommon.ff', 'zm_common.ff']
    fs = [os.path.join(zone, w) for w in want if os.path.exists(os.path.join(zone, w))]
    return fs
def build_base_index(log=None):
    """Scan the retail zombies fastfiles and cache every model's resolved bone-name set. One-time (~2 min); cached
    to _studio_cache/base_models.json keyed by the ff set + mtimes. Returns {models, ffs} or {error}."""
    import json
    zone = bo3_zone_dir()
    if not zone: return {'error': 'retail BO3 install (zone/*.ff) not found'}
    ffs = _base_index_ffs(zone)
    sig = [[os.path.basename(f), int(os.path.getmtime(f))] for f in ffs]
    models = []
    for ff in ffs:
        try:
            d = _pay(ff); pool = _strpool(ff)
            for a in inventory(ff)['assets']:
                if a['type'] != 'xmodel': continue
                bs = _model_bone_names(d, a['offset'], pool)
                if bs and len(bs) >= 3:
                    models.append({'ff': ff, 'off': int(a['offset']), 'name': a['name'], 'bones': sorted(bs)})
            if log: log(f'{os.path.basename(ff)}: {len(models)} models so far')
        except Exception as e:
            if log: log(f'skip {os.path.basename(ff)}: {e}')
        finally:
            import gc; _cache.clear(); _STRPOOL_CACHE.clear(); _INV_CACHE.clear(); gc.collect()
    os.makedirs(os.path.dirname(_base_index_path()), exist_ok=True)
    json.dump({'zone': zone, 'sig': sig, 'models': models}, open(_base_index_path(), 'w'))
    return {'models': len(models), 'ffs': len(ffs)}
def _base_index_fresh():
    """True if the on-disk cache exists and matches the current base-ff set (no build needed)."""
    import json
    zone = bo3_zone_dir()
    if not zone or not os.path.exists(_base_index_path()): return False
    try:
        j = json.load(open(_base_index_path()))
        cur = [[os.path.basename(f), int(os.path.getmtime(f))] for f in _base_index_ffs(zone)]
        return j.get('sig') == cur
    except Exception:
        return False
import threading as _threading
_BASE_BUILD = {'status': 'idle', 'msg': ''}
def base_index_state():
    if _BASE_INDEX is not None or _base_index_fresh(): return {'status': 'ready', 'msg': ''}
    if bo3_zone_dir() is None: return {'status': 'unavailable', 'msg': 'retail BO3 install not found'}
    return dict(_BASE_BUILD)
def start_base_index_build():
    """Kick off a one-time background build of the base-model index (no-op if ready/already building)."""
    if _BASE_INDEX is not None or _base_index_fresh(): return
    if _BASE_BUILD['status'] == 'building': return
    _BASE_BUILD.update(status='building', msg='indexing base-game fastfiles (one-time)…')
    def run():
        try:
            load_base_index(rebuild=False); _BASE_BUILD.update(status='ready', msg='')
        except Exception as e:
            _BASE_BUILD.update(status='error', msg=str(e))
    _threading.Thread(target=run, daemon=True).start()
_BASE_INDEX = None
def load_base_index(rebuild=False):
    """Load the cached base-model index (build it if missing/stale). Returns the list of model records or []."""
    global _BASE_INDEX
    import json
    if _BASE_INDEX is not None and not rebuild: return _BASE_INDEX
    zone = bo3_zone_dir()
    if not zone: _BASE_INDEX = []; return _BASE_INDEX
    p = _base_index_path()
    fresh = False
    if os.path.exists(p) and not rebuild:
        try:
            j = json.load(open(p)); cur = [[os.path.basename(f), int(os.path.getmtime(f))] for f in _base_index_ffs(zone)]
            if j.get('sig') == cur: _BASE_INDEX = j['models']; fresh = True
        except Exception: pass
    if not fresh:
        build_base_index();
        try: _BASE_INDEX = json.load(open(p))['models']
        except Exception: _BASE_INDEX = []
    return _BASE_INDEX
def base_match(anim_bone_names, limit=12):
    """Rank base-game models that this animation's bones drive. Coverage = matched / model-bones; a real match drives
    most of the model. Returns [{ff,off,name,boneCount,matched,score}] best-first (dedup identical-bone models)."""
    an = set(anim_bone_names or [])
    if not an: return []
    idx = load_base_index()
    out = []
    for m in idx:
        bs = m['bones']; inter = len(an.intersection(bs))
        if inter < 6: continue
        cov = inter / max(1, len(bs))
        if cov < 0.55: continue
        out.append({'ff': m['ff'], 'off': m['off'], 'name': m['name'], 'boneCount': len(bs),
                    'matched': inter, 'score': round(cov, 3)})
    out.sort(key=lambda m: (-m['score'], -m['matched'], -m['boneCount']))
    # dedup by (name-stripped, matched, boneCount) so 8 identical viewhands skins collapse to a few
    seen = {}; ded = []
    for m in out:
        k = (m['matched'], m['boneCount'])
        seen[k] = seen.get(k, 0) + 1
        if seen[k] <= 3: ded.append(m)
    return ded[:limit]

# --- XModel skeleton (bind pose): parents + local rotations/translations + global base matrices. Layout (fastfile,
# packed, no alignment): name@0x188 (inline) -> boneNames[tot] ScrString(u32) -> parents[tot-root] (1 byte each,
# parent = i - byte for real bones) -> rotations[tot-root] QuatData(4 half-floats) -> translations[tot-root]
# Vector3(3 f32) -> ... -> baseMatrices[tot] DObjAnimMat(quat 4f + pos 3f + pad = 32B, GLOBAL bind). The base-matrix
# array is located by forward-kinematics consistency: world(i)=world(parent)∘local(i) must reproduce the stored
# globals (as in Greyhound's CoDXModelTranslator). ---
def _qmul(a, b):
    ax, ay, az, aw = a; bx, by, bz, bw = b
    return (aw*bx+ax*bw+ay*bz-az*by, aw*by-ax*bz+ay*bw+az*bx,
            aw*bz+ax*by-ay*bx+az*bw, aw*bw-ax*bx-ay*by-az*bz)
def _qrot(q, v):
    x, y, z, w = q; vx, vy, vz = v
    tx = 2*(y*vz-z*vy); ty = 2*(z*vx-x*vz); tz = 2*(x*vy-y*vx)
    return (vx+w*tx+(y*tz-z*ty), vy+w*ty+(z*tx-x*tz), vz+w*tz+(x*ty-y*tx))
def _decode_skeleton(d, X):
    """Decode a model's bind skeleton. Returns per-bone parent + local rotation/translation (root carries its global
    transform as its 'local' so FK is uniform), plus the FK-validated global bind positions. `ok`/`fkError` report
    whether the base-matrix array was located and FK-consistent."""
    import struct as _st
    half = lambda o: _st.unpack('<e', d[o:o+2])[0]
    f32 = lambda o: _st.unpack('<f', d[o:o+4])[0]
    nb = d[X+8]; nc = _u(d, X+0xA, 2); nr = d[X+9]; tot = nb + nc; nonroot = tot - nr
    if not (0 < tot <= 4000 and 0 < nr <= tot): return None
    nend = d.index(b'\x00', X+0x188) + 1
    arrays = nend + tot*4
    parents = [-1]*tot
    for i in range(nr, tot):
        off = d[arrays + (i-nr)]; parents[i] = (i-off) if i < nb else off
    rot_off = arrays + nonroot; tr_off = rot_off + nonroot*8; tr_end = tr_off + nonroot*12
    if tr_end + tot*32 > len(d): return None
    lrot = [None]*tot; ltr = [None]*tot
    for k in range(nonroot):
        i = nr + k
        q = tuple(half(rot_off+8*k+2*j) for j in range(4))
        n = (q[0]*q[0]+q[1]*q[1]+q[2]*q[2]+q[3]*q[3]) ** 0.5 or 1.0
        lrot[i] = tuple(c/n for c in q)                       # renormalise quantised quat
        ltr[i] = (f32(tr_off+12*k), f32(tr_off+12*k+4), f32(tr_off+12*k+8))
    # locate base matrices (DObjAnimMat stride 32) by FK consistency
    best = None
    limit = min(tr_end + 2048, len(d) - tot*32)
    bm = tr_end
    while bm < limit:
        q0 = tuple(f32(bm+4*j) for j in range(4))
        if 0.9 < (q0[0]*q0[0]+q0[1]*q0[1]+q0[2]*q0[2]+q0[3]*q0[3]) ** 0.5 < 1.1:
            gq = [tuple(f32(bm+32*i+4*j) for j in range(4)) for i in range(tot)]
            gp = [(f32(bm+32*i+16), f32(bm+32*i+20), f32(bm+32*i+24)) for i in range(tot)]
            wq = [None]*tot; wp = [None]*tot; err = 0.0; okc = True
            for i in range(tot):
                p = parents[i]
                if p < 0:
                    wq[i] = gq[i]; wp[i] = gp[i]                # root: use stored global
                else:
                    if wq[p] is None: okc = False; break
                    wq[i] = _qmul(wq[p], lrot[i]); t = _qrot(wq[p], ltr[i])
                    wp[i] = (wp[p][0]+t[0], wp[p][1]+t[1], wp[p][2]+t[2])
                    dx, dy, dz = wp[i][0]-gp[i][0], wp[i][1]-gp[i][1], wp[i][2]-gp[i][2]
                    err += (dx*dx+dy*dy+dz*dz) ** 0.5
            if okc and (best is None or err < best[0]):
                best = (err, bm, gq, gp)
                if err/max(1, nonroot) < 1e-4: break
        bm += 4
    fkerr = (best[0]/max(1, nonroot)) if best else None
    if best:
        _, bm, gq, gp = best
        for i in range(nr):                                    # fill root locals from stored global
            lrot[i] = gq[i]; ltr[i] = gp[i]
        bindPos = gp
    else:                                                      # no base matrices found: root at identity/origin
        for i in range(nr):
            lrot[i] = (0.0, 0.0, 0.0, 1.0); ltr[i] = (0.0, 0.0, 0.0)
        wq = [None]*tot; wp = [None]*tot
        for i in range(tot):
            p = parents[i]
            if p < 0: wq[i] = lrot[i]; wp[i] = ltr[i]
            else:
                wq[i] = _qmul(wq[p], lrot[i]); t = _qrot(wq[p], ltr[i])
                wp[i] = (wp[p][0]+t[0], wp[p][1]+t[1], wp[p][2]+t[2])
        bindPos = wp
    return {'total': tot, 'roots': nr, 'parents': parents, 'localRot': lrot, 'localTrans': ltr,
            'bindPos': bindPos, 'fkError': fkerr, 'ok': fkerr is not None and fkerr < 0.05}
def skeleton_view(ff, off):
    """JSON-friendly bind skeleton for a model offset: names, parents, per-bone local rotation/translation, bind
    positions, and validation. Used by the animation viewer to pose a real skeleton with decoded anim curves."""
    d = _pay(ff); pool = _strpool(ff)
    s = _decode_skeleton(d, off)
    if not s: return {'error': 'skeleton not decodable for this model'}
    name = _is_xmodel(d, off) or 'model'
    nend = d.index(b'\x00', off+0x188) + 1
    names = []
    for i in range(s['total']):
        idx = _u(d, nend+4*i, 4)
        names.append(pool[idx] if 0 <= idx < len(pool) and pool[idx] else f'bone_{idx}')
    return {'name': name, 'boneCount': s['total'], 'roots': s['roots'], 'ok': s['ok'],
            'fkError': round(s['fkError'], 6) if s['fkError'] is not None else None,
            'names': names, 'parents': s['parents'],
            'localRot': [[round(c, 6) for c in q] for q in s['localRot']],
            'localTrans': [[round(c, 5) for c in t] for t in s['localTrans']],
            'bindPos': [[round(c, 4) for c in p] for p in s['bindPos']]}
def _ref_home_hint(name):
    """User-facing note for a mesh/model whose geometry isn't in the open fastfile (it streams from a shared xpak
    without a usable key, or the asset is a reference stub defined in another fastfile). Returns None for assets
    that have no geometry at all (collision hulls, null placeholders)."""
    n = (name or '').lower()
    if 'collision' in n or 'no_model' in n:
        return None
    return "The geometry for this model is stored in another fastfile. Open that fastfile to view it."
def _resolve_geometry_elsewhere(cur_ff, name):
    """When a model's geometry isn't in cur_ff, find the SAME model in a cached shared base ff and return
    (mesh_ff, meshOffset, meshName). Uses only an ALREADY-built base index (never triggers the ~2-min build) so it's
    non-blocking; returns None if the index isn't ready or nothing matches. Covers shared base assets (viewhands live
    in core_common, shared zombie meshes in zm_levelcommon); assets that only exist in a map's own ff aren't
    covered."""
    if not (_BASE_INDEX is not None or _base_index_fresh()): return None
    mb = _name_base(name)
    if len(mb) < 4: return None
    try: idx = load_base_index()
    except Exception: return None
    cur = os.path.normpath(cur_ff)
    for rec in idx:
        if os.path.normpath(rec['ff']) == cur or _name_base(rec['name']) != mb: continue
        try: rr = xmodel_view(rec['ff'], rec['off'], _allow_xff=False)   # _allow_xff=False: no recursion
        except Exception: continue
        if rr.get('meshOffset') is not None:
            return rec['ff'], rr['meshOffset'], rr.get('meshName')
    return None
def xmodel_view(ff, off, _allow_xff=True):
    """Assemble an XModel: link it to its drawable LOD mesh(es) by name, resolve its skeleton bone names, and list
    the materials it uses (positionally, with a preview texture). Geometry is rendered from the linked mesh. When the
    geometry isn't in this ff, `_allow_xff` lets it resolve from a cached shared base ff (returns `meshFF`/`resolvedFrom`)."""
    d = _pay(ff); X = off; inv = inventory(ff); pool = _strpool(ff)
    name = _is_xmodel(d, X) or 'xmodel'
    nb = d[X+8]; nc = _u(d, X+0xA, 2); nl = d[X+0x40]; bc = nb + nc
    # skeleton bone names: boneNames ScrString[bc] @ 0x10, inline right after the name
    bones = []
    if _u(d, X+0x10, 8) == F and 0 < bc < 4000:
        p = d.index(b'\x00', X+0x188) + 1 if _u(d, X, 8) == F else X+0x188
        for i in range(bc):
            idx = _u(d, p+i*4, 4)
            bones.append(pool[idx] if 0 <= idx < len(pool) and pool[idx] else f'bone_{idx}')
    # link to LOD meshes by the CANONICAL BASE both the model and its surfs share (an XModel is named after its lod0
    # surfs, so base==base is exact). This links the truncated/hash-only character-part names (…g_larmspawn_lod0…,
    # or a bare content hash) that a prefix test can't, while base equality avoids the false links a substring test
    # invites. Fall back to a prefix match for any name the base rule misses.
    meshes = sorted((a for a in inv['assets'] if a['type'] == 'xmodelmesh'), key=lambda a: a['offset'])
    mbase = _name_base(name)
    linked = [m for m in meshes if _name_base(m['name']) == mbase] if len(mbase) >= 4 else []
    if not linked and len(name) >= 4:
        # a model with no _lod marker and a name whose tail is itself hex (…_fb, …_body1) confuses the base rule
        # (_name_base over-strips the abutting content hash: c_t7_ally_fb2290068a -> c_t7_ally_). Link by exact prefix
        # where the mesh's remainder past the model name is PURE hex (the content hash, no separator) — precise, no
        # false links (a separator like '_' in the remainder rejects it).
        linked = [m for m in meshes if m['name'].startswith(name)
                  and _re.fullmatch(r'[0-9a-f]*', m['name'][len(name):])]
    if not linked:
        linked = [m for m in meshes if _strip_hash(m['name']).startswith(name)]
    # pick the highest-detail LOD that decodes. LODs are often all named `_lod0<hash>`, so rank by the header's
    # vertex count rather than offset/name.
    def _vc(m):
        mi = _mesh_info(d, m['offset']); return mi['vc'] if mi else 0
    drawable = None
    for m in sorted(linked, key=lambda m: -_vc(m)):
        try:
            mesh_view(ff, m['offset']); drawable = m['offset']; break
        except Exception:
            continue
    mesh_ff = ff; xff_name = None
    # CROSS-FF: geometry not here, but the SAME model may live (with its buffer) in a shared base ff. Resolve it so
    # the viewer renders it instead of only hinting — the frontend fetches the mesh from `meshFF`, not the open ff.
    if drawable is None and _allow_xff:
        xr = _resolve_geometry_elsewhere(ff, name)
        if xr: mesh_ff, drawable, xff_name = xr
    # referenced-elsewhere hint: meshes are linked but none decode here (the geometry is streamed/defined in the ff
    # that owns it), OR there's no mesh at all and it isn't a collision/placeholder model
    hint = _ref_home_hint(name) if (drawable is None and (linked or not _re.search(r'collision|no_model', name.lower()))) else None
    local_name = next((m['name'] for m in linked if m['offset'] == drawable), None) if mesh_ff == ff else None
    return {'name': name, 'boneCount': int(bc), 'lods': int(nl), 'bones': bones,
            'meshOffset': drawable, 'meshFF': (mesh_ff if drawable is not None else None),
            'resolvedFrom': (os.path.basename(mesh_ff) if (drawable is not None and mesh_ff != ff) else None),
            'linkedMeshes': len(linked), 'hint': hint, 'meshName': (xff_name or local_name)}
_MODELHASH_CACHE = {}
def _model_bone_hashes(ff):
    """Cached index {modelOffset: (name, boneCount, frozenset(boneNameHashes))} for anim->model linking."""
    d = _pay(ff)
    try: st = os.path.getmtime(ff)
    except OSError: st = 0
    c = _MODELHASH_CACHE.get(ff)
    if c and c[0] == st: return c[1]
    idx = {}
    for a in inventory(ff)['assets']:
        if a['type'] != 'xmodel': continue
        X = a['offset']
        try:
            nb = d[X+8]; nc = _u(d, X+0xA, 2); tot = nb + nc
            if not (0 < tot < 4000) or _u(d, X+0x10, 8) != F: continue
            nend = d.index(b'\x00', X+0x188) + 1
            hashes = frozenset(_u(d, nend+4*i, 4) for i in range(tot))
            idx[X] = (a['name'], tot, hashes)
        except Exception:
            continue
    _MODELHASH_CACHE.clear(); _MODELHASH_CACHE[ff] = (st, idx); return idx
def _link_models(ff, anim_hashes, anim_name):
    """Rank candidate target models for an animation. Prefers bone-name-hash overlap; falls back to a name-token
    heuristic (view anims -> *_view models, etc.). Returns [{offset,name,boneCount,score}] best-first."""
    idx = _model_bone_hashes(ff)
    ah = frozenset(anim_hashes or [])
    toks = set(_re.findall(r'[a-z0-9]+', (anim_name or '').lower()))
    out = []
    for X, (name, tot, hashes) in idx.items():
        if ah:
            inter = len(ah & hashes)
            score = inter / max(1, tot)                   # fraction of the MODEL's bones this anim drives
            keep = inter >= 4                             # need real coverage, not a 1-bone model scoring 100%
        else:                                             # no anim bone names: token overlap on the model name
            mt = set(_re.findall(r'[a-z0-9]+', name.lower()))
            inter = 0
            score = len(toks & mt) / max(1, len(toks)) * 0.5
            if anim_name.lower().startswith(('vm_', 't10_vm_')) and 'view' in name.lower(): score += 0.25
            keep = score > 0.1
        if keep:
            out.append({'offset': int(X), 'name': name, 'boneCount': int(tot), 'score': round(score, 3),
                        'matched': int(inter)})
    out.sort(key=lambda m: (-m['score'], -m['matched'], -m['boneCount']))   # best coverage, then most bones
    return out[:12]
_PARTTYPE_NAMES = ['noneRot', 'rot2D', 'rot3D', 'rot2Dstatic', 'rot3Dstatic',
                   'transByte', 'transShort', 'transStatic', 'noneTrans']
def anim_view(ff, off):
    """Decode a T7 XAnimParts to real per-bone keyframe tracks (half-float quaternions +
    Min/Size-table translations) plus metadata, via xanim_decode. Bone names resolve from the
    ff string pool when the bone-name array is inline; otherwise fall back to positional names."""
    import math
    d = _pay(ff); X = off
    fc = _u(d, X+0x20, 2); bc = _u(d, X+0x22, 2); fps = _f(d, X+0x50)
    name = _vn(d, X+0xF8) or 'anim'
    dbc = _u(d, X+0x14, 4); dsc = _u(d, X+0xC, 4); dic = _u(d, X+0x18, 4)
    notifies = sum(d[X+o+8] for o in (0xC0, 0xD0, 0xE0) if _u(d, X+o, 8) == F)   # notetrack event count
    base = {'name': name, 'frames': int(fc), 'boneCount': int(bc), 'fps': round(fps, 2),
            'duration': round(fc/fps, 3) if fps else 0, 'notifies': int(notifies),
            'dataBytes': int(dbc), 'dataShorts': int(dsc), 'dataInts': int(dic),
            'animBytes': int(dbc + dsc*2 + dic*4)}
    pool = _strpool(ff)
    try:
        A = xanim_decode.decode_xanim(d, X)
    except Exception as e:                                  # report the failure instead of showing bad motion
        base.update(decoded=False, error=str(e), bones=[f'bone_{i}' for i in range(bc)])
        return base
    # bone names: inline hashes are ScrString pool indices; else positional
    if A['boneNameHashes']:
        names = [pool[i] if 0 <= i < len(pool) and pool[i] else f'bone_{i}' for i in A['boneNameHashes']]
    else:
        names = [f'bone_{i}' for i in range(bc)]
    # per-bone tracks (frame index + value); rot as [f,x,y,z,w], trn as [f,x,y,z]
    tracks = []; unit_ok = True; nrot = 0; ntrn = 0
    for i in range(bc):
        r = A['rot'].get(i); t = A['trn'].get(i)
        if not r and not t:
            continue
        e = {'i': i, 'bone': names[i] if i < len(names) else f'bone_{i}'}
        if r:
            e['rot'] = [[fr, round(q[0],5), round(q[1],5), round(q[2],5), round(q[3],5)] for fr, q in r]
            nrot += 1
            for _, q in r:
                if not (0.96 < math.sqrt(q[0]*q[0]+q[1]*q[1]+q[2]*q[2]+q[3]*q[3]) < 1.04): unit_ok = False
        if t:
            e['trn'] = [[fr, round(v[0],4), round(v[1],4), round(v[2],4)] for fr, v in t]
            ntrn += 1
        tracks.append(e)
    parts = {_PARTTYPE_NAMES[k]: int(A['boneCounts'][k]) for k in range(9) if A['boneCounts'][k]}
    # candidate target models to pose with this animation (bone-name-hash overlap, best-first)
    try:
        cand = _link_models(ff, A['boneNameHashes'], name)
    except Exception:
        cand = []
    # auto-pose only on a strong match (most of the model's bones driven, and a real number of them)
    default = cand[0]['offset'] if (cand and cand[0]['score'] >= 0.6 and cand[0].get('matched', 0) >= 4) else None
    base.update(decoded=True, exact=bool(A['exact']), unitQuaternions=bool(unit_ok),
                hasDelta=bool(A['hasDelta']), animatedBones=len(tracks),
                rotatedBones=nrot, translatedBones=ntrn, partCounts=parts,
                bones=names, tracks=tracks, models=cand, defaultModel=default)
    return base

def stringtable_view(ff, off):
    """Decode a T7 StringTable into a grid. Each of the rowCount*columnCount StringTableCells (16 B: {string*@0,
    u32 hash@8, pad}) has a string that is INLINE (-1: read in row-major order from name_end + rows*cols*16),
    NULL (0: empty), or a POOLED reference to a shared string, which is resolved through its stored DJB2 hash.
    Cells whose hash matches more than one string are marked as a best guess."""
    d = _pay(ff); X = off
    cols = _u(d, X+8, 4); rows = _u(d, X+0xC, 4)
    e = d.index(b'\x00', X+0x20); nm = d[X+0x20:e].decode('latin1', 'replace')
    p = e + 1; ncells = rows*cols; cur = [p + ncells*16]
    hidx, coll = _str_hash_index(ff)                        # {hash:(str,clean)} + genuine-collision hashes
    stats = {'inline': 0, 'resolved': 0, 'ambiguous': 0, 'unresolved': 0}
    def rd(o):
        sp = _u(d, o, 8)
        if sp == F:                                         # inline (-1): the mod-authored value
            k = d.index(b'\x00', cur[0]); s = d[cur[0]:k]; cur[0] = k + 1
            stats['inline'] += 1; return s.decode('latin1', 'replace')
        if sp == 0: return ''
        h = _u(d, o+8, 4); v = hidx.get(h)                  # pooled: resolve the shared string by its stored hash
        if v is None: stats['unresolved'] += 1; return '«%08x»' % h
        s = v[0].decode('latin1', 'replace')
        if h in coll: stats['ambiguous'] += 1; return '⚙' + s   # gear = hash-collision best guess
        stats['resolved'] += 1; return s
    grid = [[rd(p + (r*cols + c)*16) for c in range(cols)] for r in range(rows)]
    return {'name': nm, 'cols': int(cols), 'rows': int(rows),
            'inlineCount': stats['inline'], 'resolvedCount': stats['resolved'],
            'ambiguousCount': stats['ambiguous'], 'unresolvedCount': stats['unresolved'], 'grid': grid}
def rawfile_view(ff, off):
    """View any rawfile. HKS Lua (\\x1bLuaQ) -> the full Lua analysis; anything else (.atr/.cfg/.txt/...) ->
    its text (or a hex dump for binary), so non-Lua rawfiles don't get forced through the Lua decoder."""
    d = _pay(ff); ln = _u(d, off+8, 4); nm = _vn(d, off+0x18) or ''
    p = d.index(b'\x00', off+0x18)+1
    buf = d[p:p+ln]
    if buf[:5] == b'\x1bLuaQ':
        return lua_view(ff, off)
    # non-Lua rawfile: decode as text when it's printable, else a hex dump
    printable = sum(1 for b in buf[:4096] if 9 <= b < 127 or b in (10, 13))
    ext = nm.rsplit('.', 1)[-1].lower() if '.' in nm else ''
    if buf and printable / max(1, min(len(buf), 4096)) > 0.85:
        return {'kind': 'text', 'name': nm, 'ext': ext, 'length': ln,
                'text': buf.decode('latin1', 'replace')}
    hexlines = []
    for i in range(0, min(len(buf), 8192), 16):
        chunk = buf[i:i+16]
        hexlines.append(f"{i:08x}  " + ' '.join(f'{b:02x}' for b in chunk).ljust(48) +
                        '  ' + ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk))
    return {'kind': 'hex', 'name': nm, 'ext': ext, 'length': ln,
            'text': '\n'.join(hexlines) + ('' if len(buf) <= 8192 else f'\n... ({ln} bytes total)')}

def lua_view(ff, off):
    d = _pay(ff); ln = _u(d, off+8, 4); p = d.index(b'\x00', off+0x18)+1
    buf = d[p:p+ln]
    if buf[:5] != b'\x1bLuaQ':                                # non-Lua rawfile routed here -> text/hex, no crash
        return rawfile_view(ff, off)
    r = hks_disasm.analyze(buf)
    # attach reconstructed pseudo-Lua source to each proto-tree function (by index)
    try:
        src = hks_decompile.decompile_all(buf)
        by_idx = {f['index']: f.get('source') for f in src.get('functions', [])}
        for f in r.get('proto_tree', {}).get('functions', []):
            if f['index'] in by_idx:
                f['source'] = by_idx[f['index']]
    except Exception as e:
        r['source_error'] = str(e)
    try:
        r['reserialize_ok'] = hks_reserialize.round_trip_ok(buf)   # bytecode-level edits are re-serializable
    except Exception:
        r['reserialize_ok'] = False
    r['recompile_available'] = hks_compile.find_hksc() is not None  # source-level recompile (hksc) present?
    return r


def lua_build(ff, off, source, out_path, hksc_path=None):
    """Recompile HKS Lua SOURCE and splice it into the ff rawfile at `off`, producing a drop-in ff at out_path.
    Length changes go through grow_engine; the result is re-read and nothing is written on any mismatch.
    Returns splice stats."""
    import grow_engine
    d = _pay(ff); ln = _u(d, off+8, 4); nm = _vn(d, off+0x18) or 'lua'
    p = d.index(b'\x00', off+0x18) + 1
    res = hks_compile.compile_source(source, hksc_path=hksc_path, strip=True)
    if not res.get('ok') or not res.get('buffer'):
        raise RuntimeError('Lua compile failed: ' + (res.get('stderr') or res.get('error') or 'unknown'))
    newbuf = res['buffer']
    raw = open(ff, 'rb').read()
    comp, stats = grow_engine.grow_region(raw, p, ln, off+8, newbuf)
    p2, _h = ffbo3.decompress(comp)
    pp = p2.index(b'\x00', off+0x18) + 1                          # re-read the Lua at the same struct offset
    if p2[pp:pp+len(newbuf)] != newbuf:
        raise RuntimeError('Write check failed. Nothing was written.')
    open(out_path, 'wb').write(comp)
    return {'out_path': out_path, 'name': nm, 'orig_len': int(ln), 'new_len': len(newbuf), **stats}


# --- generic inspector for any located asset (kvp, and a fallback for types without a dedicated viewer) and
# the per-asset exporter. ---
def struct_view(ff, off):
    """Generic struct inspector for any located asset. Returns the readable strings inside the asset's region, the
    inline(-1)/block-ref pointer slots in its header, and a bounded hex dump — so no asset is a dead end."""
    import bisect
    d = _pay(ff)
    name = _vn(d, off+0x18) or _vn(d, off+0xF8) or _vn(d, off+0x108) or ''
    offs = sorted(set(a['offset'] for a in inventory(ff)['assets']))
    i = bisect.bisect_right(offs, off)
    end = min(offs[i] if i < len(offs) else off + 0x400, off + 0x1000, len(d))
    region = d[off:end]
    strings = []; cur = []; start = 0
    for k, b in enumerate(region):
        if 32 <= b < 127:
            if not cur: start = k
            cur.append(chr(b))
        else:
            if len(cur) >= 4: strings.append({'off': start, 'text': ''.join(cur)})
            cur = []
    if len(cur) >= 4: strings.append({'off': start, 'text': ''.join(cur)})
    ptrs = []
    for k in range(0, min(len(region) - 8, 0x100), 8):
        v = _u(d, off + k, 8)
        if v == F: ptrs.append({'off': k, 'kind': 'inline (-1)'})
        elif v != 0 and (v >> 60) == 5: ptrs.append({'off': k, 'kind': 'block ref'})
    hexlines = []
    for k in range(0, min(len(region), 0x400), 16):
        c = region[k:k+16]
        hexlines.append('%04x  %-47s  %s' % (k, ' '.join('%02x' % b for b in c),
                        ''.join(chr(b) if 32 <= b < 127 else '.' for b in c)))
    return {'kind': 'struct', 'name': name, 'offset': int(off), 'regionLen': len(region),
            'strings': strings[:80], 'pointers': ptrs[:48], 'hex': '\n'.join(hexlines)}

def _obj_from_mesh(P, tri, name):
    """Wavefront OBJ text from raw positions + triangle indices."""
    out = ['# FF Studio export: %s' % name, 'o %s' % (name.replace('/', '_') or 'mesh')]
    out += ['v %.6f %.6f %.6f' % (float(p[0]), float(p[1]), float(p[2])) for p in P]
    out += ['f %d %d %d' % (int(a)+1, int(b)+1, int(c)+1) for a, b, c in tri]
    return ('\n'.join(out) + '\n').encode('utf-8')

def export_asset(ff, off, atype):
    """Return (filename, content_type, bytes) for an asset download. Images -> PNG, fonts -> TTF,
    meshes/models -> Wavefront OBJ, fx -> .efx, rawfiles/scripts -> raw bytes. Raises for other types."""
    d = _pay(ff)
    if atype == 'image':
        nm = _vn(d, off+0x108) or 'image'
        png, _meta = image_png(ff, off)                      # image_png returns (png_bytes, meta)
        return nm.replace('/', '_') + '.png', 'image/png', png
    if atype == 'ttf':
        r = _ttf_at(d, off)
        if not r: raise RuntimeError('no TrueType at this offset')
        nm = _name_before(d, off) or r['family'] or 'font'
        nm = _re.sub(r'\.ttf$', '', nm)                      # avoid a double .ttf extension
        return nm.replace('/', '_') + '.ttf', 'font/ttf', bytes(d[off:off+r['len']])
    if atype == 'xmodelmesh':
        mi, raw, P, tri, ns = _best_mesh(ff, off)
        nm = _is_mesh(d, off) or 'mesh'
        return nm.replace('/', '_') + '.obj', 'text/plain', _obj_from_mesh(P, tri, nm)
    if atype == 'xmodel':
        name = _is_xmodel(d, off) or 'model'
        inv = inventory(ff)
        meshes = sorted((a for a in inv['assets'] if a['type'] == 'xmodelmesh'), key=lambda a: a['offset'])
        for m in [x for x in meshes if _strip_hash(x['name']).startswith(name)]:
            try:
                mi, raw, P, tri, ns = _best_mesh(ff, m['offset'])
                return name.replace('/', '_') + '.obj', 'text/plain', _obj_from_mesh(P, tri, name)
            except Exception: continue
        raise RuntimeError('No mesh linked to this model.')
    if atype == 'fx':
        r = fx_view(ff, off)
        return (r.get('name', 'fx').replace('/', '_') + '.efx', 'text/plain',
                (r.get('efx') or _json_dump(r)).encode('utf-8'))
    if atype in ('rawfile', 'script'):
        ln = _u(d, off+8, 4); nm = _vn(d, off+0x18) or 'rawfile'
        p = d.index(b'\x00', off+0x18) + 1
        return nm.replace('/', '_'), 'application/octet-stream', bytes(d[p:p+ln])
    raise RuntimeError('no exporter for type %r' % atype)

def _json_dump(o):
    import json; return json.dumps(o, indent=1)
