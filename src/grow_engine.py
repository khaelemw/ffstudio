"""Grows a script (or other data region) inside a closed BO3 fastfile and writes a loadable ff.

Given the original ff, a scriptparsetree name and a new GSC object that may be larger than the original:
  * derives G, the script's block-5 end offset (handles both a trailing and a scattered block 5), and checks
    the choice by requiring that nothing points into the script's own range;
  * finds every block-5 pointer at or past G (value scan with data-blob masks for DXBC, GSC, mesh vertex data
    and the large block-6 region, plus the mesh walker's recorded pointers);
  * pads the new object so the size change is a multiple of 64, fixes the GSC size fields, splices it in,
    shifts the affected pointers and updates the length, header size and blockSize[5];
  * recompresses and re-reads the result to check it before returning.
"""
import os, struct
import numpy as np
import ffbo3
import ff_deserialize as fd
from reserializer import Rec, walk_xmodelmesh

MAGIC = ffbo3.MAGIC  # T7GSCOBJ magic
F = 0xFFFFFFFFFFFFFFFF
_HERE = os.path.dirname(os.path.abspath(__file__))


def _fwalk_ns(pay):
    g = {'__name__': 'nm'}
    exec(compile(open(os.path.join(_HERE, 'fwalk.py')).read(), 'fwalk.py', 'exec'), g)
    g['pay'] = pay; g['N'] = len(pay)
    return g


def analyze(pay, h):
    """Structure scan: meshes_end (end of the leading mesh run), STRUCT (first scriptparsetree), and the
    walker's mesh pointer/vertex-blob records (rec.ptrs / b6) from ALL meshes in the payload."""
    N = len(pay)
    g = _fwalk_ns(pay); is_mesh = g['is_mesh']; is_scr = g['is_scr']
    try: o = fd.parse_xassetlist(pay)[2]
    except Exception: o = 0
    # leading contiguous mesh run
    rec = Rec(); b6 = []
    cur = o; nlead = 0
    while cur < N - 0x10 and is_mesh(cur):
        try:
            nxt = walk_xmodelmesh(pay, cur, rec, b6=b6)
        except Exception:
            break
        if nxt is None or nxt <= cur: break
        cur = nxt; nlead += 1
    meshes_end = cur
    # STRUCT = first scriptparsetree at/after meshes_end (skips the block6 GIANT if present)
    STRUCT = None; q = meshes_end
    while q < N:
        dd = pay.find(b'\xff' * 8, q)
        if dd < 0: break
        if is_scr(dd): STRUCT = dd; break
        q = dd + 1
    if STRUCT is None: STRUCT = meshes_end
    # ALL meshes anywhere (for the full vertex-blob mask + mesh block5 pointers)
    reca = Rec(); b6a = []; q = 0
    while True:
        d = pay.find(b'\xff' * 8, q)
        if d < 0: break
        if is_mesh(d):
            try: walk_xmodelmesh(pay, d, reca, b6=b6a)
            except Exception: pass
        q = d + 1
    return dict(meshes_end=meshes_end, STRUCT=STRUCT, nlead=nlead, rec=reca, b6=b6a, is_mesh=is_mesh)


def _all_targets(pay, bs5):
    """Every (5<<60)|off (off<bs5) target-offset present in the payload (for the no-incoming-ptr validation)."""
    N = len(pay); bb = np.frombuffer(pay, np.uint8); v = np.zeros(N - 8, np.uint64)
    for i in range(8): v |= bb[i:i + (N - 8)].astype(np.uint64) << np.uint64(8 * i)
    top = v >> np.uint64(60); low = v & np.uint64(0x0FFFFFFFFFFFFFFF)
    idx = np.flatnonzero((top == np.uint64(5)) & (low < np.uint64(bs5)))
    return low, top, np.unique(low[idx].astype(np.int64))


def derive_g(pay, h, info, meshes_end, STRUCT, verbose=False):
    """Return (G, B5_START, method). Tries B5_START = N-bs5 (trailing block5) and mesh-anchor bases
    (scattered block5); picks the candidate whose script block5 range [G-oldlen, G) contains NO incoming
    pointer target (scripts are never pointed into) and 0<G<bs5."""
    N = len(pay); bs5 = h['blockSize'][5]; u = lambda p, n: int.from_bytes(pay[p:p + n], 'little')
    INS = info['bc_off'] + info['oldlen']; oldlen = info['oldlen']
    _, _, targets = _all_targets(pay, bs5)

    def cstr(p): return pay.index(b'\x00', p) + 1
    g = _fwalk_ns(pay); is_mesh = g['is_mesh']
    anchors = []; q = 0
    while True:
        d = pay.find(b'\xff' * 8, q)
        if d < 0: break
        if is_mesh(d):
            X = d; ns = pay[X + 0x3C]; np_ = u(X, 8); spp = u(X + 0x68, 8); shp = u(X + 0x70, 8); p = X + 0x78
            if np_ == F: p = cstr(p)
            if shp == F:
                sp = p; fl = u(p, 4); dp = u(p + 0x10, 8); dsz = u(p + 0x18, 4); p2 = p + 0x50
                if dp == F and (fl & 1) == 0: p2 += dsz
                if spp == F and ns > 0:
                    shref = u(p2 + 0x10, 8)
                    if (shref >> 60) == 5: anchors.append((sp, shref & 0x0FFFFFFFFFFFFFFF))
        q = d + 1
    cands = [('N-bs5', N - bs5)]
    for sp, off in anchors:
        if sp >= STRUCT: cands.append(('mesh-anchor', sp - off))
    seen = set(); valid = []
    for method, base in cands:
        if base in seen: continue
        seen.add(base)
        G = INS - base
        if not (0 < G < bs5): continue
        lo = G - oldlen
        # script must have no incoming block5 targets in its own range [lo, G)
        inrange = int(((targets >= lo) & (targets < G)).sum())
        valid.append((inrange, method, base, G))
    valid.sort()  # fewest in-range targets first
    if not valid:
        raise RuntimeError("derive_g: no valid B5_START candidate (0<G<bs5)")
    inrange, method, base, G = valid[0]
    if verbose:
        print(f"  derive_g: method={method} B5_START={base:#x} G={G:#x} (script-range incoming targets={inrange})")
        if len(valid) > 1:
            print("            (candidates: " + ", ".join(f"{m}:G={g_:#x}/in={ir}" for ir, m, b, g_ in valid) + ")")
    if inrange != 0:
        print(f"  WARNING: derived G has {inrange} pointer target(s) inside the script's own block5 range — "
              f"G derivation may be wrong for this ff; review before installing.")
    return G, base, method


def build_patch_positions(pay, h, G, STRUCT, an):
    """>=G pointer positions: value-scan (5<<60)|off in [G,bs5), masked (DXBC/GSC-magic/mesh-vert/GIANT),
    pos>=STRUCT, UNION the walker's mesh block5 pointers (all positions)."""
    N = len(pay); bs5 = h['blockSize'][5]; u = lambda p, n: int.from_bytes(pay[p:p + n], 'little')
    masked = np.zeros(N, bool)
    pos = 0
    while True:
        d = pay.find(b'DXBC', pos)
        if d < 0: break
        sz = u(d + 0x18, 4)
        if 0x20 <= sz <= 0x400000: masked[d:d + sz] = True
        pos = d + 4
    q = 0
    while True:
        m = pay.find(MAGIC, q)
        if m < 0: break
        sz = u(m + 0x1C, 4); sz = sz if 0 < sz < 0x100000 else 0x20000
        masked[m:m + sz] = True; q = m + 8
    for a, b in an['b6']:
        if 0 <= a < b <= N: masked[a:b] = True
    if an['STRUCT'] > an['meshes_end']:
        masked[an['meshes_end']:an['STRUCT']] = True  # block6 GIANT
    bb = np.frombuffer(pay, np.uint8); v = np.zeros(N - 8, np.uint64)
    for i in range(8): v |= bb[i:i + (N - 8)].astype(np.uint64) << np.uint64(8 * i)
    top = v >> np.uint64(60); low = v & np.uint64(0x0FFFFFFFFFFFFFFF)
    cand = np.flatnonzero((top == np.uint64(5)) & (low >= np.uint64(G)) & (low < np.uint64(bs5)))
    cand = cand[~masked[cand]]; cand = cand[cand >= STRUCT]
    mesh_pos = {pp for (pp, blk, oo) in an['rec'].ptrs if blk == 5 and G <= oo < bs5}
    return sorted(set(int(p) for p in cand) | mesh_pos)


def grow_region(pristine_raw, bc_off, oldlen, len_off, new_obj, align=64, verbose=False):
    """Grow an arbitrary opaque data region [bc_off, bc_off+oldlen) (e.g. a recompiled HKS Lua rawfile buffer) to
    new_obj bytes inside the original ff. Uses the same block-5 machinery (derive_g / build_patch_positions)
    but applies NO GSC-specific size fixups — the region is opaque and HKS bytecode is self-delimiting, so trailing
    alignment pad is ignored by the loader. len_off is set to the padded physical length (stream stays in sync).
    Full round-trip self-validation; raises on any mismatch (never writes a corrupt ff)."""
    pay, h = ffbo3.decompress(pristine_raw); bs5 = h['blockSize'][5]
    u = lambda p, n: int.from_bytes(pay[p:p + n], 'little')
    INS = bc_off + oldlen
    NEWBC = bytearray(new_obj); obj_len = len(NEWBC); raw_delta = obj_len - oldlen
    info = {'bc_off': bc_off, 'oldlen': oldlen, 'len_off': len_off}
    if raw_delta <= 0:
        DELTA = 0; NEWBC += b'\x00' * (oldlen - obj_len)          # pad back to oldlen (dead space, no reflow)
        patch = []; G = B5_START = method = None
    else:
        an = analyze(pay, h)
        G, B5_START, method = derive_g(pay, h, info, an['meshes_end'], an['STRUCT'], verbose)
        patch = build_patch_positions(pay, h, G, an['STRUCT'], an)
        DELTA = (raw_delta + (align - 1)) & ~(align - 1); NEWBC += b'\x00' * (DELTA - raw_delta)
    newpay = bytearray(pay[:bc_off] + bytes(NEWBC) + pay[INS:])
    hdr = bytearray(pristine_raw[:ffbo3.HEADER_SIZE])
    struct.pack_into('<I', newpay, len_off, len(NEWBC))          # len = padded physical size (loader stays in sync)
    struct.pack_into('<Q', hdr, 0x90, struct.unpack_from('<Q', hdr, 0x90)[0] + DELTA)
    b5o = 0xA8 + 5 * 8; struct.pack_into('<Q', hdr, b5o, struct.unpack_from('<Q', hdr, b5o)[0] + DELTA)
    for p in patch:
        off = u(p, 8) & 0x0FFFFFFFFFFFFFFF; npp = p + (DELTA if p >= INS else 0)
        struct.pack_into('<Q', newpay, npp, (5 << 60) | (off + DELTA))
    comp, nb, nm = ffbo3.recompress(bytes(newpay), bytes(hdr))
    p2, h2 = ffbo3.decompress(comp)                              # self-validation
    if p2 != bytes(newpay): raise RuntimeError("container round-trip mismatch — refusing to write")
    if h2['blockSize'][5] != bs5 + DELTA: raise RuntimeError("blockSize[5] mismatch")
    for p in patch:
        off = u(p, 8) & 0x0FFFFFFFFFFFFFFF; npp = p + (DELTA if p >= INS else 0)
        if struct.unpack_from('<Q', p2, npp)[0] != ((5 << 60) | (off + DELTA)):
            raise RuntimeError(f"patched pointer verify failed @ {p:#x}")
    return comp, dict(oldlen=oldlen, newlen=len(NEWBC), delta=DELTA, patched=len(patch),
                      out_size=len(comp), bs5=bs5, new_bs5=h2['blockSize'][5])

def grow_patch(pristine_raw, script_name, new_obj, align=64, verbose=False):
    """Grow `script_name` to `new_obj` (bytes, must be >= original) inside the pristine ff bytes.
    Returns (out_ff_bytes, stats). Raises on any validation failure."""
    if isinstance(script_name, str): script_name = script_name.encode()
    pay, h = ffbo3.decompress(pristine_raw); bs5 = h['blockSize'][5]
    u = lambda p, n: int.from_bytes(pay[p:p + n], 'little')
    info = ffbo3.find_script(pay, script_name)
    if info is None: raise RuntimeError(f"script not found: {script_name!r}")
    bc_off, oldlen, len_off = info['bc_off'], info['oldlen'], info['len_off']
    INS = bc_off + oldlen
    if verbose: print(f"grow_patch: {script_name.decode()} bc_off={bc_off:#x} oldlen={oldlen} INS={INS:#x} bs5={bs5:#x}")
    NEWBC = bytearray(new_obj); obj_len = len(NEWBC)
    raw_delta = obj_len - oldlen
    if raw_delta <= 0:
        # DELTA-0 splice: the edit is same-size or smaller — pad the new object back up to the original size
        # (trailing zero pad is harmless in a GSC buffer) so nothing downstream shifts. No pointer patch needed.
        DELTA = 0; padn = oldlen - obj_len; NEWBC += b'\x00' * padn
        if padn: ffbo3._fix_gsc_size_fields(NEWBC, 0, obj_len, padn)
        patch = []; G = B5_START = method = None
        if verbose: print(f"  DELTA-0 splice: obj={obj_len} padded to {oldlen} (edit fits in place, no reflow)")
    else:
        an = analyze(pay, h)
        G, B5_START, method = derive_g(pay, h, info, an['meshes_end'], an['STRUCT'], verbose)
        patch = build_patch_positions(pay, h, G, an['STRUCT'], an)
        if verbose: print(f"  patch set: {len(patch)} block5 pointers >=G")
        DELTA = (raw_delta + (align - 1)) & ~(align - 1)
        padn = DELTA - raw_delta; NEWBC += b'\x00' * padn
        if padn: ffbo3._fix_gsc_size_fields(NEWBC, 0, obj_len, padn)
        if verbose: print(f"  obj={obj_len} raw_delta={raw_delta} DELTA={DELTA}({DELTA:#x}, {align}-aligned) pad={padn}")
    # splice + header/len
    newpay = bytearray(pay[:bc_off] + bytes(NEWBC) + pay[INS:])
    hdr = bytearray(pristine_raw[:ffbo3.HEADER_SIZE])
    struct.pack_into('<I', newpay, len_off, len(NEWBC))
    struct.pack_into('<Q', hdr, 0x90, struct.unpack_from('<Q', hdr, 0x90)[0] + DELTA)
    b5o = 0xA8 + 5 * 8; struct.pack_into('<Q', hdr, b5o, struct.unpack_from('<Q', hdr, b5o)[0] + DELTA)
    # pointer patch
    for p in patch:
        off = u(p, 8) & 0x0FFFFFFFFFFFFFFF
        npp = p + (DELTA if p >= INS else 0)
        struct.pack_into('<Q', newpay, npp, (5 << 60) | (off + DELTA))
    comp, nb, nm = ffbo3.recompress(bytes(newpay), bytes(hdr))
    # ---- self-validation ----
    p2, h2 = ffbo3.decompress(comp)
    if p2 != bytes(newpay): raise RuntimeError("container round-trip mismatch — refusing to write")
    gi = ffbo3.find_script(p2, script_name)
    if gi['oldlen'] != len(NEWBC): raise RuntimeError("spliced len mismatch")
    if h2['blockSize'][5] != bs5 + DELTA: raise RuntimeError("blockSize[5] mismatch")
    # every patched pointer must read back +DELTA
    for p in patch:
        off = u(p, 8) & 0x0FFFFFFFFFFFFFFF; npp = p + (DELTA if p >= INS else 0)
        if struct.unpack_from('<Q', p2, npp)[0] != ((5 << 60) | (off + DELTA)):
            raise RuntimeError(f"patched pointer verify failed @ {p:#x}")
    stats = dict(script=script_name.decode(), G=G, B5_START=B5_START, method=method, INS=INS,
                 oldlen=oldlen, newlen=len(NEWBC), delta=DELTA, patched=len(patch),
                 blocks=nb, markers=nm, out_size=len(comp), bs5=bs5, new_bs5=h2['blockSize'][5])
    if verbose: print(f"  OK: len {oldlen}->{len(NEWBC)} (+{DELTA}), {len(patch)} ptrs patched, "
                      f"bs5 {bs5:#x}->{h2['blockSize'][5]:#x}, ff {len(comp):,} B, round-trip verified")
    return comp, stats
