"""FX (FxEffectDef, asset type 0x26) decoder: the effect header and per-element fields as a dict for the viewer.

FxEffectDef header is 0x90 bytes, each FxElemDef is 0x260 bytes, element count = u16@0xC + u16@0xE.
Per-element sample arrays are reported as {pointer kind, offset}, not expanded.
"""
import struct

F = 0xFFFFFFFFFFFFFFFF
ELEM_SIZE = 0x260
HDR = 0x90

def _u(d, o, n): return int.from_bytes(d[o:o+n], 'little')
def _f(d, o):
    try: return round(struct.unpack('<f', d[o:o+4])[0], 5)
    except Exception: return None
def _cstr(d, o, mx=128):
    e = o
    while e < len(d) and 32 <= d[e] < 127 and e-o < mx: e += 1
    return d[o:e].decode('latin1') if (e < len(d) and d[e] == 0) else None

def is_fx(d, P):
    N = len(d)
    if P < 0 or P+0xC0 >= N or _u(d, P, 8) != F: return None
    if any(_u(d, P+8+2*i, 2) >= 4000 for i in range(4)): return None
    if sum(_u(d, P+8+2*i, 2) for i in range(4)) == 0: return None
    if _u(d, P+0x20, 8) != F: return None
    if not all(_f(d, P+0x28+4*j) and 0.01 <= abs(_f(d, P+0x28+4*j)) <= 1e5 for j in range(3)): return None
    nm = _cstr(d, P+HDR)
    return nm if (nm and ('fx' in nm or '/' in nm)) else None

def decode_elem(d, e):
    """Decode one FxElemDef (0x260) into named-ish fields. Pointer slots at +0xD8/0xE8/0xF0/0x130."""
    ptr = lambda o: ('inline' if _u(d, e+o, 8) == F else ('null' if _u(d, e+o, 8) == 0 else f"block{_u(d,e+o,8)>>60}:{_u(d,e+o,8)&0x0FFFFFFFFFFFFFFF:#x}"))
    return {
        'flags': f"{_u(d, e+0, 4):#010x}",
        'spawn_range':  [_f(d, e+0x70), _f(d, e+0x74), _f(d, e+0x78)],
        'angle_ranges': [_f(d, e+0x7c), _f(d, e+0x80), _f(d, e+0x84)],
        'count_bytes':  list(d[e+0xC8:e+0xD0]),   # elemType/visualCount/vel&vis interval counts
        'ptr_velSamples@0xD8': ptr(0xD8),
        'ptr_visSamples@0xE8': ptr(0xE8),
        'ptr@0xF0':            ptr(0xF0),
        'ptr_visuals@0x130':   ptr(0x130),
    }

def decode(d, P, end=None):
    """Decode an fx at offset P. `end` (next asset) bounds the sample data; if None, only the fixed part."""
    name = _cstr(d, P+HDR)
    nend = P + HDR + (len(name)+1 if name else 0)
    elemCount = _u(d, P+0xC, 2) + _u(d, P+0xE, 2)
    out = {
        'type': 'fx (FxEffectDef)', 'name': name, 'offset': f"{P:#x}",
        'elemCount': elemCount, 'totalSize_field': _u(d, P+0x14, 4),
        'msecLoopingLife': _u(d, P+0x18, 4),
        'boundingBox': [_f(d, P+0x28), _f(d, P+0x2c), _f(d, P+0x30)],
        'header_flags': f"{_u(d, P+8, 4):#010x}",
        'elemArray_bytes': elemCount*ELEM_SIZE,
        'elements': [decode_elem(d, nend + i*ELEM_SIZE) for i in range(elemCount)],
    }
    if end is not None:
        out['sampleData_bytes'] = end - (nend + elemCount*ELEM_SIZE)
    return out
