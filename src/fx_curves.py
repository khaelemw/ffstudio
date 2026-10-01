"""FX sample-table decoder: the sampled curves of a compiled FxEffectDef.

The .efx editor stores control-point curves (velGraph/colorGraph/sizeGraph/alphaGraph...). The linker bakes them
into fixed-interval sample tables and only the tables are stored, so this module recovers the sampled values,
not the editor's control points.

  FxElemDef.count bytes @0xC8:  [elemType, visualCount, velIntervalCount, ?, ?, visStateIntervalCount, 0, 0]
      velSampleCount = velIntervalCount + 1        (= count byte [2] + 1)
      visSampleCount = visStateIntervalCount + 1   (= count byte [5] + 1)

  FxElemVelStateSample  = 0x60 (two FxElemVelStateInFrame: local + world; each 0x30)
  FxElemVisStateSample  = 0x50 (two FxElemVisStateInFrame: base + amplitude; each 0x28)
  FxElemVisStateInFrame = 0x28:
      +0x00 uint8 color[4]  (R,G,B,A)   R,G,B = colorGraph, A = alphaGraph  (0..255)
      +0x04 float rotationDelta
      +0x08 float rotationTotal
      +0x0C float size[0]   (width)
      +0x10 float size[1]   (length/height)
      +0x14..+0x24 five floats (scale/child-scale group; usually 0,1,0,0,1)

Layout after the element array: inline arrays in element order, and within an element in field-offset order
[velSamples@0xD8, visSamples@0xE8, visuals@0xF0, markVisuals@0x130]. An array is stored inline only when its
pointer slot is -1; any other value refers to a shared default table outside this fx, which isn't present here.
`curves()` walks the inline stream, decoding each inline vel/vis table (velN*0x60 / visN*0x50 bytes), and stops at
the first inline visuals/markVisuals block, which is variable-size. Shared curves and curves after that point
are reported as not recovered.
"""
import struct

VEL = 0x60
VIS = 0x50

def _u(d, o, n): return int.from_bytes(d[o:o+n], 'little')
def _f(d, o):
    try: return struct.unpack('<f', d[o:o+4])[0]
    except Exception: return float('nan')
def _finite(x): return x == x and abs(x) < 1e12   # not NaN/inf and sane magnitude

def _visframe(d, o):
    return {
        'color': list(d[o:o+4]),                 # R,G,B,A  0..255
        'rotDelta': round(_f(d, o+0x04), 5),
        'rotTotal': round(_f(d, o+0x08), 5),
        'size': [round(_f(d, o+0x0C), 5), round(_f(d, o+0x10), 5)],
        'extra': [round(_f(d, o+0x14+4*k), 5) for k in range(5)],
    }

def _vis_ok(d, o, n, N):
    """Do `n` visSamples plausibly start at o? (sizes finite, colors are bytes — always true, so check floats)."""
    if o + n*VIS > N: return False
    for i in range(n):
        b = o + i*VIS
        for fo in (0x04, 0x08, 0x0C, 0x10):          # base InFrame floats
            if not _finite(_f(d, b+fo)): return False
        if not (_finite(_f(d, b+0x0C)) and _f(d, b+0x0C) >= 0): return False   # size[0] >= 0
    return True

def _vel_ok(d, o, n, N):
    if o + n*VEL > N: return False
    for i in range(n):
        b = o + i*VEL
        for k in range(24):                          # 24 floats per velSample
            if not _finite(_f(d, b+4*k)): return False
    return True

def _velframe(d, o):
    # two FxElemVelStateInFrame (local, world); each = vec3 velocity + vec3 totalDelta (+pad to 0x30)
    def infr(p): return {'velocity': [round(_f(d, p+4*k), 5) for k in range(3)],
                         'totalDelta': [round(_f(d, p+0x0C+4*k), 5) for k in range(3)],
                         'rest': [round(_f(d, p+0x18+4*k), 5) for k in range(6)]}
    return {'local': infr(o), 'world': infr(o+0x30)}


F_PTR = 0xFFFFFFFFFFFFFFFF          # -1 pointer = "data follows inline in the stream"

def _ptr_status(v):
    """Classify a serialized pointer slot: inline (-1), null (0), or a block-encoded reference/shared default."""
    if v == F_PTR: return 'inline'
    if v == 0:     return 'null'
    return f'ref:b{v>>60}:{(v & 0x0FFFFFFFFFFFFFFF):#x}'   # block-encoded (shared-default or cross-ref)

def curves(d, P, end):
    """Per-element sampled curves for the fx at offset P (end = next asset's offset, bounds the region).
    See the module docstring for which curves can be recovered."""
    from fx_decode import _cstr
    HDR = 0x90; ELEM = 0x260
    name = _cstr(d, P+HDR); nend = P+HDR+(len(name)+1 if name else 0)
    ec = _u(d, P+0xC, 2) + _u(d, P+0xE, 2)
    elem_end = nend + ec*ELEM
    N = len(d); region_end = end if end else N

    elems = []
    for i in range(ec):
        e = nend + i*ELEM
        cb = list(d[e+0xC8:e+0xD0])
        elems.append({
            'index': i, 'velSampleCount': cb[2]+1, 'visSampleCount': cb[5]+1, 'visualCount': cb[1],
            'count_bytes': cb,
            'velPtr':  _ptr_status(_u(d, e+0xD8, 8)),
            'visPtr':  _ptr_status(_u(d, e+0xE8, 8)),
            'visualsPtr': _ptr_status(_u(d, e+0xF0, 8)),
            'markVisualsPtr': _ptr_status(_u(d, e+0x130, 8)),
        })

    # inline-stream walk
    o = elem_end; stop = None
    for el in elems:
        if el['velPtr'] == 'inline':
            n = el['velSampleCount']
            if _vel_ok(d, o, n, region_end):
                el['velSamples'] = [_velframe(d, o + k*VEL) for k in range(n)]
                el['velOffset'] = f'{o:#x}'; o += n*VEL
            else:
                stop = (el['index'], 'velSamples@0xD8 did not validate'); break
        if el['visPtr'] == 'inline':
            n = el['visSampleCount']
            if _vis_ok(d, o, n, region_end):
                el['visSamples'] = [_visframe(d, o + k*VIS) for k in range(n)]
                el['visOffset'] = f'{o:#x}'; o += n*VIS
            else:
                stop = (el['index'], 'visSamples@0xE8 did not validate'); break
        if el['visualsPtr'] == 'inline':
            stop = (el['index'], 'visuals@0xF0 (variable-size inline material block)'); break
        if el['markVisualsPtr'] == 'inline':
            stop = (el['index'], 'markVisuals@0x130 (variable-size inline block)'); break

    # mark elements with no recovered curves
    for el in elems:
        if 'velSamples' not in el and 'visSamples' not in el:
            if stop and el['index'] >= stop[0]:
                el['note'] = 'beyond inline-walk stop (variable-size inline visuals/material block not yet sized)'
            elif el['velPtr'].startswith('ref') or el['visPtr'].startswith('ref'):
                el['note'] = 'curves are shared/default tables (block5) stored outside this asset — not recovered here'

    walk_complete = (stop is None and o == region_end)
    out = {'name': name, 'elemCount': ec, 'elements': elems, 'inlineWalkComplete': walk_complete}
    if stop:
        out['note'] = (f'inline-curve walk stopped at element {stop[0]} ({stop[1]}). Curves before this point '
                       f'are byte-exact; later inline curves and all shared/referenced (block5) curves need the '
                       f'block5→payload relocation map / recursive inline-material sizing (not yet reversed).')
    return out
