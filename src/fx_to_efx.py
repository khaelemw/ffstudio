"""FX decompiler: compiled FxEffectDef -> .efx source text (Treyarch FX editor format, `iwfx 3`).

Angles are stored in radians (.efx uses degrees) and angular velocity in radians/msec (.efx uses deg/sec).
Emits each element's scalar parameters plus its sampled curves (color, alpha, size, rotation, and velocity when
present) from fx_curves. The compiled asset stores baked sample tables, not the editor's control points, so
curves are written as *_sampled values. Curves that aren't stored inline are marked "not recovered".
"""
import struct, math
F = 0xFFFFFFFFFFFFFFFF
S = 0x260
def _u(d, o, n): return int.from_bytes(d[o:o+n], 'little')
def _f(d, o): return struct.unpack('<f', d[o:o+4])[0]
def _cstr(d, o, mx=128):
    e = o
    while e < len(d) and 32 <= d[e] < 127 and e-o < mx: e += 1
    return d[o:e].decode('latin1') if (e < len(d) and d[e] == 0) else ''
def _deg(x): return round(math.degrees(x), 4)
def _r2(a, b): return f"{round(a,4)} {round(b,4)}"   # base range

# FxElemDef scalar field map (offset -> (efx_name, kind)); kind: 'msec2','flt2','deg2','degvel2','deg1','flt1'
_ELEM_FIELDS = [
    (0x08, 'spawnOneShot', 'int2'),
    (0x18, 'spawnRange', 'flt2'),
    (0x30, 'spawnFrustumCullRadius', 'flt1'),
    (0x34, 'spawnDelayMsec', 'msec2'),
    (0x3C, 'lifeSpanMsec', 'msec2'),
    (0x60, 'spawnOffsetRadius', 'flt2'),
    (0x70, 'spawnAnglePitch', 'deg2'),
    (0x78, 'spawnAngleYaw', 'deg2'),
    (0x80, 'spawnAngleRoll', 'deg2'),
    (0x88, 'angleVelPitch', 'degvel2'),
    (0x90, 'angleVelYaw', 'degvel2'),
    (0x98, 'angleVelRoll', 'degvel2'),
    (0xA0, 'initialRot', 'deg2'),
    (0xB4, 'elasticity', 'flt2'),
]

def _curve_lines(cv):
    """Emit one element's sampled curves (baked sample tables, not editor control points).
    Times are normalized 0..1 over the element's life."""
    out = []
    vis = cv.get('visSamples')
    if vis:
        n = len(vis); dt = 1.0/(n-1) if n > 1 else 0
        out.append(f'\t// --- recovered sampled curves ({cv.get("order","?")}); {n} vis frames ---')
        # colorGraph: t r g b   (0..1)
        out.append('\tcolorGraph_sampled {')
        for i, s in enumerate(vis):
            r, g, b, a = s['color']
            out.append(f'\t\t{round(i*dt,4)} {round(r/255,4)} {round(g/255,4)} {round(b/255,4)}')
        out.append('\t};')
        out.append('\talphaGraph_sampled {')
        for i, s in enumerate(vis):
            out.append(f'\t\t{round(i*dt,4)} {round(s["color"][3]/255,4)}')
        out.append('\t};')
        out.append('\tsizeGraph_sampled {   // t  sizeX  sizeY')
        for i, s in enumerate(vis):
            out.append(f'\t\t{round(i*dt,4)} {s["size"][0]} {s["size"][1]}')
        out.append('\t};')
        if any(s['rotTotal'] or s['rotDelta'] for s in vis):
            out.append('\trotGraph_sampled {   // t  rotTotal  rotDelta')
            for i, s in enumerate(vis):
                out.append(f'\t\t{round(i*dt,4)} {s["rotTotal"]} {s["rotDelta"]}')
            out.append('\t};')
    vel = cv.get('velSamples')
    if vel:
        n = len(vel); dt = 1.0/(n-1) if n > 1 else 0
        out.append('\tvelGraph_sampled {   // t  localVel(xyz)  worldVel(xyz)')
        for i, s in enumerate(vel):
            lv = s['local']['velocity']; wv = s['world']['velocity']
            out.append(f'\t\t{round(i*dt,4)}  {lv[0]} {lv[1]} {lv[2]}  {wv[0]} {wv[1]} {wv[2]}')
        out.append('\t};')
    if not out:
        why = cv.get('note') or ('shared block5 default table (outside this asset)'
              if str(cv.get('velPtr','')).startswith('ref') or str(cv.get('visPtr','')).startswith('ref')
              else 'not stored inline')
        out.append(f'\t// sampled curves: not recovered for this element ({why})')
    return out

def _elem_efx(d, e, curve=None):
    out = ['{', f'\tflags {_u(d,e,4):#010x};']
    ct = list(d[e+0xC8:e+0xD0])
    out.append(f'\tcounts {ct};   // elemType/visualCount/velInterval/?/?/visInterval')
    for off, name, kind in _ELEM_FIELDS:
        a, b = _f(d, e+off), _f(d, e+off+4); ia, ib = _u(d, e+off, 4), _u(d, e+off+4, 4)
        if kind == 'int2':   out.append(f'\t{name} {ia} {ib};')
        elif kind == 'flt2': out.append(f'\t{name} {_r2(a,b)};')
        elif kind == 'flt1': out.append(f'\t{name} {round(a,4)};')
        elif kind == 'msec2':out.append(f'\t{name} {ia} {ib};')
        elif kind == 'deg2': out.append(f'\t{name} {_deg(a)} {_deg(b)};')
        elif kind == 'degvel2': out.append(f'\t{name} {round(math.degrees(a)*1000,2)} {round(math.degrees(b)*1000,2)};')
    if curve is not None:
        out += _curve_lines(curve)
    else:
        out.append('\t// sampled curves: element data not bounded')
    out.append('};')
    return '\n'.join(out)

def to_efx(d, P, end=None):
    import fx_curves
    name = _cstr(d, P+0x90); nend = P+0x90+len(name)+1
    ec = _u(d, P+0xC, 2) + _u(d, P+0xE, 2)
    bb = [round(_f(d, P+0x28+4*j), 3) for j in range(3)]
    cv = fx_curves.curves(d, P, end)['elements'] if end else [None]*ec
    lines = ['iwfx 3', '', f'\t// name {name}', f'\tefBoundingBoxDim {bb[0]} {bb[1]} {bb[2]};',
             f'\tmsecLoopingLife {_u(d,P+0x18,4)};', f'\t// {ec} elements']
    for i in range(ec):
        lines.append(_elem_efx(d, nend + i*S, cv[i] if i < len(cv) else None))
    return '\n'.join(lines)
