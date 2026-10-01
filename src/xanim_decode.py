"""
T7 (Black Ops 3) XAnimParts keyframe decoder.

Decodes per-bone rotation (quaternion) and translation keyframes from an
inline XAnimParts asset inside a decompressed fastfile payload.

Format reference: Scobalula's Greyhound (CoDXAnimTranslator.cpp / GameBlackOps3.cpp)
and HydraX (XAnim.cs struct layout). BO3 stores quaternions as IEEE half-floats
and translations as a per-part Min/Size table applied to quantised byte/short keys.

Struct offsets (XAnimAsset, size 0xF8, Pack=8):
  0x00 name ptr        0x08 randDataByteCount  0x0C dataShortCount
  0x10 extraChanCount  0x14 dataByteCount       0x18 dataIntCount
  0x1C randDataIntCount 0x20 frameCount(u16)    0x22 boneCount(u16)
  0x30 boneCounts[10] (u16, indexed by PartType) 0x48 randDataShortCount
  0x4C indexCount      0x50 frameRate(f32)       0x54 frequency(f32)
  0x68 names ptr  0x70 dataByte  0x78 dataShort  0x80 dataInt
  0x88 randDataShort 0x90 randDataByte 0x98 randDataInt 0xA0 extraChan
  0xA8 indices 0xB0 ikLayers 0xB8 ikBones
  0xC0/0xD0/0xE0 Notes/StartupNotes/ShutdownNotes (ptr@+0, count byte@+8)
  0xF0 deltaParts ptr

Inline stream order (what the linker writes back-to-back, no alignment padding):
  name -> [bone-name hashes if names inline: boneCount*4] -> notetracks (16B each)
       -> [delta block if delta inline: variable] -> DataByte -> DataShort
       -> DataInt -> RandomDataShort -> RandomDataByte -> RandomDataInt

PartType order of boneCounts[10] (drives the decode stages):
  0 NoneRotated   1 TwoDRotated    2 NormalRotated  3 TwoDStaticRotated
  4 NormalStaticRotated  5 NormalTranslated(byte)  6 PreciseTranslated(short)
  7 StaticTranslated     8 NoneTranslated          9 total (== boneCount)
"""
import struct

_INLINE = 0xFFFFFFFFFFFFFFFF


def _u(d, o, n):   return int.from_bytes(d[o:o + n], 'little')
def _half(d, o):   return struct.unpack('<e', d[o:o + 2])[0]
def _f32(d, o):    return struct.unpack('<f', d[o:o + 4])[0]


def _array_base(d, X):
    """Offset just past name + inline bone-names + notetracks (before delta/arrays)."""
    o = d.index(b'\x00', X + 0xF8) + 1                 # after the inline name
    bc = _u(d, X + 0x22, 2)
    if _u(d, X + 0x68, 8) == _INLINE:                  # bone-name hashes inline
        o += bc * 4
    notes = d[X + 0xC8] + d[X + 0xD8] + d[X + 0xE8]     # notetrack count (3 lists)
    o += notes * 16                                    # XAnimNotifyInfo = 16 bytes
    return o


def _consume_ok(d, X, pDB):
    """Walk the staged cursors from a candidate DataByte start; True iff every
    cursor ends exactly at start+size and every framecount/boneID is in range."""
    dS = _u(d, X + 0x0C, 4); dB = _u(d, X + 0x14, 4); dI = _u(d, X + 0x18, 4)
    rB = _u(d, X + 0x08, 4); rS = _u(d, X + 0x48, 4)
    fc = _u(d, X + 0x20, 2); bc = _u(d, X + 0x22, 2)
    bcnt = [_u(d, X + 0x30 + 2 * k, 2) for k in range(10)]
    NoneRot, TwoDRot, NormRot, TwoDStat, NormStat, NormTr, PrecTr, StatTr, NoneTr = bcnt[:9]
    pDS = pDB + dB; pDI = pDS + dS * 2; pRS = pDI + dI * 4; pRB = pRS + rS * 2; endRB = pRB + rB
    if endRB > len(d):
        return False
    c = {'DB': pDB, 'DS': pDS, 'DI': pDI, 'RS': pRS, 'RB': pRB}
    frmS = 1 if fc <= 255 else 2
    bonS = 1 if bc <= 255 else 2

    def rf():
        if frmS == 1:
            v = d[c['DB']]; c['DB'] += 1
        else:
            v = _u(d, c['DS'], 2); c['DS'] += 2
        return v

    def rb():
        if bonS == 1:
            v = d[c['DB']]; c['DB'] += 1
        else:
            v = _u(d, c['DS'], 2); c['DS'] += 2
        return v

    try:
        for _ in range(TwoDRot):
            n = _u(d, c['DS'], 2); c['DS'] += 2
            if n > fc: return False
            for _ in range(n + 1): rf()
            c['RS'] += (n + 1) * 4
        for _ in range(NormRot):
            n = _u(d, c['DS'], 2); c['DS'] += 2
            if n > fc: return False
            for _ in range(n + 1): rf()
            c['RS'] += (n + 1) * 8
        c['DS'] += TwoDStat * 4 + NormStat * 8
        for _ in range(NormTr):
            if rb() >= bc: return False
            n = _u(d, c['DS'], 2); c['DS'] += 2
            if n > fc: return False
            c['DI'] += 24
            for _ in range(n + 1): rf()
            c['RB'] += (n + 1) * 3
        for _ in range(PrecTr):
            if rb() >= bc: return False
            n = _u(d, c['DS'], 2); c['DS'] += 2
            if n > fc: return False
            c['DI'] += 24
            for _ in range(n + 1): rf()
            c['RS'] += (n + 1) * 6
        for _ in range(StatTr):
            c['DI'] += 12
            if rb() >= bc: return False
        for _ in range(NoneTr):
            if rb() >= bc: return False
    except IndexError:
        return False
    return (c['DB'] == pDB + dB and c['DS'] == pDS + dS * 2 and c['DI'] == pDI + dI * 4
            and c['RS'] == pRS + rS * 2 and c['RB'] == endRB)


def locate_arrays(d, X, scan_limit=1 << 16):
    """Return the DataByte start offset. Uses the self-consistency check; if the
    natural base fails (an inline delta block precedes the arrays), scans forward
    for the first offset that consumes exactly. Returns None if not found."""
    base = _array_base(d, X)
    if _consume_ok(d, X, base):
        return base, 0
    for s in range(1, scan_limit):
        if _consume_ok(d, X, base + s):
            return base + s, s
    return None, None


def decode_xanim(d, X):
    """Decode the XAnimParts at offset X. Returns a dict:
       name, frameCount, boneCount, fps, boneNameHashes,
       rot: {boneIdx: [(frame,(x,y,z,w)), ...]},
       trn: {boneIdx: [(frame,(x,y,z)), ...]},
       noTrans: [boneIdx...], hasDelta: bool, deltaSkip: int, exact: bool
    """
    dS = _u(d, X + 0x0C, 4); dB = _u(d, X + 0x14, 4); dI = _u(d, X + 0x18, 4)
    rB = _u(d, X + 0x08, 4); rS = _u(d, X + 0x48, 4)
    fc = _u(d, X + 0x20, 2); bc = _u(d, X + 0x22, 2)
    fps = _f32(d, X + 0x50)
    bcnt = [_u(d, X + 0x30 + 2 * k, 2) for k in range(10)]
    NoneRot, TwoDRot, NormRot, TwoDStat, NormStat, NormTr, PrecTr, StatTr, NoneTr = bcnt[:9]

    pDB, skip = locate_arrays(d, X)
    if pDB is None:
        raise ValueError('could not locate xanim data arrays for %r' % _name(d, X))
    pDS = pDB + dB; pDI = pDS + dS * 2; pRS = pDI + dI * 4; pRB = pRS + rS * 2

    # bone name hashes (4 bytes each) if present
    hashes = []
    if _u(d, X + 0x68, 8) == _INLINE:
        ho = d.index(b'\x00', X + 0xF8) + 1
        hashes = [_u(d, ho + 4 * k, 4) for k in range(bc)]

    c = {'DB': pDB, 'DS': pDS, 'DI': pDI, 'RS': pRS, 'RB': pRB}
    frmS = 1 if fc <= 255 else 2
    bonS = 1 if bc <= 255 else 2

    def rf():
        if frmS == 1:
            v = d[c['DB']]; c['DB'] += 1
        else:
            v = _u(d, c['DS'], 2); c['DS'] += 2
        return v

    def rb():
        if bonS == 1:
            v = d[c['DB']]; c['DB'] += 1
        else:
            v = _u(d, c['DS'], 2); c['DS'] += 2
        return v

    rot = {}; trn = {}; noTrans = []
    i = 0
    for _ in range(NoneRot):                            # identity rotation
        rot[i] = [(0, (0.0, 0.0, 0.0, 1.0))]; i += 1
    for _ in range(TwoDRot):                            # animated 2D (Z,W)
        n = _u(d, c['DS'], 2); c['DS'] += 2; rs0 = c['RS']; keys = []
        for f in range(n + 1):
            fr = rf(); z = _half(d, rs0 + 2 * (2 * f)); w = _half(d, rs0 + 2 * (2 * f + 1))
            keys.append((fr, (0.0, 0.0, z, w)))
        c['RS'] = rs0 + (n + 1) * 4; rot[i] = keys; i += 1
    for _ in range(NormRot):                            # animated 3D (X,Y,Z,W)
        n = _u(d, c['DS'], 2); c['DS'] += 2; rs0 = c['RS']; keys = []
        for f in range(n + 1):
            fr = rf(); q = tuple(_half(d, rs0 + 2 * (4 * f + j)) for j in range(4))
            keys.append((fr, q))
        c['RS'] = rs0 + (n + 1) * 8; rot[i] = keys; i += 1
    for _ in range(TwoDStat):                           # static 2D
        z = _half(d, c['DS']); w = _half(d, c['DS'] + 2); c['DS'] += 4
        rot[i] = [(0, (0.0, 0.0, z, w))]; i += 1
    for _ in range(NormStat):                           # static 3D
        q = tuple(_half(d, c['DS'] + 2 * j) for j in range(4)); c['DS'] += 8
        rot[i] = [(0, q)]; i += 1
    for _ in range(NormTr):                             # byte translation
        b = rb(); n = _u(d, c['DS'], 2); c['DS'] += 2
        mn = (_f32(d, c['DI']), _f32(d, c['DI'] + 4), _f32(d, c['DI'] + 8)); c['DI'] += 12
        sz = (_f32(d, c['DI']), _f32(d, c['DI'] + 4), _f32(d, c['DI'] + 8)); c['DI'] += 12
        rb0 = c['RB']; keys = []
        for f in range(n + 1):
            fr = rf(); kx, ky, kz = d[rb0 + 3 * f], d[rb0 + 3 * f + 1], d[rb0 + 3 * f + 2]
            keys.append((fr, (sz[0] * kx + mn[0], sz[1] * ky + mn[1], sz[2] * kz + mn[2])))
        c['RB'] = rb0 + (n + 1) * 3; trn[b] = keys
    for _ in range(PrecTr):                             # short translation
        b = rb(); n = _u(d, c['DS'], 2); c['DS'] += 2
        mn = (_f32(d, c['DI']), _f32(d, c['DI'] + 4), _f32(d, c['DI'] + 8)); c['DI'] += 12
        sz = (_f32(d, c['DI']), _f32(d, c['DI'] + 4), _f32(d, c['DI'] + 8)); c['DI'] += 12
        rs0 = c['RS']; keys = []
        for f in range(n + 1):
            fr = rf()
            kx = _u(d, rs0 + 2 * (3 * f), 2); ky = _u(d, rs0 + 2 * (3 * f + 1), 2); kz = _u(d, rs0 + 2 * (3 * f + 2), 2)
            keys.append((fr, (sz[0] * kx + mn[0], sz[1] * ky + mn[1], sz[2] * kz + mn[2])))
        c['RS'] = rs0 + (n + 1) * 6; trn[b] = keys
    for _ in range(StatTr):                             # static translation
        v = (_f32(d, c['DI']), _f32(d, c['DI'] + 4), _f32(d, c['DI'] + 8)); c['DI'] += 12
        b = rb(); trn[b] = [(0, v)]
    for _ in range(NoneTr):                             # no translation (bind pose)
        noTrans.append(rb())

    exact = (c['DB'] == pDB + dB and c['DS'] == pDS + dS * 2 and c['DI'] == pDI + dI * 4
             and c['RS'] == pRS + rS * 2 and c['RB'] == pRB + rB)
    return dict(name=_name(d, X), frameCount=fc, boneCount=bc, fps=fps,
                boneCounts=bcnt, boneNameHashes=hashes, rot=rot, trn=trn,
                noTrans=noTrans, hasDelta=(_u(d, X + 0xF0, 8) == _INLINE),
                deltaSkip=skip, exact=exact)


def _name(d, X):
    e = d.index(b'\x00', X + 0xF8)
    return d[X + 0xF8:e].decode('latin-1', 'replace')
