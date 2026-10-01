"""HKS re-serializer: rebuilds an HKS chunk from the hksc ldump layout (see hks_disasm._read_function).

Supports byte-exact round-trip and bytecode-level edits (change a string or number constant, or patch an
instruction word). The format is length/count-prefixed and jumps are instruction-relative, so changing a
constant's length just reflows the bytes; no offset fixups are needed. Source-level recompile is in hks_compile.

API:
  serialize(d, const_edits=None, code_edits=None) -> new HKS bytes
       const_edits: {fn_index: {const_index: python value}}   (str/int/float/bool/None)
       code_edits:  {fn_index: {instr_index: word_int}}
  round_trip_ok(d) -> bool
"""
import struct
import hks_disasm as H

def _u(d, o, n): return int.from_bytes(d[o:o+n], 'little')

def _encode_const(t, v):
    if t == 'nil':  return b'\x00'
    if t == 'bool': return b'\x01' + (b'\x01' if v else b'\x00')
    if t == 'num':  return b'\x03' + struct.pack('<f', float(v))
    if t == 'str':
        b = v.encode('latin1') if isinstance(v, str) else bytes(v)
        return b'\x04' + struct.pack('<Q', len(b) + 1) + b + b'\x00'
    if t == 'ui64': return b'\x0b' + struct.pack('<Q', int(v))
    raise ValueError(f'cannot encode const type {t}')

def _py_to_const(value):
    if value is None:            return ('nil', None)
    if isinstance(value, bool):  return ('bool', value)
    if isinstance(value, int):   return ('num', float(value))
    if isinstance(value, float): return ('num', value)
    if isinstance(value, str):   return ('str', value)
    raise ValueError(f'unsupported edit value {value!r}')

def serialize(d, const_edits=None, code_edits=None, hoff=None):
    """Re-serialize the HKS chunk, applying optional constant/code edits. Returns new bytes."""
    const_edits = const_edits or {}; code_edits = code_edits or {}
    if hoff is None:
        _, hoff = H._parse_types(d)
    prefix = d[:hoff]
    idx = [0]
    def emit(hoff):
        r = H._read_function(d, hoff)
        if r is None:
            raise ValueError(f'bad function @ {hoff:#x}')
        i = idx[0]; idx[0] += 1
        cs = r['code_start']; ce = r['code_end']
        out = bytearray()
        out += d[r['header_off']:cs]                    # header (incl size_t sizecode) + '_' pad — verbatim
        ce_edits = code_edits.get(i, {})
        if ce_edits:
            for k in range(r['sizecode']):
                out += struct.pack('<I', ce_edits.get(k, _u(d, cs + 4*k, 4)))
        else:
            out += d[cs:ce]
        # constants: sizek + values (raw spans preserved, edited ones re-encoded)
        o = ce; sizek = _u(d, o, 4); o += 4
        spans = []
        for _ in range(sizek):
            cr = H._parse_const(d, o); spans.append((o, cr[1], cr[0])); o = cr[1]
        const_region_end = o
        k_edits = const_edits.get(i, {})
        if k_edits:
            out += struct.pack('<I', sizek)             # value edits keep the count
            for ci, (s, e, val) in enumerate(spans):
                if ci in k_edits:
                    t, v = _py_to_const(k_edits[ci]); out += _encode_const(t, v)
                else:
                    out += d[s:e]                        # verbatim (exact float/hash bytes preserved)
        else:
            out += d[ce:const_region_end]
        out += d[const_region_end:r['children_start']]  # debug{flag,hash} + sizep — verbatim
        o = r['children_start']
        for _ in range(r['sub_count']):
            cb, o = emit(o)
            out += cb
        return bytes(out), o
    body, _end = emit(hoff)
    return prefix + body

def round_trip_ok(d, hoff=None):
    try:
        return serialize(d, hoff=hoff) == d
    except Exception:
        return False
