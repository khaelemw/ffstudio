"""Fix a linker-compiled T7 GSC object's identifier hashes back to ACTS's convention.
The linker hashes the literal string 'function_c9206e95' -> HashT7(...) = wrong value,
but the intended hash is 0xc9206e95. We scan the SOURCE for every ACTS-style identifier
(function_/var_/namespace_/script_/hash_ + hex), compute HashT7(identifier) = the wrong
value the linker emitted, and remap it to the correct hex value in the import & export
tables (and, optionally, everywhere)."""
import struct, re
from t7hash import hasht7

IDENT_RE = re.compile(r'\b(function|namespace|var|script|hash|method)_([0-9a-fA-F]{1,16})\b')

def build_map_from_source(*source_paths):
    m = {}
    for p in source_paths:
        txt = open(p, 'r', encoding='utf-8', errors='replace').read()
        for pre, hexv in IDENT_RE.findall(txt):
            ident = f"{pre}_{hexv}"
            wrong = hasht7(ident)          # what the linker emitted
            correct = int(hexv, 16) & 0xFFFFFFFF
            m[wrong] = correct
    return m

def remap_gsc(data, remap):
    data = bytearray(data)
    assert data[:8] == bytes.fromhex('804753430d0a001c'), "not a T7 GSC object"
    cseg_off = struct.unpack_from('<I', data, 0x14)[0]
    export_off, import_off = struct.unpack_from('<II', data, 0x20)
    cseg_size = struct.unpack_from('<I', data, 0x30)[0]
    export_cnt, import_cnt = struct.unpack_from('<HH', data, 0x3A)
    changed = 0
    # exports: 20 bytes each (checksum,address,name,name_space,param,flags,pad); name @+8, name_space @+12
    for i in range(export_cnt):
        o = export_off + i * 20
        for f in (o + 8, o + 12):
            v = struct.unpack_from('<I', data, f)[0]
            if v in remap:
                struct.pack_into('<I', data, f, remap[v]); changed += 1
    # imports: variable size; name @+0, name_space @+4, num_address @+8 (u16), +12 header, +N*4
    o = import_off
    for i in range(import_cnt):
        name, ns, num_addr = struct.unpack_from('<IIH', data, o)
        for f in (o + 0, o + 4):
            v = struct.unpack_from('<I', data, f)[0]
            if v in remap:
                struct.pack_into('<I', data, f, remap[v]); changed += 1
        o += 12 + num_addr * 4
    # code segment: local ScriptFunctionCall hashes + field/var hashes are stored INLINE.
    # 4-byte-aligned scan (T7 opcodes align hash operands to 4) and replace exact matches.
    cchanged = 0
    start = (cseg_off + 3) & ~3          # first 4-aligned pos in cseg
    end = cseg_off + cseg_size - 3
    for p in range(start, end, 4):        # hash operands are 4-byte aligned
        v = struct.unpack_from('<I', data, p)[0]
        if v in remap:
            struct.pack_into('<I', data, p, remap[v]); cchanged += 1
    return bytes(data), changed, cchanged
