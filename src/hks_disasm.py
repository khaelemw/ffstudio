"""Havok Script (HKS) Lua bytecode DISASSEMBLER for BO3 (T7) LUI rawfiles (`\\x1bLuaQ`, format 0x0E).

The opcode table and operand decode follow the Call of Duty HavokScript ISA (T7/T8) as used by
CoDHVKDecompiler (Deewarz).

CONTAINER:
  header \\x1bLuaQ, format 0x0E, int4/size_t8/instr4/number4(float)/integral0 ;
  `u32 numTypes(=13)` + 13×{u32 code,u32 nameLen,name} (TNIL..TSTRUCT) ;
  then the function tree (see _read_function). Constant TValue = typebyte + payload (0 nil, 1 bool+byte,
  3 number+f32, 4 string+u64len+bytes).

INSTRUCTION DECODE (4-byte little-endian word w) — byte-precise per CoDHVKDecompiler (Deewarz) LuaFileT7T8.cs
(bytes b0..b3 = w&0xFF, (w>>8)&0xFF, (w>>16)&0xFF, (w>>24)&0xFF):
  A = b0 ;  C = b1 (full 8-bit) ;  ExtraCBit = b2&1 ;  B = (b2>>1) | ((b3&1)<<7) (8-bit) ;  opcode = b3>>1 ;
  Bx = (B<<9) | (ExtraCBit<<8) | C ;  sBx = Bx - 65535.
Operand roles (from LuaDisassembler.GenerateIRHKS): iABx ops (LOADK/GETGLOBAL/SETGLOBAL/GETGLOBAL_MEM) → K[Bx];
CLOSURE → proto[Bx]; GETFIELD/GETFIELD_R1 → R(A)=R(B)[K[C]] (field=K[C]); SETFIELD/SETFIELD_R1 →
R(A)[K[B]]=RK(C) (field=K[B], value=RK(C)); RK(C) = ExtraCBit ? K[C] : R(C); `_BK` ops → operand B is K[B];
comparisons EQ/LT/LE(+_BK) test-and-skip the following JMP; SETLIST block stride = 32. Ops with no reference
semantics in the source (INTRINSIC_*, SETSLOT*/GETSLOT*/CHECKTYPE*, NEWSTRUCT, CALL_C/CALL_M, GETFIELD_MM,
GETTABLE_N, SETTABLE_N*/_BK) are rendered raw (A/B/C).

`disassemble_all(d)` / `analyze()['proto_tree']` disassemble the whole nested function tree. Readable source
is produced by hks_decompile; recompiling from source uses hksc (hks_compile).
"""
import struct

# Authoritative T7/T8 (BO3/BO4) HavokScript opcode table (index -> mnemonic), 0..100.
OPCODES = ("GETFIELD TEST CALL_I CALL_C EQ EQ_BK GETGLOBAL MOVE SELF RETURN GETTABLE_S GETTABLE_N GETTABLE "
 "LOADBOOL TFORLOOP SETFIELD SETTABLE_S SETTABLE_S_BK SETTABLE_N SETTABLE_N_BK SETTABLE SETTABLE_BK TAILCALL_I "
 "TAILCALL_C TAILCALL_M LOADK LOADNIL SETGLOBAL JMP CALL_M CALL INTRINSIC_INDEX INTRINSIC_NEWINDEX INTRINSIC_SELF "
 "INTRINSIC_INDEX_LITERAL INTRINSIC_NEWINDEX_LITERAL INTRINSIC_SELF_LITERAL TAILCALL GETUPVAL SETUPVAL ADD ADD_BK "
 "SUB SUB_BK MUL MUL_BK DIV DIV_BK MOD MOD_BK POW POW_BK NEWTABLE UNM NOT LEN LT LT_BK LE LE_BK SHIFT_LEFT "
 "SHIFT_LEFT_BK SHIFT_RIGHT SHIFT_RIGHT_BK BITWISE_AND BITWISE_AND_BK BITWISE_OR BITWISE_OR_BK CONCAT TESTSET "
 "FORPREP FORLOOP SETLIST CLOSE CLOSURE VARARG TAILCALL_I_R1 CALL_I_R1 SETUPVAL_R1 TEST_R1 NOT_R1 GETFIELD_R1 "
 "SETFIELD_R1 NEWSTRUCT DATA SETSLOTN SETSLOTI SETSLOT SETSLOTS SETSLOTMT CHECKTYPE CHECKTYPES GETSLOT GETSLOTMT "
 "SELFSLOT SELFSLOTMT GETFIELD_MM CHECKTYPE_D GETSLOT_D GETGLOBAL_MEM MAX").split()

_KBX     = {'LOADK', 'GETGLOBAL', 'SETGLOBAL', 'GETGLOBAL_MEM'}   # constant index is Bx
_FIELD_C = {'GETFIELD', 'GETFIELD_R1', 'GETFIELD_MM'}            # R(A)=R(B)[K[C]] : field const is C
_FIELD_B = {'SETFIELD', 'SETFIELD_R1'}                           # R(A)[K[B]]=RK(C) : field const is B
_JMP     = {'JMP', 'FORLOOP', 'FORPREP'}                         # sBx branch target
_ARITH   = {'ADD','SUB','MUL','DIV','MOD','POW','SHIFT_LEFT','SHIFT_RIGHT','BITWISE_AND','BITWISE_OR'}
_BINSYM  = {'ADD':'+','SUB':'-','MUL':'*','DIV':'/','MOD':'%','POW':'^','SHIFT_LEFT':'<<','SHIFT_RIGHT':'>>',
            'BITWISE_AND':'&','BITWISE_OR':'|'}
_CMPSYM  = {'EQ':('==','~='), 'LT':('<','>='), 'LE':('<=','>')}   # (normal, inverted when A==1)

def _u(d, o, n): return int.from_bytes(d[o:o+n], 'little')

def _parse_types(d):
    p = 0x0c; types = []
    while p < 0x400 and len(types) < 13:
        code = _u(d, p, 4); ln = _u(d, p+4, 4)
        if 0 < ln < 40 and p+8+ln <= len(d) and all(32 <= d[p+8+k] < 127 for k in range(ln-1)) and d[p+8+ln-1] == 0:
            types.append([code, d[p+8:p+8+ln-1].decode('latin1')]); p += 8+ln
        else:
            p += 1
    return types, p

def _parse_const(d, o):
    if o >= len(d): return None
    t = d[o]
    if t == 0: return ('nil', None), o+1
    if t == 1:
        if o+2 > len(d): return None
        return ('bool', bool(d[o+1])), o+2
    if t == 3:
        if o+5 > len(d): return None
        return ('num', round(struct.unpack('<f', d[o+1:o+5])[0], 6)), o+5
    if t == 4:
        ln = _u(d, o+1, 8)
        if not (0 < ln < 100000) or o+9+ln > len(d): return None
        s = d[o+9:o+9+ln-1]
        if not all(9 <= b < 127 or b == 0 for b in s): return None
        return ('str', s.decode('latin1', 'replace')), o+9+ln
    if t == 11:                                    # TUI64 (hash literal) — 8 bytes
        if o+9 > len(d): return None
        return ('ui64', _u(d, o+1, 8)), o+9
    if t == 2:                                     # TLIGHTUSERDATA — size_t (8)
        if o+9 > len(d): return None
        return ('lud', _u(d, o+1, 8)), o+9
    return None

def _decode(w):
    """(opcode, A, B, C, Bx, sBx, ExtraCBit) for a 32-bit HKS instruction word (byte-precise T7/T8 layout)."""
    A = w & 0xFF                       # b0
    C = (w >> 8) & 0xFF                # b1  (full 8-bit; 9th bit is ExtraCBit)
    ExtraC = (w >> 16) & 1             # b2 bit0
    B = ((w >> 17) & 0x7F) | (((w >> 24) & 1) << 7)   # b2>>1 | (b3 bit0)<<7  (8-bit)
    op = w >> 25                       # b3>>1
    Bx = (B << 9) | (ExtraC << 8) | C
    return op, A, B, C, Bx, Bx - 65535, ExtraC

def _read_function(d, hoff):
    """Read ONE function prototype at hoff using the authoritative Havok/hksc `ldump.c` layout (format 0x0E):
      nups i32, nparams i32, vararg u8, maxstacksize i32, sizecode size_t(8), pad-to-4('_'), code(sizecode*4),
      sizek i32, constants, debug{ i32=1, i32 hash }, sizep i32, then children.
    Deterministic — no searching. Returns a record dict or None."""
    if hoff + 21 > len(d): return None
    up = _u(d, hoff, 4); pa = _u(d, hoff+4, 4); va = d[hoff+8]; rg = _u(d, hoff+9, 4)
    if up > 4096 or pa > 4096 or rg > 4096: return None
    sizecode = _u(d, hoff+0xd, 8)                       # 8-byte size_t
    o = (hoff + 0xd + 8 + 3) & ~3                       # align up to sizeof(Instruction)=4 (aligned2instr)
    code_start = o
    if not (0 < sizecode < 1000000) or code_start + 4*sizecode > len(d): return None
    o = code_start + 4*sizecode; code_end = o
    sizek = _u(d, o, 4); o += 4
    if sizek > 100000: return None
    consts = []
    for _ in range(sizek):
        r = _parse_const(d, o)
        if r is None: return None
        consts.append(r[0]); o = r[1]
    if o + 12 > len(d): return None
    dbg = _u(d, o, 4); o += 4                           # debug-present flag (1 in stripped files)
    fhash = _u(d, o, 4); o += 4                         # function hash (const 0xe1335a45 in shipped RR files)
    sizep = _u(d, o, 4); o += 4
    if sizep > 100000: return None
    return {'header_off': hoff, 'upvals': up, 'params': pa, 'vararg': va, 'registers': rg,
            'sizecode': sizecode, 'code_start': code_start, 'code_end': code_end,
            'constants': consts, 'debug_flag': dbg, 'hash': fhash, 'sub_count': sizep,
            'children_start': o}

def _top_function(d):
    """Parse the top-level function (starts right after the 13-type table). Adds decoded `code` words."""
    if len(d) < 0x20 or d[:5] != b'\x1bLuaQ':
        return None
    _, hoff = _parse_types(d)
    r = _read_function(d, hoff)
    if r is None:
        return None
    r['code'] = [_u(d, r['code_start'] + 4*k, 4) for k in range(r['sizecode'])]
    return r

def _fmt_const(c):
    return (repr(c[1]) if c[0] == 'str' else str(c[1]) if c[0] != 'nil' else 'nil')

def _render(op_name, A, B, C, Bx, sBx, K, EC=0):
    """A short readable form of one instruction with resolved constants and correct operand roles (grounded;
    unmodeled ops fall back to raw A/B/C, never guessed)."""
    def k(i): return f"K{i}({_fmt_const(K[i])})" if 0 <= i < len(K) else f"K{i}?"
    def rk(c): return k(c) if EC else f"R{c}"                 # RK(C): const if ExtraCBit else register
    nm = op_name
    if nm == 'LOADK':                    return f"LOADK  R{A} := {k(Bx)}"
    if nm in ('GETGLOBAL', 'GETGLOBAL_MEM'): return f"{nm}  R{A} := _G[{k(Bx)}]"
    if nm == 'SETGLOBAL':                return f"SETGLOBAL  _G[{k(Bx)}] := R{A}"
    if nm in _FIELD_C:                   return f"{nm}  R{A} := R{B}.{k(C)}"
    if nm in _FIELD_B:                   return f"{nm}  R{A}.{k(B)} := {rk(C)}"
    if nm == 'CLOSURE':                  return f"CLOSURE  R{A} := proto#{Bx}"
    if nm == 'MOVE':                     return f"MOVE  R{A} := R{B}"
    if nm in ('GETTABLE_S', 'GETTABLE'): return f"{nm}  R{A} := R{B}[{rk(C)}]"
    if nm in ('SETTABLE_S', 'SETTABLE'): return f"{nm}  R{A}[R{B}] := {rk(C)}"
    if nm == 'SETTABLE_S_BK':            return f"SETTABLE_S_BK  R{A}[{k(B)}] := {rk(C)}"
    if nm == 'SELF':                     return f"SELF  R{A+1} := R{B}; R{A} := R{B}[{rk(C)}]"
    if nm == 'NEWTABLE':                 return f"NEWTABLE  R{A} := {{}}"
    if nm in ('CALL_I', 'CALL', 'CALL_I_R1'):
        na = 'top' if B == 0 else B-1; nr = 'multi' if C == 0 else C-1
        return f"{nm}  R{A}({na} args) -> {nr} ret"
    if nm in ('TAILCALL', 'TAILCALL_I', 'TAILCALL_I_R1'):
        na = 'top' if B == 0 else B-1;   return f"{nm}  return R{A}({na} args)"
    if nm == 'RETURN':                   return f"RETURN  R{A}..R{A+B-2}" if B else f"RETURN  R{A}.. (multi)"
    if nm in _ARITH:                     return f"{nm}  R{A} := R{B} {_BINSYM[nm]} {rk(C)}"
    if nm.endswith('_BK') and nm[:-3] in _ARITH:
        return f"{nm}  R{A} := {k(B)} {_BINSYM[nm[:-3]]} R{C}"
    if nm in ('UNM', 'NOT', 'NOT_R1', 'LEN'):
        u = {'UNM':'-', 'NOT':'not ', 'NOT_R1':'not ', 'LEN':'#'}[nm]
        return f"{nm}  R{A} := {u}R{B}"
    if nm == 'CONCAT':                   return f"CONCAT  R{A} := R{B}..R{C}"
    if nm in ('EQ', 'LT', 'LE'):         return f"{nm}  if not (R{B} {_CMPSYM[nm][A & 1]} {rk(C)}) skip"
    if nm[:-3] in ('EQ', 'LT', 'LE') and nm.endswith('_BK'):
        return f"{nm}  if not ({k(B)} {_CMPSYM[nm[:-3]][A & 1]} R{C}) skip"
    if nm == 'JMP':                      return f"JMP  -> {sBx:+d}"
    if nm in _JMP:                       return f"{nm}  R{A} -> {sBx:+d}"
    if nm == 'LOADNIL':                  return f"LOADNIL  R{A}..R{B} := nil"
    if nm == 'LOADBOOL':                 return f"LOADBOOL  R{A} := {bool(B)}" + ("  (skip next)" if C else "")
    if nm == 'GETUPVAL':                 return f"GETUPVAL  R{A} := U{B}"
    if nm in ('SETUPVAL', 'SETUPVAL_R1'):return f"{nm}  U{B} := R{A}"
    if nm in ('TEST', 'TEST_R1'):        return f"{nm}  if {'' if C else 'not '}R{A} skip"
    if nm == 'DATA':                     return f"DATA  ({'upval R'+str(C) if A==1 else 'upval U'+str(C) if A==2 else 'pad'})"
    if nm == 'VARARG':                   return f"VARARG  R{A}..R{A+B-1}" if B else f"VARARG  R{A}.. (multi)"
    if nm == 'TFORLOOP':                 return f"TFORLOOP  R{A}(iter) -> {C} ret"
    return f"{nm}  A={A} B={B} C={C}" + (f" Bx={Bx}" if Bx else "")

def disassemble(d):
    fn = _top_function(d)
    if fn is None:
        return {'error': 'unrecognized HKS function header (non-empty source name?)'}
    K = fn['constants']
    listing = []
    for i, w in enumerate(fn['code']):
        op, A, B, C, Bx, sBx, ex = _decode(w)
        name = OPCODES[op] if op < len(OPCODES) else f'OP_{op}'
        ins = {'i': i, 'word': f'{w:08x}', 'op': op, 'name': name,
               'A': A, 'B': B, 'C': C, 'Bx': Bx, 'sBx': sBx, 'ec': ex,
               'text': _render(name, A, B, C, Bx, sBx, K, ex)}
        if name in _KBX and 0 <= Bx < len(K): ins['const'] = _fmt_const(K[Bx])
        elif name in _FIELD_C and 0 <= C < len(K): ins['const'] = _fmt_const(K[C])
        elif name in _FIELD_B and 0 <= B < len(K): ins['const'] = _fmt_const(K[B])
        elif name == 'CLOSURE': ins['proto'] = Bx
        listing.append(ins)
    return {'upvals': fn['upvals'], 'params': fn['params'], 'vararg': fn['vararg'],
            'registers': fn['registers'], 'sizecode': fn['sizecode'],
            'instructions': listing,
            'constants': [{'i': i, 'type': c[0], 'value': c[1]} for i, c in enumerate(K)],
            'opcode_histogram': _hist(fn['code'])}

def _hist(code):
    h = {}
    for w in code:
        op = w >> 25; name = OPCODES[op] if op < len(OPCODES) else f'OP_{op}'
        h[name] = h.get(name, 0) + 1
    return dict(sorted(h.items(), key=lambda kv: -kv[1]))

def analyze(d):
    """Backward-compatible summary (header/types/string_count/strings) + full `disasm` of the top function."""
    assert d[:5] == b'\x1bLuaQ', "not HKS/LuaQ"
    hdr = dict(lua='5.1', hks_format=d[5], endian=d[6], int=d[7], size_t=d[8],
               instr=d[9], number=d[10], integral=d[11])
    types, typeEnd = _parse_types(d)
    strings = []; i = typeEnd; n = len(d)
    while i < n-9:
        if d[i] == 0x04:
            ln = _u(d, i+1, 8)
            if 1 < ln < 4096 and i+9+ln <= n and d[i+9+ln-1] == 0 and all(9 <= d[i+9+k] < 127 for k in range(ln-1)):
                strings.append(d[i+9:i+9+ln-1].decode('latin1')); i += 9+ln; continue
        i += 1
    out = dict(header=hdr, types=types, string_count=len(strings), strings=strings)
    try:
        out['disasm'] = disassemble(d)
    except Exception as e:
        out['disasm'] = {'error': str(e)}
    try:
        out['proto_tree'] = disassemble_all(d)     # every function (nested), additive to 'disasm'
    except Exception as e:
        out['proto_tree'] = {'error': str(e), 'functions': [], 'count': 0}
    return out

# ---------------------------------------------------------------------------------------------------
# NESTED FUNCTIONS: the recursive function tree, following the hksc `ldump.c` layout (format 0x0E).
#
# Per function: nups i32, nparams i32, vararg u8, maxstacksize i32, sizecode size_t(8), '_'-pad to a 4-byte
# boundary, code (sizecode*4), sizek i32, constants, debug{ i32 flag=1, i32 hash }, sizep i32, then sizep
# children recursively. Everything is length/count-prefixed.

def _parse_proto_tree(d, hoff=None):
    """Recursively parse the full proto tree. hoff defaults to the end of the 13-type table (top function).
    Returns (flat preorder list of function records, end_offset, error_or_None)."""
    if hoff is None:
        _, hoff = _parse_types(d)
    out = []
    def rec(hoff, depth, parent):
        r = _read_function(d, hoff)
        if r is None:
            return None, f'badfn@{hoff:#x}'
        idx = len(out)
        r.update(index=idx, depth=depth, parent=parent, children=[])
        out.append(r)
        o = r['children_start']
        for _ in range(r['sub_count']):
            child_idx = len(out)
            ro, err = rec(o, depth + 1, idx)
            if ro is None:
                return None, err
            r['children'].append(child_idx)
            o = ro
        return o, None
    end, err = rec(hoff, 0, None)
    return out, end, err

def _disasm_fn(d, rec):
    """Disassemble one function record."""
    cs = rec['code_start']; ic = rec['sizecode']; K = rec['constants']; kids = rec['children']
    listing = []
    for i in range(ic):
        w = _u(d, cs + 4*i, 4)
        op, A, B, C, Bx, sBx, ex = _decode(w)
        name = OPCODES[op] if op < len(OPCODES) else f'OP_{op}'
        ins = {'i': i, 'word': f'{w:08x}', 'op': op, 'name': name,
               'A': A, 'B': B, 'C': C, 'Bx': Bx, 'sBx': sBx, 'ec': ex,
               'text': _render(name, A, B, C, Bx, sBx, K, ex)}
        if name in _KBX and 0 <= Bx < len(K): ins['const'] = _fmt_const(K[Bx])
        elif name in _FIELD_C and 0 <= C < len(K): ins['const'] = _fmt_const(K[C])
        elif name in _FIELD_B and 0 <= B < len(K): ins['const'] = _fmt_const(K[B])
        elif name == 'CLOSURE':
            ins['proto'] = Bx                                    # local child index
            if 0 <= Bx < len(kids): ins['proto_index'] = kids[Bx]  # global preorder index of that child
        listing.append(ins)
    return listing

def disassemble_all(d):
    """Disassemble EVERY function in the HKS chunk (the whole nested proto tree). Additive to
    `disassemble` (which stays top-only for backward compatibility). Returns:
      {'functions':[{index,depth,parent,children,header_off,code_start,sizecode,params,upvals,vararg,
                     registers,sub_count,instructions,constants,opcode_histogram}...],
       'count', 'end_offset', 'file_size', 'complete', 'error'}."""
    if len(d) < 0x110 or d[:5] != b'\x1bLuaQ':
        return {'error': 'not HKS/LuaQ', 'functions': [], 'count': 0}
    tree, end, err = _parse_proto_tree(d)
    funcs = []
    for rec in tree:
        code = [_u(d, rec['code_start'] + 4*k, 4) for k in range(rec['sizecode'])]
        funcs.append({
            'index': rec['index'], 'depth': rec['depth'], 'parent': rec['parent'],
            'children': rec['children'],
            'header_off': f"{rec['header_off']:#x}", 'code_start': f"{rec['code_start']:#x}",
            'sizecode': rec['sizecode'], 'params': rec['params'], 'upvals': rec['upvals'],
            'vararg': rec['vararg'], 'registers': rec['registers'], 'sub_count': rec['sub_count'],
            'instructions': _disasm_fn(d, rec),
            'constants': [{'i': i, 'type': c[0], 'value': c[1]} for i, c in enumerate(rec['constants'])],
            'opcode_histogram': _hist(code),
        })
    return {'functions': funcs, 'count': len(funcs),
            'end_offset': (f'{end:#x}' if end is not None else None),
            'file_size': len(d), 'complete': (err is None and end == len(d)), 'error': err}
