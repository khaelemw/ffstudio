"""HKS bytecode -> readable pseudo-Lua, built on hks_disasm.

Tracks registers to rebuild statements using the T7/T8 operand semantics (as in CoDHVKDecompiler): resolves
constants, globals and fields, rebuilds calls with their argument and return lists, and links closures to their
child functions. Single-use temporaries are folded into their consumer when nothing with side effects sits
in between.

Limits:
  * Control flow is shown as labels and gotos (`if <cond> then goto L_n end`, `::L_n::`), not rebuilt into
    if/else/while/for blocks. Locals are not named.
  * Opcodes without known semantics (INTRINSIC_*, SETSLOT*/GETSLOT*, CHECKTYPE*, NEWSTRUCT, CALL_C/CALL_M,
    TAILCALL_C/M, GETTABLE_N, SETTABLE_N*/_BK, GETFIELD_MM) are emitted as `-- <raw disasm>` comments.

Public API:
  decompile_function(d, rec)   -> list[str] source lines for one proto-tree record (from hks_disasm)
  decompile_all(d)             -> {'functions':[{index,depth,parent,header,source:[...] }...], ...}
"""
import hks_disasm as H

_ARITH = H._ARITH; _BINSYM = H._BINSYM; _CMPSYM = H._CMPSYM
_KBX = H._KBX; _FIELD_C = H._FIELD_C; _FIELD_B = H._FIELD_B
OPCODES = H.OPCODES

# opcodes with no reference semantics -> render raw, never guess
_RAW = {'CALL_C', 'CALL_M', 'TAILCALL_C', 'TAILCALL_M', 'GETTABLE_N', 'SETTABLE_N', 'SETTABLE_N_BK',
        'SETTABLE_BK', 'GETFIELD_MM', 'NEWSTRUCT', 'INTRINSIC_INDEX', 'INTRINSIC_NEWINDEX',
        'INTRINSIC_SELF', 'INTRINSIC_INDEX_LITERAL', 'INTRINSIC_NEWINDEX_LITERAL', 'INTRINSIC_SELF_LITERAL',
        'SETSLOTN', 'SETSLOTI', 'SETSLOT', 'SETSLOTS', 'SETSLOTMT', 'CHECKTYPE', 'CHECKTYPES', 'GETSLOT',
        'GETSLOTMT', 'SELFSLOT', 'SELFSLOTMT', 'CHECKTYPE_D', 'GETSLOT_D'}

def _sent(r): return f'\x00{r}\x00'                       # register-reference sentinel (for inlining)

def _lit(c):
    """Lua literal text for a constant tuple (type,value)."""
    t, v = c
    if t == 'str': return _qstr(v)
    if t == 'nil': return 'nil'
    if t == 'bool': return 'true' if v else 'false'
    if t == 'num':
        return str(int(v)) if float(v).is_integer() else repr(v)
    return repr(v)

def _qstr(s):
    return '"' + s.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n') + '"'

def _field_key(name):
    """Render a constant field key as `.name` if it's a valid identifier, else `["name"]`."""
    import re
    if isinstance(name, str) and re.match(r'^[A-Za-z_][A-Za-z0-9_]*$', name):
        return '.' + name
    return '[' + (_qstr(name) if isinstance(name, str) else str(name)) + ']'

class _Stmt:
    __slots__ = ('i', 'kind', 'dest', 'rhs', 'text', 'reads', 'writes', 'side', 'atomic', 'label', 'ctl')
    def __init__(self, i, kind, text='', dest=None, rhs=None, reads=(), writes=(), side=False, atomic=False):
        self.i = i; self.kind = kind; self.text = text; self.dest = dest; self.rhs = rhs
        self.reads = list(reads); self.writes = list(writes); self.side = side; self.atomic = atomic
        self.label = None            # jump/for target instruction index (control ops)
        self.ctl = None              # control tag: 'jmp'|'test'|'forprep'|'forloop'|'tforloop'

def _build(d, rec):
    """Decode each instruction of one function into a _Stmt with sentinel-encoded register refs."""
    cs = rec['code_start']; ic = rec['sizecode']; K = rec['constants']; kids = rec.get('children', [])
    def kconst(idx): return _lit(K[idx]) if 0 <= idx < len(K) else f'K{idx}?'
    def kfield(idx): return _field_key(K[idx][1]) if (0 <= idx < len(K) and K[idx][0] == 'str') else \
                            ('[' + kconst(idx) + ']')
    stmts = []; targets = set()
    for i in range(ic):
        w = H._u(d, cs + 4*i, 4)
        op, A, B, C, Bx, sBx, ec = H._decode(w)
        nm = OPCODES[op] if op < len(OPCODES) else f'OP_{op}'
        R = _sent
        def rk(c): return kconst(c) if ec else R(c)            # RK(C)
        raw = f'-- {i:3}: {H._render(nm, A, B, C, Bx, sBx, K, ec)}'
        s = None
        if nm in _RAW or nm.startswith('OP_'):
            s = _Stmt(i, 'raw', text=raw)
        elif nm == 'LOADK':
            s = _Stmt(i, 'set', dest=A, rhs=kconst(Bx), writes=[A], atomic=True)
        elif nm == 'LOADNIL':
            s = _Stmt(i, 'stmt', text='; '.join(f'r{r} = nil' for r in range(A, B+1)), writes=list(range(A, B+1)))
        elif nm == 'LOADBOOL':
            s = _Stmt(i, 'set', dest=A, rhs=('true' if B else 'false'), writes=[A], atomic=True)
        elif nm in ('GETGLOBAL', 'GETGLOBAL_MEM'):
            s = _Stmt(i, 'set', dest=A, rhs=(K[Bx][1] if 0 <= Bx < len(K) and K[Bx][0] == 'str' else f'_G[{kconst(Bx)}]'),
                      writes=[A], atomic=True)
        elif nm == 'SETGLOBAL':
            g = (K[Bx][1] if 0 <= Bx < len(K) and K[Bx][0] == 'str' else f'_G[{kconst(Bx)}]')
            s = _Stmt(i, 'stmt', text=f'{g} = {R(A)}', reads=[A], side=True)
        elif nm == 'MOVE':
            s = _Stmt(i, 'set', dest=A, rhs=R(B), reads=[B], writes=[A], atomic=True)
        elif nm == 'GETUPVAL':
            s = _Stmt(i, 'set', dest=A, rhs=f'upval[{B}]', writes=[A], atomic=True)
        elif nm in ('SETUPVAL', 'SETUPVAL_R1'):
            s = _Stmt(i, 'stmt', text=f'upval[{B}] = {R(A)}', reads=[A], side=True)
        elif nm in _FIELD_C:                                    # GETFIELD/_R1 : R(A)=R(B)[K[C]]
            s = _Stmt(i, 'set', dest=A, rhs=f'{R(B)}{kfield(C)}', reads=[B], writes=[A], atomic=True)
        elif nm in _FIELD_B:                                    # SETFIELD/_R1 : R(A)[K[B]]=RK(C)
            s = _Stmt(i, 'stmt', text=f'{R(A)}{kfield(B)} = {rk(C)}',
                      reads=[A] + ([] if ec else [C]), side=True)
        elif nm in ('GETTABLE_S', 'GETTABLE'):
            s = _Stmt(i, 'set', dest=A, rhs=f'{R(B)}[{rk(C)}]', reads=[B] + ([] if ec else [C]),
                      writes=[A], atomic=True)
        elif nm in ('SETTABLE_S', 'SETTABLE'):
            s = _Stmt(i, 'stmt', text=f'{R(A)}[{R(B)}] = {rk(C)}',
                      reads=[A, B] + ([] if ec else [C]), side=True)
        elif nm == 'SETTABLE_S_BK':
            s = _Stmt(i, 'stmt', text=f'{R(A)}[{kconst(B)}] = {rk(C)}', reads=[A] + ([] if ec else [C]), side=True)
        elif nm == 'NEWTABLE':
            s = _Stmt(i, 'set', dest=A, rhs='{}', writes=[A], atomic=True)
        elif nm == 'SELF':                                      # R(A+1)=R(B); R(A)=R(B)[RK(C)]
            s = _Stmt(i, 'stmt', text=f'r{A+1} = {R(B)}; r{A} = {R(B)}[{rk(C)}]',
                      reads=[B] + ([] if ec else [C]), writes=[A, A+1])
        elif nm in _ARITH:
            s = _Stmt(i, 'set', dest=A, rhs=f'{R(B)} {_BINSYM[nm]} {rk(C)}',
                      reads=[B] + ([] if ec else [C]), writes=[A])
        elif nm.endswith('_BK') and nm[:-3] in _ARITH:
            s = _Stmt(i, 'set', dest=A, rhs=f'{kconst(B)} {_BINSYM[nm[:-3]]} {R(C)}', reads=[C], writes=[A])
        elif nm in ('UNM', 'NOT', 'NOT_R1', 'LEN'):
            u = {'UNM': '-', 'NOT': 'not ', 'NOT_R1': 'not ', 'LEN': '#'}[nm]
            s = _Stmt(i, 'set', dest=A, rhs=f'{u}{R(B)}', reads=[B], writes=[A])
        elif nm == 'CONCAT':
            s = _Stmt(i, 'set', dest=A, rhs=' .. '.join(R(r) for r in range(B, C+1)),
                      reads=list(range(B, C+1)), writes=[A])
        elif nm in ('CALL_I', 'CALL', 'CALL_I_R1'):
            args = 'top' if B == 0 else ', '.join(R(r) for r in range(A+1, A+B))
            reads = [A] + ([] if B == 0 else list(range(A+1, A+B)))
            call = f'{R(A)}({"..." if B == 0 else args})'
            if C == 1:                                           # 0 returns -> pure statement
                s = _Stmt(i, 'stmt', text=call, reads=reads, side=True)
            elif C == 0:                                         # multi-return
                s = _Stmt(i, 'stmt', text=f'r{A}, ... = {call}  -- multiret', reads=reads, writes=[A], side=True)
            else:
                dests = list(range(A, A+C-1))
                s = _Stmt(i, 'stmt', text=f'{", ".join("r"+str(x) for x in dests)} = {call}',
                          reads=reads, writes=dests, side=True)
        elif nm in ('TAILCALL', 'TAILCALL_I', 'TAILCALL_I_R1'):
            args = '...' if B == 0 else ', '.join(R(r) for r in range(A+1, A+B))
            reads = [A] + ([] if B == 0 else list(range(A+1, A+B)))
            s = _Stmt(i, 'stmt', text=f'return {R(A)}({args})', reads=reads, side=True)
        elif nm == 'RETURN':
            if B == 0:
                s = _Stmt(i, 'stmt', text=f'return {R(A)}, ...  -- multiret', reads=[A], side=True)
            elif B == 1:
                s = _Stmt(i, 'stmt', text='return', side=True)
            else:
                rs = list(range(A, A+B-1))
                s = _Stmt(i, 'stmt', text='return ' + ', '.join(R(r) for r in rs), reads=rs, side=True)
        elif nm == 'CLOSURE':
            child = kids[Bx] if 0 <= Bx < len(kids) else None
            ref = f'function#{child}' if child is not None else f'proto#{Bx}'
            s = _Stmt(i, 'set', dest=A, rhs=ref, writes=[A], atomic=True)
        elif nm == 'VARARG':
            if B == 0:
                s = _Stmt(i, 'set', dest=A, rhs='...', writes=[A], atomic=True)
            else:
                rs = list(range(A, A+B))
                s = _Stmt(i, 'stmt', text=', '.join('r'+str(r) for r in rs) + ' = ...', writes=rs)
        elif nm == 'JMP':
            tgt = i + 1 + sBx; targets.add(tgt)
            s = _Stmt(i, 'jump', text=f'goto L_{tgt}', side=True); s.label = tgt; s.ctl = 'jmp'
        elif nm in ('FORPREP', 'FORLOOP'):
            tgt = i + 1 + sBx; targets.add(tgt)
            s = _Stmt(i, 'stmt', text=(f'-- numeric for prep; goto L_{tgt}' if nm == 'FORPREP'
                       else f'r{A+3} = r{A}; if for-continue then goto L_{tgt} end'), reads=[A], side=True)
            s.label = tgt; s.dest = A; s.ctl = 'forprep' if nm == 'FORPREP' else 'forloop'
        elif nm in ('EQ', 'LT', 'LE'):                          # cmp: paired with the JMP at i+1; rhs = "goto i+2" cond
            sym = _CMPSYM[nm][A & 1]
            s = _Stmt(i, 'branch', rhs=f'{R(B)} {sym} {rk(C)}', reads=[B] + ([] if ec else [C]), side=True)
            s.ctl = 'cmp'
        elif nm[:-3] in ('EQ', 'LT', 'LE') and nm.endswith('_BK'):
            sym = _CMPSYM[nm[:-3]][A & 1]
            s = _Stmt(i, 'branch', rhs=f'{kconst(B)} {sym} {R(C)}', reads=[C], side=True); s.ctl = 'cmp'
        elif nm in ('TEST', 'TEST_R1'):                         # guard: skips ONLY instr i+1; rhs = "execute i+1" cond
            s = _Stmt(i, 'branch', rhs=(f'r{A}' if C else f'not r{A}'), reads=[A], side=True); s.ctl = 'guard'
        elif nm == 'TESTSET':
            s = _Stmt(i, 'branch', rhs=(f'r{B}' if C else f'not r{B}'), reads=[B], side=True); s.ctl = 'guard'
        elif nm == 'TFORLOOP':
            nvar = C if C else 1
            s = _Stmt(i, 'stmt', text=f'-- generic-for iterate r{A}(); results r{A+3}..', reads=[A], side=True)
            s.dest = A; s.writes = list(range(A+3, A+3+nvar)); s.ctl = 'tforloop'
        elif nm == 'DATA':
            s = _Stmt(i, 'nop', text=raw)                       # closure-upvalue binding / pad (shown in disasm)
        elif nm == 'CLOSE':
            s = _Stmt(i, 'stmt', text=f'-- close upvalues >= r{A}', side=True)
        else:
            s = _Stmt(i, 'raw', text=raw)
        stmts.append(s)
    return stmts, targets, ic

def _basic_blocks(stmts, targets, ic):
    """Leaders = index 0, any jump/branch target, and the instruction after any jump/branch."""
    leaders = {0}
    for s in stmts:
        if s.kind in ('jump', 'branch') or (s.kind == 'stmt' and s.label is not None):
            leaders.add(s.i + 1)
            if s.ctl in ('cmp', 'guard'): leaders.add(s.i + 2)   # both skip to i+2
            if s.label is not None: leaders.add(s.label)
    leaders = {l for l in leaders if 0 <= l < ic}
    block_of = {}
    cur = 0
    for i in range(ic):
        if i in leaders: cur = i
        block_of[i] = cur
    return block_of

def _inline(stmts, block_of):
    """Fold a pure def into its consumer using proper def->use LIVE RANGES, so reassigned registers fold too
    (e.g. r=CoD; r=r.Zombie; r=r.Foo; r(a) -> CoD.Zombie.Foo(a)). A def of r at idx is inlined iff, within its
    live range (idx+1 .. the next statement that writes r, inclusive — that statement reads r before overwriting),
    r is used EXACTLY once, that use is in the same basic block, and between def and use there is no side-effecting
    statement and no rewrite of the def's own inputs (keeps table-read / call ordering correct)."""
    def refs(s): return (s.rhs or '') + (s.text or '')
    live = stmts[:]
    changed = True
    while changed:
        changed = False
        for idx, dstmt in enumerate(live):
            if dstmt.kind != 'set' or dstmt.side or dstmt.dest is None: continue
            r = dstmt.dest
            nd = None                                   # next redefinition of r
            for j in range(idx+1, len(live)):
                if r in live[j].writes: nd = j; break
            hi = nd if nd is not None else len(live)-1
            uses = [j for j in range(idx+1, hi+1) if _sent(r) in refs(live[j])]
            if len(uses) != 1: continue                 # not single-use within its live range
            ui = uses[0]; u = live[ui]
            if block_of.get(dstmt.i) != block_of.get(u.i): continue
            between = live[idx+1:ui]
            if any(b.side for b in between): continue
            din = set(dstmt.reads)
            if any(din & set(b.writes) for b in between): continue
            expr = dstmt.rhs if dstmt.atomic else f'({dstmt.rhs})'
            if u.rhs is not None: u.rhs = u.rhs.replace(_sent(r), expr)
            if u.text: u.text = u.text.replace(_sent(r), expr)
            u.reads = [x for x in u.reads if x != r] + dstmt.reads
            live.pop(idx)
            changed = True
            break
    return live

import re as _re
def _finalize(text, names=None):
    """Resolve register sentinels to names: a scoped `names` map (loop vars) wins, else rN."""
    names = names or {}
    return _re.sub('\x00(\\d+)\x00', lambda m: names.get(int(m.group(1)), 'r' + m.group(1)), text)

def _render_line(s, names=None):
    """Render one surviving (post-inline) statement to a source line, or None to omit (nop/pad)."""
    if s.kind == 'set':
        d = names.get(s.dest, f'r{s.dest}') if names else f'r{s.dest}'
        return _finalize(f'{d} = {s.rhs}', names)
    if s.kind in ('stmt', 'jump'):    return _finalize(s.text, names)
    if s.kind == 'raw':               return s.text
    if s.kind == 'branch':            return _finalize(f'if {s.rhs} then goto L_{s.i+2} end', names)  # fallback only
    return None                       # nop

# ---- structuring: build a node tree over instruction indices, fall back to goto where unmatched ----
def _structure(stmts, ic):
    """Return (nodes, fallback_targets). Nodes: ('lines',[i..]) ('if',ci,then,else|None) ('while',ci,body)
    ('numfor',pi,body) ('genfor',ji,tf,body) ('goto',i,tgt). Only clean, single-entry reducible patterns are
    structured; anything else degrades to a ('goto',...) leaf (always correct)."""
    fb = set()                        # fallback goto targets that need a ::label::
    def ctl(i): return stmts[i].ctl if 0 <= i < ic else None
    def build(lo, hi, depth):
        nodes = []; i = lo; run = []
        def flush():
            if run: nodes.append(('lines', run[:])); run.clear()
        if depth > 400:               # guard against pathological recursion
            flush()
            for j in range(i, hi): run.append(j)
            flush(); return nodes
        while i < hi:
            c = ctl(i)
            if c is None:
                run.append(i); i += 1; continue
            if c == 'forprep':
                F = stmts[i].label                       # FORLOOP index (loop end)
                if i < F <= hi and ctl(F) == 'forloop':
                    flush(); nodes.append(('numfor', i, build(i+1, F, depth+1))); i = F + 1; continue
                flush(); nodes.append(('goto', i, F)); fb.add(F); i += 1; continue
            if c == 'forloop':                           # bare FORLOOP (numfor consumed its own) -> back-edge
                flush(); nodes.append(('goto', i, stmts[i].label)); fb.add(stmts[i].label); i += 1; continue
            if c == 'jmp':
                T = stmts[i].label
                # generic for: JMP -> TFORLOOP at T, with back-JMP at T+1 to i+1
                if i < T < hi and ctl(T) == 'tforloop' and ctl(T+1) == 'jmp' and stmts[T+1].label == i+1:
                    flush(); nodes.append(('genfor', i, T, build(i+1, T, depth+1))); i = T + 2; continue
                # otherwise an unstructured jump -> fallback
                flush(); nodes.append(('goto', i, T)); fb.add(T); i += 1; continue
            if c == 'guard':                             # TEST/TESTSET: skips only instr i+1 (no paired JMP)
                flush(); nodes.append(('guard', i, i+2)); fb.add(i+2); i += 1; continue
            if c == 'cmp':                               # EQ/LT/LE: paired with the JMP at i+1
                jmp = stmts[i+1] if i+1 < ic else None
                if jmp is None or jmp.ctl != 'jmp':
                    flush(); nodes.append(('goto', i, i+2)); fb.add(i+2); i += 1; continue
                T = jmp.label                            # condition-fails target
                if T <= i or T > hi:                      # backward / escaping -> not a clean forward if
                    flush(); nodes.append(('cmpgoto', i, T)); fb.add(T); fb.add(i+2); i += 1; continue
                last = T - 1
                if last >= i+2 and ctl(last) == 'jmp' and stmts[last].label == i:
                    flush(); nodes.append(('while', i, build(i+2, last, depth+1))); i = T; continue
                if last >= i+2 and ctl(last) == 'jmp' and i < stmts[last].label <= hi and stmts[last].label > T:
                    E = stmts[last].label                # if/else
                    flush(); nodes.append(('if', i, build(i+2, last, depth+1), build(T, E, depth+1)))
                    i = E; continue
                flush(); nodes.append(('if', i, build(i+2, T, depth+1), None)); i = T; continue
            # forloop/tforloop reached standalone (not consumed) -> fallback line
            flush(); nodes.append(('goto', i, stmts[i].label if stmts[i].label is not None else i+1))
            if stmts[i].label is not None: fb.add(stmts[i].label)
            i += 1
        flush(); return nodes
    return build(0, ic, 0), fb

_NUMVAR = ['i', 'j', 'k', 'l', 'm', 'n']            # numeric-for counter names by nesting depth

def _emit_nodes(nodes, keep, fb, indent, out, names=None, loopdepth=0):
    ind = '  ' * indent
    names = names or {}
    def lbl(i):
        if i in fb: out.append(ind + f'::L_{i}::')
    for node in nodes:
        kind = node[0]
        if kind == 'lines':
            for i in node[1]:
                lbl(i)
                s = keep.get(i)
                if s is not None:
                    ln = _render_line(s, names)
                    if ln is not None: out.append(ind + ln)
        elif kind == 'goto':
            _, i, tgt = node
            lbl(i)
            out.append(ind + f'goto L_{tgt}')
        elif kind == 'cmpgoto':                          # unstructured comparison: rhs = "skip the JMP" cond
            _, i, tgt = node
            lbl(i)
            out.append(ind + _finalize(f'if {keep[i].rhs} then goto L_{i+2} end', names))
        elif kind == 'guard':                            # TEST/TESTSET: rhs = "execute i+1" cond; skip when NOT it
            _, i, tgt = node
            lbl(i)
            rhs = keep[i].rhs
            neg = rhs[4:] if rhs.startswith('not ') else f'not ({rhs})'   # not(not x) -> x
            out.append(ind + _finalize(f'if {neg} then goto L_{i+2} end', names))
        elif kind == 'if':
            _, ci, then_n, else_n = node
            lbl(ci)
            cond = _finalize(keep[ci].rhs, names) if ci in keep and keep[ci].rhs else 'cond?'
            out.append(ind + f'if {cond} then')
            _emit_nodes(then_n, keep, fb, indent+1, out, names, loopdepth)
            if else_n is not None:
                out.append(ind + 'else')
                _emit_nodes(else_n, keep, fb, indent+1, out, names, loopdepth)
            out.append(ind + 'end')
        elif kind == 'while':
            _, ci, body = node
            lbl(ci)
            cond = _finalize(keep[ci].rhs, names) if ci in keep and keep[ci].rhs else 'cond?'
            out.append(ind + f'while {cond} do')
            _emit_nodes(body, keep, fb, indent+1, out, names, loopdepth)
            out.append(ind + 'end')
        elif kind == 'numfor':
            _, pi, body = node
            A = keep[pi].dest
            var = _NUMVAR[loopdepth % len(_NUMVAR)] + ('' if loopdepth < len(_NUMVAR) else str(loopdepth))
            inner = dict(names); inner[A+3] = var          # counter is scoped to the loop body
            start, limit, step = (_finalize(_sent(A), names), _finalize(_sent(A+1), names), _finalize(_sent(A+2), names))
            out.append(ind + f'for {var} = {start}, {limit}, {step} do')
            _emit_nodes(body, keep, fb, indent+1, out, inner, loopdepth+1)
            out.append(ind + 'end')
        elif kind == 'genfor':
            _, ji, tf, body = node
            A = keep[tf].dest; vregs = keep[tf].writes or [A+3]
            vnames = _genfor_varnames(keep, tf, A, len(vregs))
            inner = dict(names)
            for reg, nm in zip(vregs, vnames): inner[reg] = nm  # loop vars scoped to the body
            iexpr = ', '.join(_finalize(_sent(A+j), names) for j in range(3))
            out.append(ind + f'for {", ".join(vnames)} in {iexpr} do')
            _emit_nodes(body, keep, fb, indent+1, out, inner, loopdepth+1)
            out.append(ind + 'end')

def _genfor_varnames(keep, tf, A, nvar):
    """Name generic-for loop vars grounded in the iterator when known: pairs/next -> k,v; ipairs -> i,v;
    otherwise neutral positional v1,v2,... (real names are stripped from the bytecode)."""
    # find the setup statement that wrote A (the iterator function), the last one before the TFORLOOP
    setup = None
    for s in keep.values():
        if s.writes and A in s.writes and s.i < tf: setup = s
    txt = (setup.text or setup.rhs or '') if setup else ''
    low = txt.lower()
    if 'pairs' in low and 'ipairs' not in low: base = ['k', 'v']
    elif 'ipairs' in low: base = ['i', 'v']
    elif 'next' in low: base = ['k', 'v']
    else: base = None
    if base and nvar <= 2:
        return base[:nvar]
    return [f'v{j+1}' for j in range(nvar)]              # neutral: real names not recoverable

def decompile_function(d, rec):
    """Return reconstructed pseudo-Lua source lines for one proto-tree record (structured; goto fallback)."""
    try:
        stmts, targets, ic = _build(d, rec)
        block_of = _basic_blocks(stmts, targets, ic)
        live = _inline(stmts, block_of)
        keep = {s.i: s for s in live}
        nodes, fb = _structure(stmts, ic)
        out = []
        _emit_nodes(nodes, keep, fb, 0, out)
    except Exception as e:
        # any structuring failure -> safe linear label/goto fallback
        try:
            out = _emit_linear_fallback(live, ic)
        except Exception:
            return [f'-- decompile error: {e}']
    params = rec.get('params', 0); va = rec.get('vararg', 0)
    sig = ', '.join(f'a{k}' for k in range(params))
    if va: sig = (sig + ', ...') if sig else '...'
    head = f'function #{rec.get("index","?")}({sig})'
    return [head] + ['  ' + l for l in out] + ['end']

def _emit_linear_fallback(live, ic):
    """Faithful non-structured emit: labels for every jump target + inline branch/goto."""
    targets = set()
    for s in live:
        if s.ctl in ('jmp', 'forprep', 'forloop') and s.label is not None: targets.add(s.label)
        if s.ctl == 'test': targets.add(s.i + 2)
    lines = []
    for s in live:
        if s.i in targets: lines.append(f'::L_{s.i}::')
        if s.kind == 'branch':
            lines.append(_finalize(f'if {s.rhs} then goto L_{s.i+2} end')); targets.add(s.i + 2)
        else:
            ln = _render_line(s)
            if ln is not None: lines.append(ln)
    return lines

def decompile_all(d):
    """Decompile every function in the HKS chunk. Returns {'functions':[...], 'count', 'complete'}."""
    pt = H.disassemble_all(d)
    if pt.get('error') and not pt.get('functions'):
        return {'error': pt.get('error'), 'functions': [], 'count': 0}
    # rebuild layout records (disassemble_all returns rendered dicts; we need code_start/constants)
    tree, end, err = H._parse_proto_tree(d)
    funcs = []
    for rec in tree:
        funcs.append({
            'index': rec['index'], 'depth': rec['depth'], 'parent': rec['parent'],
            'children': rec['children'], 'code_start': f"{rec['code_start']:#x}",
            'params': rec['params'], 'upvals': rec['upvals'], 'registers': rec['registers'],
            'source': decompile_function(d, rec),
        })
    return {'functions': funcs, 'count': len(funcs),
            'complete': (err is None and end == len(d)), 'error': err}
