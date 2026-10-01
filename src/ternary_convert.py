"""Convert GSC ternary expressions `COND ? A : B` into `if/else`, because the T7 mod-tools GSC compiler
does NOT support the ternary operator (it rejects it even in a plain assignment). ACTS's
decompiler emits ternaries freely, so this is a required prep fixup alongside foreach_convert.

Strategy (SAFE-by-construction): only auto-convert statements whose ENTIRE right-hand side (or return value)
is a ternary chain, into an if / else-if / else:
    X = c1 ? a : c2 ? b : d;        ->   if (c1) X = a; else if (c2) X = b; else X = d;
    return c ? a : b;               ->   if (c) return a; else return b;
Anything else (a ternary embedded inside a larger expression, or with a ternary nested in a branch) is
LEFT UNCHANGED and counted in `remaining` so the caller can surface it for manual review — we never emit a
conversion that would change semantics. Comment/string aware. Ternaries in ACTS output are single-line.

convert(src) -> (new_src, n_converted, n_remaining)
"""
import re

def _code_mask(s):
    """1 where s[i] is code, 0 where inside a string / line- or block-comment (so we ignore '?' there)."""
    m = bytearray(len(s)); i, n = 0, len(s)
    while i < n:
        c = s[i]
        if c == '/' and i+1 < n and s[i+1] == '/':
            while i < n and s[i] != '\n': i += 1
        elif c == '/' and i+1 < n and s[i+1] == '*':
            i += 2
            while i+1 < n and not (s[i] == '*' and s[i+1] == '/'): m[i]=0; i += 1
            i += 2
        elif c == '"':
            i += 1
            while i < n and s[i] != '"':
                if s[i] == '\\': i += 1
                i += 1
            i += 1
        else:
            m[i] = 1; i += 1
    return m

def split_top_ternary(expr):
    """If expr contains a TOP-LEVEL (paren-depth 0) ternary, return (cond, a, b); b keeps any right-nested
    ternary chain. Returns None if there is no top-level ternary. String/comment aware within expr."""
    mask = _code_mask(expr)
    depth = 0; qi = -1
    for i, c in enumerate(expr):
        if not mask[i]: continue
        if c in '([{': depth += 1
        elif c in ')]}': depth -= 1
        elif c == '?' and depth == 0: qi = i; break
    if qi < 0: return None
    depth = 0; tern = 0; ci = -1
    for j in range(qi+1, len(expr)):
        if not mask[j]: continue
        c = expr[j]
        if c in '([{': depth += 1
        elif c in ')]}': depth -= 1
        elif depth == 0 and c == '?': tern += 1
        elif depth == 0 and c == ':':
            if tern == 0: ci = j; break
            tern -= 1
    if ci < 0: return None
    return expr[:qi].strip(), expr[qi+1:ci].strip(), expr[ci+1:].strip()

_ASSIGN = re.compile(r'^(\s*)([A-Za-z_][\w.\[\]"\'\s]*?)\s*(=|\+=|-=|\*=|/=|\|=|&=)\s*(.+?);\s*$')
_RETURN = re.compile(r'^(\s*)return\s+(.+?);\s*$')

def _emit_chain(indent, prefix_fmt, rhs):
    """prefix_fmt(value) -> the statement text assigning/returning `value`. Build if/else-if/else. Returns
    the block text, or None if a branch still contains a ternary (too complex -> leave for manual)."""
    lines = []; first = True; cur = rhs
    while True:
        t = split_top_ternary(cur)
        if t is None:
            kw = "" if first else "else "
            if split_top_ternary(cur) is not None: return None
            lines.append(f"{indent}{kw}{prefix_fmt(cur.strip())}")
            break
        cond, a, b = t
        if split_top_ternary(a) is not None: return None   # nested ternary in a branch -> manual
        kw = "if" if first else "else if"
        lines.append(f"{indent}{kw} ( {cond} ) {prefix_fmt(a.strip())}")
        first = False; cur = b
    out = "\n".join(lines)
    if ' ? ' in out: return None
    return out

def convert(src):
    lines = src.split('\n'); out = []; nconv = 0; nrem = 0
    for ln in lines:
        # quick reject: a real ternary needs ' ? ' and a ' : ' in code
        if ' ? ' not in ln:
            out.append(ln); continue
        m = _ASSIGN.match(ln)
        conv = None
        if m and split_top_ternary(m.group(4)) is not None:
            indent, lhs, op, rhs = m.groups()
            conv = _emit_chain(indent, (lambda v, L=lhs.strip(), O=op: f"{L} {O} {v};"), rhs)
        if conv is None:
            mr = _RETURN.match(ln)
            if mr and split_top_ternary(mr.group(2)) is not None:
                indent, rhs = mr.groups()
                conv = _emit_chain(indent, (lambda v: f"return {v};"), rhs)
        if conv is not None:
            out.append(conv); nconv += 1
        else:
            out.append(ln)
            # count residual ternaries on this line (embedded / nested branch) for reporting
            if split_top_ternary(re.sub(r'^\s*(return\s+|[^=]*=\s*)', '', ln.rstrip(';')) or '') is not None or ' ? ' in ln:
                nrem += 1
    return '\n'.join(out), nconv, nrem
