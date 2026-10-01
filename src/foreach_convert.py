"""Convert GSC `foreach (VAL in ARR){...}` / `foreach (KEY, VAL in ARR){...}` into plain
`for` loops using getarraykeys(), so ACTS's compiler (which lacks foreach for BO3 but
preserves function_HEX hashes) can compile the script. Comment/string/brace aware.
Innermost-safe via repeated single-conversion passes with a global unique counter.
"""
import re

def _skip_regions(s):
    """Return a set-like predicate: positions inside strings/line/block comments."""
    mask = bytearray(len(s))  # 1 = code, 0 = string/comment (skip)
    i, n = 0, len(s)
    while i < n:
        c = s[i]
        if c == '/' and i+1 < n and s[i+1] == '/':
            while i < n and s[i] != '\n': i += 1
        elif c == '/' and i+1 < n and s[i+1] == '*':
            i += 2
            while i+1 < n and not (s[i] == '*' and s[i+1] == '/'): i += 1
            i += 2
        elif c == '"':
            i += 1
            while i < n and s[i] != '"':
                if s[i] == '\\': i += 1
                i += 1
            i += 1
        else:
            mask[i] = 1
            i += 1
    return mask

def _match(s, open_i, oc, cc, mask):
    """Given index of opening bracket oc at open_i, return index of matching cc."""
    depth = 0; i = open_i; n = len(s)
    while i < n:
        if mask[i]:
            if s[i] == oc: depth += 1
            elif s[i] == cc:
                depth -= 1
                if depth == 0: return i
        i += 1
    raise ValueError("unbalanced")

def convert_once(s, counter):
    mask = _skip_regions(s)
    # find a 'foreach' keyword in code
    for m in re.finditer(r'\bforeach\b', s):
        k = m.start()
        if not mask[k]:
            continue
        # find '(' after foreach
        p = s.index('(', m.end())
        close = _match(s, p, '(', ')', mask)
        head = s[p+1:close]  # "VAL in ARR" or "KEY, VAL in ARR"
        # split on last ' in ' (top level) — ARR may contain 'in'? rare; use regex on head
        mm = re.match(r'\s*(?:([A-Za-z_]\w*)\s*,\s*)?([A-Za-z_]\w*)\s+in\s+(.+)$', head, re.S)
        if not mm:
            raise ValueError(f"can't parse foreach head: {head!r}")
        key, val, arr = mm.group(1), mm.group(2), mm.group(3).strip()
        # find body { }
        b = s.index('{', close)
        bclose = _match(s, b, '{', '}', mask)
        body = s[b+1:bclose]
        c = counter[0]; counter[0] += 1
        keysv = f"_fe_keys_{c}"; iv = f"_fe_i_{c}"
        indent = ''
        ls = s.rfind('\n', 0, k)
        indent = s[ls+1:k]
        if key:
            assign = f"{indent}    {key} = {keysv}[{iv}];\n{indent}    {val} = {arr}[{key}];\n"
        else:
            assign = f"{indent}    {val} = {arr}[{keysv}[{iv}]];\n"
        repl = (f"{keysv} = getarraykeys({arr});\n"
                f"{indent}for ({iv} = 0; {iv} < {keysv}.size; {iv}++)\n"
                f"{indent}{{\n{assign}{body}}}")
        return s[:k] + repl + s[bclose+1:], True
    return s, False

def convert(src):
    counter = [0]
    changed = True
    while changed:
        src, changed = convert_once(src, counter)
    return src, counter[0]
