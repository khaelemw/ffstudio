"""Resolve decompiled cross-namespace `NS::function_HEX` calls back to real names.

When ACTS decompiles a closed script it can't always name a function it calls in ANOTHER
namespace, so it emits `function_<hash>`. The linker then fails with
    Compiler Internal Error : Unresolved external 'NS::function_HEX'
because no function is literally named "function_HEX". But hasht7(realname) == 0xHEX, and
the base game source (share/raw) contains the real names — so we hash every function in the
#using'd namespaces and restore the name the compiler expects.

Local (same-namespace) function_HEX are left untouched: they are defined+called consistently
within the script and are fixed after the build by the hash remap step (gsc_remap).
"""
import os, re
from t7hash import hasht7

FUNC_DEF = re.compile(r'\bfunction\b[^\n(]*?\b(\w+)\s*\(')
# ACTS drops leading zeros, so hashes are 1-8 hex digits; the negative lookahead keeps us
# from swallowing a real identifier that merely begins with hex chars (e.g. function_beef_x).
CALL     = re.compile(r'(\w+)::function_([0-9a-fA-F]{1,8})(?![0-9a-zA-Z_])')

def _ns_index(src, raw_root):
    """{namespace: {hash: realname}} built from the base sources named by this file's #using."""
    idx = {}
    for m in re.finditer(r'#using\s+([^;]+);', src):
        rel = m.group(1).strip().replace('\\', os.sep).replace('/', os.sep)
        for ext in ('.gsc', '.csc', '.gsh'):
            f = os.path.join(raw_root, rel + ext)
            if not os.path.exists(f):
                continue
            txt = open(f, encoding='utf-8', errors='replace').read()
            nm = re.search(r'#namespace\s+(\w+)', txt)
            if not nm:
                continue
            d = idx.setdefault(nm.group(1), {})
            for fn in FUNC_DEF.findall(txt):
                d.setdefault(hasht7(fn), fn)
    return idx

def resolve(src, raw_root):
    """Return (new_src, still_unresolved_set). Renames every NS::function_HEX we can name."""
    idx = _ns_index(src, raw_root)
    unresolved = set()
    def repl(m):
        ns, hx = m.group(1), int(m.group(2), 16)
        real = idx.get(ns, {}).get(hx)
        if real:
            return f"{ns}::{real}"
        unresolved.add(f"{ns}::function_{m.group(2)}")
        return m.group(0)
    return CALL.sub(repl, src), unresolved
