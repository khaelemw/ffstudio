"""Minimal T7 asset classifiers used by the grow engine.

This file is loaded by `grow_engine._fwalk_ns()` via exec() with the module globals `pay` (the decompressed
fastfile payload) and `N` (its length) injected by the caller, then its `is_mesh` / `is_scr` classifiers are
called to locate the leading mesh run and the first script while planning a grow-splice. Kept as a standalone
exec'd file (rather than a normal import) so the classifiers can run against an arbitrary payload the caller
supplies, without the module holding any state of its own.
"""
F = 0xFFFFFFFFFFFFFFFF
pay = None          # set by the caller (grow_engine) before the classifiers are used
N = 0               # len(pay), set by the caller
u = lambda p, n: int.from_bytes(pay[p:p + n], 'little')

def vname(q, mx=120, minlen=3):
    """Read a plausible inline asset name at offset q (printable, name-ish charset), or None."""
    e = q
    while e < N and 32 <= pay[e] < 127 and e - q < mx:
        e += 1
    if e < N and pay[e] == 0 and e - q >= minlen:
        s = pay[q:e]
        if (65 <= s[0] <= 90 or 97 <= s[0] <= 122 or s[0] in b'_$/') and \
           all(48 <= c <= 57 or 65 <= c <= 90 or 97 <= c <= 122 or c in b'_/-.$&:~# ' for c in s):
            return s.decode('latin1')
    return None

def is_scr(P):
    """ScriptParseTree header at P: name*(-1)@0, inline name @0x18 starting with 'scripts/'."""
    if u(P, 8) != F:
        return None
    nm = vname(P + 0x18)
    return nm if (nm and nm.startswith('scripts/')) else None

def is_mesh(P):
    """XModelSurfs header at P: name*(-1)@0, inline name @0x78, numSurfs @0x3C in 1..64, and the surfs/shared
    pointers @0x68/@0x70 are each -1 / 0 / a block-5 encoded pointer."""
    if u(P, 8) != F:
        return None
    nm = vname(P + 0x78)
    if not nm or not (1 <= pay[P + 0x3C] <= 64):
        return None
    sp = u(P + 0x68, 8); sh = u(P + 0x70, 8)
    return nm if ((sp == F or sp == 0 or (sp >> 60) == 5) and (sh == F or sh == 0 or (sh >> 60) == 5)) else None
