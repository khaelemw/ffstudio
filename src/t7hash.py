M32 = 0xFFFFFFFF
M64 = 0xFFFFFFFFFFFFFFFF

def _lowerc(ch):
    o = ord(ch)
    if 0x41 <= o <= 0x5A:   # A-Z -> a-z
        return o + 0x20
    if ch == '\\':
        return ord('/')
    return o

def hasht7(s):
    """T7/BO3 script identifier hash (ACTS hash::HashT7):
    64-bit FNV-1a (iv 0x4B9ACE2F, prime 0x1000193, lowercased), take low 32, then *0x1000193."""
    h = 0x4B9ACE2F
    for ch in s:
        c = _lowerc(ch) & 0xFF
        h = ((h ^ c) * 0x1000193) & M64
    pre = h & M32
    return (pre * 0x1000193) & M32
