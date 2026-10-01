"""T7 (BO3) .xpak ("KAPI") container reader.

An .xpak holds the streamed data a fastfile references: high-resolution image mips, mesh buffers and sound.

FORMAT (little-endian):
  Header (0x40):
    +0x00 magic 'KAPI' (4b 41 50 49) + u16 version (0x0a)
    +0x08 u64 flags(=1)
    +0x10 u64 fileSize
    +0x18 u64 hashCount
    +0x20 u64 dataOffset      (typically 0x8000)
    +0x28 u64 dataSize
    +0x30 u64 entryCount
    +0x38 u64 entryTableOffset
  Entry table: entryCount * 0x18  -> {u64 hash, u64 offset (relative to dataOffset), u64 size}
  Each entry's data begins with a 0x80 block header {u32 chunkCount, u32 runningOff, u32 chunkDesc[]} then the
  chunk payloads (contiguous). An entry's `size` covers header + all chunks; the un-chunked payload is the
  asset's streamed bytes (usually the base/top mip of an image).

COMPRESSION: every xpak (mod and retail) uses the same block layout. Each 0x40000-byte decompressed block
starts with a 0x80 header:
  {u32 chunkCount, u32 runningDecompOffset, u32 chunkDesc[chunkCount]}   chunkDesc = (codec << 24) | compSize
The chunks follow contiguously and each decompresses to 0x7ff0 bytes. codec 0 = raw (copied as-is; mod xpaks use
this), codec 3 = LZ4 block format (no frame header).

IMAGE -> ENTRY MAPPING: a GfxImage stores one stream hash per mip (u64 at +0x08/+0x30/+0x58/+0x80/...), and
each hash is an xpak entry key. Entries are looked up by hash, never by size, since different images can
share the same dimensions.
"""
import struct

def parse_header(d):
    u = lambda o: int.from_bytes(d[o:o+8], 'little')
    assert d[:4] == b'KAPI', "not a KAPI/xpak file"
    return dict(version=int.from_bytes(d[4:6],'little'), fileSize=u(0x10), hashCount=u(0x18),
                dataOffset=u(0x20), dataSize=u(0x28), entryCount=u(0x30), entryTableOffset=u(0x38))

def entries(d, h=None):
    h = h or parse_header(d); u = lambda o: int.from_bytes(d[o:o+8], 'little')
    et = h['entryTableOffset']
    return [dict(hash=u(et+i*0x18), offset=u(et+i*0x18+8), size=u(et+i*0x18+0x10)) for i in range(h['entryCount'])]

BLOCK = 0x40000   # xpak stores an entry's data in 0x40000-byte blocks, each led by a 0x80 chunk header
BLOCK_HDR = 0x80  # {u32 chunkCount, ...chunkSizes...} + zero pad to 0x80; the 0x3ff80 data follows

try:
    import lz4.block as _lz4blk               # fast C decoder if installed
    def _lz4_decompress(chunk): return _lz4blk.decompress(chunk, uncompressed_size=BLOCK)
except Exception:
    def _lz4_decompress(chunk):                # pure-python LZ4 block fallback (no dependency)
        out = bytearray(); i = 0; n = len(chunk)
        while i < n:
            tok = chunk[i]; i += 1
            lit = tok >> 4
            if lit == 15:
                while True:
                    b = chunk[i]; i += 1; lit += b
                    if b != 255: break
            out += chunk[i:i+lit]; i += lit
            if i >= n: break
            off = chunk[i] | (chunk[i+1] << 8); i += 2
            ml = (tok & 15) + 4
            if (tok & 15) == 15:
                while True:
                    b = chunk[i]; i += 1; ml += b
                    if b != 255: break
            s = len(out) - off
            for k in range(ml): out.append(out[s+k])
        return bytes(out)

def entry_raw(d, e, h=None):
    """Return the entry's de-chunked, decompressed payload (raw mod xpaks and LZ4-compressed retail xpaks).
    Each block is [0x80 header {u32 chunkCount, u32 offset, u32 (codec<<24|size)[]}][chunks]; codec 0 chunks are
    copied as-is and codec 3 chunks are LZ4-block-decompressed."""
    h = h or parse_header(d)
    base = h['dataOffset'] + e['offset']; end = base + e['size']
    out = bytearray(); o = base
    while o < end:
        cc = int.from_bytes(d[o:o+4], 'little')      # u32 chunkCount; d[o+4:o+8] is a running decompressed offset
        if not (0 < cc <= 30):
            # not the block-descriptor header (old raw single-block or trailing pad) — fall back to header strip
            if o == base: return bytes(d[base+BLOCK_HDR : end])
            break
        descs = [int.from_bytes(d[o+8+4*i:o+12+4*i], 'little') for i in range(cc)]
        p = o + BLOCK_HDR
        for v in descs:
            codec = v >> 24; sz = v & 0xFFFFFF
            if sz == 0 or p + sz > end: break
            ch = bytes(d[p:p+sz])
            if codec == 0: out += ch
            else:
                try: out += _lz4_decompress(ch)
                except Exception: return bytes(out)
            p += sz
        o = p
    return bytes(out)

def is_raw(d, e, h=None):
    """Heuristic: RAW chunk data has very few distinct byte values in a window (solid/BC blocks); a
    compressed chunk is ~uniformly high-entropy."""
    seg = entry_raw(d, e, h)[:0x1000]
    return len(set(seg)) < 200 if seg else False

# ---- DDS (DX10) writer ----
_DXGI = {'BC1':71,'BC3':77,'BC5':83,'BC7':98}
def dds(w, h, fmt, px):
    hdr = struct.pack('<4sIIIIIII44s', b'DDS ',124,0x1|0x2|0x4|0x1000|0x80000, h, w, max(1,(w+3)//4)*16,0,1,b'\0'*44)
    pf  = struct.pack('<II4sIIIII',32,0x4,b'DX10',0,0,0,0,0)
    return hdr+pf+struct.pack('<IIIII',0x1000,0,0,0,0)+struct.pack('<IIIII',_DXGI.get(fmt,98),3,0,1,0)+px
