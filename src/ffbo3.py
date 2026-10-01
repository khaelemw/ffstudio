"""
BO3 (T7, version 0x251) fastfile decompress/recompress.
Format reverse-engineered from ate47/atian-cod-tools:
  decompressor_t78.cpp, compressor_t789_abstract.hpp, fastfile_data_tre.hpp

XFileBO3 header (0x248 bytes):
  0x00 magic[8]="TAff0000"; 0x08 version(u32)=0x251; 0x0C server(u8);
  0x0D compression(u8); 0x0E platform(u8); 0x0F encrypted(u8);
  0x10 timestamp(u64); 0x18 changelist(u32); 0x1C archiveChecksum[4](u32);
  0x2C builder[32]; 0x4C metaVersion(u32); 0x50 mergeFastfile[64];
  0x90 size(u64)=decompressed size; 0x98 externalSize(u64); 0xA0 memMappedOffset(u64);
  0xA8 blockSize[10](u64); 0xF8 fastfileName[64]; 0x138 signature[256]; 0x238 aesIV[16].

Block stream starts at 0x248. Each block:
  DBStreamHeader { u32 compressedSize; u32 uncompressedSize; u32 alignedSize; u32 offset }
  offset must == file position of this header.
  uncompressedSize==0 -> align file pos up to next 0x800000 and continue (segment marker/end).
  else read alignedSize bytes; raw-inflate compressedSize of them -> uncompressedSize out.
Compression: 1 => zlib (raw deflate, wbits=-15). 0 => none.
"""
import struct, zlib

HEADER_SIZE = 0x248
READ_SEGMENT = 0x800000
SIZE_OFF = 0x90
COMP_OFF = 0x0D
ENC_OFF = 0x0F
FFNAME_OFF = 0xF8

def _align_up(x, n):
    return ((x + n - 1) // n) * n

def parse_header(data):
    assert data[:8] == b'TAff0000', "not a TAff fastfile"
    version = struct.unpack_from('<I', data, 8)[0]
    assert version == 0x251, f"version 0x{version:x} != BO3 0x251"
    return {
        'version': version,
        'server': data[0x0C],
        'compression': data[COMP_OFF],
        'platform': data[0x0E],
        'encrypted': data[ENC_OFF],
        'size': struct.unpack_from('<Q', data, SIZE_OFF)[0],
        'blockSize': list(struct.unpack_from('<10Q', data, 0xA8)),
        'ffname': data[FFNAME_OFF:FFNAME_OFF+64].split(b'\x00')[0].decode('latin1'),
    }

def decompress(data, verbose=False):
    h = parse_header(data)
    if h['encrypted']:
        raise NotImplementedError("encrypted ff")
    size = h['size']
    comp = h['compression']
    out = bytearray(size)
    off = 0            # decompressed offset
    loc = HEADER_SIZE  # file location
    nblocks = 0
    seg_markers = 0
    while off < size:
        if loc + 16 > len(data):
            raise Exception(f"ran out of file at loc 0x{loc:x}, off 0x{off:x}/0x{size:x}")
        cSize, uSize, aSize, boff = struct.unpack_from('<IIII', data, loc)
        if boff != loc:
            raise Exception(f"bad block position 0x{loc:x} != 0x{boff:x} (block {nblocks}, off 0x{off:x})")
        loc += 16
        if uSize == 0:
            seg_markers += 1
            loc = _align_up(loc, READ_SEGMENT)
            continue
        block = data[loc:loc+aSize]
        loc += aSize
        if comp == 0:
            out[off:off+uSize] = block[:cSize]
        else:
            # BO3 uses zlib WITH header (RFC1950), 4KB window (CINFO=4). wbits=15 accepts it.
            d = zlib.decompressobj(15)
            chunk = d.decompress(block[:cSize], uSize)
            chunk += d.flush()
            if len(chunk) != uSize:
                raise Exception(f"block {nblocks}: inflated {len(chunk)} != {uSize}")
            out[off:off+uSize] = chunk
        off += uSize
        nblocks += 1
    if verbose:
        print(f"  ffname={h['ffname']} decompressed=0x{size:x} blocks={nblocks} segMarkers={seg_markers}")
    return bytes(out), h

def recompress(payload, template_header, chunk_size=0x381b0, level=9):
    """Rebuild a BO3 v0x251 ff from a decompressed payload.
    template_header: >=0x248 bytes of the ORIGINAL header, copied verbatim then
    patched with the new decompressed size. Block layout uses the original's
    segment-marker style: blocks never cross an 8MB boundary; a uSize==0
    DBStreamHeader marks the end of a segment and the reader aligns to the next.
    zlib window = 4KB (wbits=12) to match what the game's inflate expects.
    """
    assert len(template_header) >= HEADER_SIZE
    n = len(payload)
    out = bytearray(template_header[:HEADER_SIZE])
    # patch decompressed size @0x90
    struct.pack_into('<Q', out, SIZE_OFF, n)
    # force zlib compression flag @0x0D (in case template differs)
    out[COMP_OFF] = 1
    out[ENC_OFF] = 0

    MARKER = 16
    MARGIN = 16  # always keep room for a segment-end marker
    pos = HEADER_SIZE
    off = 0
    nblocks = 0
    nmarkers = 0
    while off < n:
        usize = min(chunk_size, n - off)
        co = zlib.compressobj(level, zlib.DEFLATED, 12)  # 4KB window, RFC1950 header
        comp = co.compress(payload[off:off+usize]) + co.flush()
        csize = len(comp)
        asize = (csize + 3) & ~3  # align to 4
        need = MARKER + asize
        boundary = ((pos // READ_SEGMENT) + 1) * READ_SEGMENT
        if pos + need <= boundary - MARGIN:
            # place block here
            out += struct.pack('<IIII', csize, usize, asize, pos)
            out += comp
            out += b'\x00' * (asize - csize)
            pos += need
            off += usize
            nblocks += 1
        else:
            # The next block doesn't fit before the 8MB boundary, so DEFER it to the
            # next segment. Write a segment marker (uncompressedSize==0) whose
            # compressedSize/alignedSize announce the deferred block's total footprint
            # (its own 16-byte header + aligned data). This matches Treyarch's linker;
            # the shipped reader/game rely on these fields (all-zero markers fail).
            assert boundary - pos >= MARKER, f"no room for marker: pos=0x{pos:x} boundary=0x{boundary:x}"
            out += struct.pack('<IIII', csize + MARKER, 0, asize + MARKER, pos)
            pos += MARKER
            pad = boundary - pos
            out += b'\x00' * pad
            pos = boundary
            nmarkers += 1
            # do NOT advance off; retry (re-place) this same chunk at the new segment
    # trailing end marker (matches Treyarch/ACTS: uSize==0 then some padding)
    out += struct.pack('<IIII', 0, 0, 0, pos)
    pos += MARKER
    out += b'\x00' * 0x40
    return bytes(out), nblocks, nmarkers


MAGIC = bytes.fromhex('804753430d0a001c')  # 0x1c000a0d43534780 (BO3 GSC VM)

def find_script(payload, name):
    """name: bytes path e.g. b'scripts/zm/_zm_example.gsc'.
    Returns dict with name offset, len-field offset, current len, bytecode offset."""
    npos = payload.find(name)
    if npos < 0:
        return None
    len_off = npos - 0x10  # ScriptParseTree: name(8) len(4) pad(4) buffer(8); name string follows struct
    oldlen = struct.unpack_from('<I', payload, len_off)[0]
    bc_off = payload.find(MAGIC, npos + len(name))
    if bc_off < 0 or bc_off - (npos + len(name)) > 8:
        raise Exception(f"bytecode magic not found right after name {name!r} (bc_off=0x{bc_off:x})")
    return {'npos': npos, 'len_off': len_off, 'oldlen': oldlen, 'bc_off': bc_off}


def _fix_gsc_size_fields(buf, bc_off, old_len, delta):
    """Update a T7GSCOBJ's in-header size fields after its buffer grows/shrinks by `delta`.
    @0x28 and @0x2c are always the total GSC size (== scriptparsetree.len); @0x1c is a section offset that
    equals len only when the script has no trailing section, so it's only updated in that case. Without this
    the game reads past or short of the buffer ('Unexpected string type in stringtable' / 'Could not find ...').
    `buf` is a bytearray; `bc_off` is the GSC start; `old_len` its size BEFORE the delta."""
    for o in (0x28, 0x2c):
        struct.pack_into('<I', buf, bc_off+o, struct.unpack_from('<I', buf, bc_off+o)[0] + delta)
    if struct.unpack_from('<I', buf, bc_off+0x1c)[0] == old_len:
        struct.pack_into('<I', buf, bc_off+0x1c,
                         struct.unpack_from('<I', buf, bc_off+0x1c)[0] + delta)
