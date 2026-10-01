"""T7 (BO3) XAssetList reader: the script strings and asset directory at the start of a decompressed payload,
plus the asset type enum.

The payload is one stream that the loader reads in a single pass. A pointer field of -1 means the data follows
inline at the current position; 0 means null. Data is byte-packed with no padding between assets.
"""
import struct

FOLLOW = 0xFFFFFFFFFFFFFFFF   # -1: data follows inline

# T7 (Black Ops 3) XAssetType enum, after Scobalula's HydraX (BlackOps3.cs AssetPool) and Greyhound
# (GameBlackOps3.cpp). Slot 3 is named 'xanimparts' and 0x28 'newlensflaredef' here.
ASSET_TYPES = {
    0x00:'physpreset',       0x01:'physconstraints',  0x02:'destructibledef',  0x03:'xanimparts',
    0x04:'xmodel',           0x05:'xmodelmesh',       0x06:'material',         0x07:'computeshaderset',
    0x08:'techset',          0x09:'image',            0x0A:'sound',            0x0B:'sound_patch',
    0x0C:'col_map',          0x0D:'com_map',          0x0E:'game_map',         0x0F:'map_ents',
    0x10:'gfxworld',         0x11:'lightdef',         0x12:'lensflaredef',     0x13:'ui_map',
    0x14:'font',             0x15:'fonticon',         0x16:'localize',         0x17:'weapon',
    0x18:'weapondef',        0x19:'weaponvariant',    0x1A:'weaponfull',       0x1B:'cgmediatable',
    0x1C:'playersoundstable',0x1D:'playerfxtable',    0x1E:'sharedweaponsounds',0x1F:'attachment',
    0x20:'attachmentunique', 0x21:'weaponcamo',       0x22:'customizationtable',0x23:'customizationtable_feimages',
    0x24:'customizationtablecolor',0x25:'snddriverglobals',0x26:'fx',          0x27:'tagfx',
    0x28:'newlensflaredef',  0x29:'impactsfxtable',   0x2A:'impactsoundstable',0x2B:'player_character',
    0x2C:'aitype',           0x2D:'character',        0x2E:'xmodelalias',      0x2F:'rawfile',
    0x30:'stringtable',      0x31:'structuredtable',  0x32:'leaderboarddef',   0x33:'ddl',
    0x34:'glasses',          0x35:'texturelist',      0x36:'scriptparsetree',  0x37:'keyvaluepairs',
    0x38:'vehicledef',       0x39:'addon_map_ents',   0x3A:'tracer',           0x3B:'slug',
    0x3C:'surfacefxtable',   0x3D:'surfacesounddef',  0x3E:'footsteptable',    0x3F:'entityfximpacts',
    0x40:'entitysoundimpacts',0x41:'zbarrier',        0x42:'vehiclefxdef',     0x43:'vehiclesounddef',
    0x44:'typeinfo',         0x45:'scriptbundle',     0x46:'scriptbundlelist', 0x47:'rumble',
    0x48:'bulletpenetration',0x49:'locdmgtable',      0x4A:'aimtable',         0x4B:'animselectortable',
    0x4C:'animmappingtable', 0x4D:'animstatemachine', 0x4E:'behaviortree',     0x4F:'behaviorstatemachine',
    0x50:'ttf',              0x51:'sanim',            0x52:'lightdescription', 0x53:'shellshock',
    0x54:'xcam',             0x55:'bg_cache',         0x56:'texturecombo',     0x57:'flametable',
    0x58:'bitfield',         0x59:'attachment_cosmetic_variant',0x5A:'maptable',0x5B:'maptableloadingimages',
    0x5C:'medal',            0x5D:'medaltable',       0x5E:'objective',        0x5F:'objectivelist',
    0x60:'umbra_tome',       0x61:'navmesh',          0x62:'navvolume',        0x63:'binaryhtml',
    0x64:'laser',            0x65:'beam',             0x66:'streamerhint',     0x67:'_string',
    0x68:'assetlist',        0x69:'report',           0x6A:'depend',
}

class Stream:
    """Sequential reader over the decompressed payload, mirroring the loader's single pass.
    `pos` is the stream cursor; following a -1 pointer just keeps reading at pos."""
    def __init__(self, payload):
        self.p = memoryview(payload); self.pos = 0
        self.offset_fields = []   # (stream_pos, size, value, note) — position-dependent fields we find
    def u8(self):  v=self.p[self.pos]; self.pos+=1; return v
    def u16(self): v=struct.unpack_from('<H',self.p,self.pos)[0]; self.pos+=2; return v
    def u32(self): v=struct.unpack_from('<I',self.p,self.pos)[0]; self.pos+=4; return v
    def i32(self): v=struct.unpack_from('<i',self.p,self.pos)[0]; self.pos+=4; return v
    def u64(self): v=struct.unpack_from('<Q',self.p,self.pos)[0]; self.pos+=8; return v
    def skip(self,n): self.pos+=n
    def ptr(self):
        """Read an 8-byte pointer. Returns 'FOLLOW' (-1, data inline), 0 (null), or a raw value."""
        return self.u64()
    def string_inline(self):
        """Read a null-terminated inline string at the cursor (used when a name ptr was -1)."""
        s=self.pos
        while self.p[self.pos]!=0: self.pos+=1
        out=bytes(self.p[s:self.pos]); self.pos+=1
        return out
    def align(self, n):
        """Some inline blobs are aligned; advance cursor to a multiple of n (rarely needed)."""
        r=self.pos % n
        if r: self.pos += (n-r)

def _entry_ok(payload, off):
    """Does `off` look like an XAsset directory entry {type u32<128, pad u32==0, hdrPtr==-1}?"""
    if off+16 > len(payload): return False
    t,pad,hp = struct.unpack_from('<IIQ', payload, off)
    return t < 128 and pad == 0 and hp == FOLLOW

def parse_xassetlist(payload):
    """Parse the XAssetList head: script strings + the asset directory. The header base is 0x30;
    when script strings are present a `const char**` pointer array (0x38, string_count entries of -1)
    plus the strings themselves push the asset directory later — and it is NOT 8-aligned. So compute
    the directory position from the strings and validate; fall back to 0x30 (no strings).
    Returns (strings[list of bytes], assets[list of dict], first_header_pos)."""
    s = Stream(payload)
    string_count = s.u32(); s.u32(); strings_ptr = s.ptr()
    s.pos = 0x20
    asset_count  = s.u32(); s.u32(); s.ptr()
    candidates = []
    if strings_ptr == FOLLOW and string_count > 1:
        p = 0x38 + string_count*8                  # after the -1 pointer array; index 0 = reserved ""
        tmp = [b'']
        try:
            for _ in range(string_count-1):
                e = payload.index(b'\x00', p); tmp.append(bytes(payload[p:e])); p = e+1
            candidates.append((p, tmp))
        except ValueError:
            pass
    candidates.append((0x30, [b'']))               # no-strings layout
    aa = None; strings = [b'']
    for cand, cstrings in candidates:
        if _entry_ok(payload, cand) and _entry_ok(payload, cand+16):
            aa, strings = cand, cstrings; break
    if aa is None:
        # Robust fallback for ffs whose inline-string blob our heuristic couldn't size: scan forward for the
        # first offset that starts a long contiguous run of valid {type<128, pad==0, hdr==-1} entries whose
        # first type is a KNOWN asset type. A run this long of exact -1 header pointers is not chance, so this
        # latches onto a real directory without false-positiving on all-\xff padding. (Truly streamed ffs — the
        # directory interleaved with inline headers, no contiguous array — still legitimately find nothing here.)
        want = max(3, min(asset_count, 8))
        off, n = 0x30, len(payload)
        while off + 16*want <= n:
            if struct.unpack_from('<I', payload, off)[0] in ASSET_TYPES and \
               all(_entry_ok(payload, off+i*16) for i in range(want)):
                aa = off; break
            off += 4
    if aa is None:
        raise ValueError("asset directory not found")
    assets=[]
    s.pos = aa
    for _ in range(asset_count):
        t=s.u32(); s.u32(); hp=s.ptr()
        assets.append(dict(type=t, name=ASSET_TYPES.get(t, f'type_{t}'), hdr_ptr=hp))
    return strings, assets, s.pos

