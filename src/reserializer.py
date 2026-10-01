"""XModelMesh walker that records every encoded (block<<60)|offset pointer field by its struct position.

Used by the grow engine: when a script grows, only recorded pointer fields whose block-5 target is past the
insertion point are shifted. Recording fields structurally (rather than scanning for pointer-like values)
avoids corrupting shader or bytecode data whose bytes happen to look like pointers.
"""
F=0xFFFFFFFFFFFFFFFF
u=lambda p,o,n: int.from_bytes(p[o:o+n],'little')

class Rec:
    """Pointer-field recorder. rec.ptr(pay,pos) reads an 8-byte pointer, logs it if it's a real
    (block<<60)|off encoded pointer, and returns the raw value so the sizer can branch on F/0."""
    def __init__(s): s.ptrs=[]; s.blobs=[]   # ptrs: (pos,block,off); blobs: (start,end) inline data (no pointers)
    def ptr(s,pay,pos):
        v=u(pay,pos,8)
        if v!=F and v!=0:
            blk=v>>60; off=v & 0x0FFFFFFFFFFFFFFF
            if blk<10: s.ptrs.append((pos,blk,off))
        return v

def cstr_end(pay,p): return pay.index(b'\x00',p)+1

def walk_xmodelmesh(pay,X,rec,b6=None):
    """Walk one XModelMesh byte-exactly, recording every pointer field (name, surfs, shared, per-surface
    shared/vertList/name, collisionTree). Returns the offset just past the mesh. If b6 is a list, appends the
    (start, end) of inline vertex data (block 6) regions."""
    name_ptr=rec.ptr(pay,X)                 # const char* name @ +0
    numSurfs=pay[X+0x3C]
    surfs_ptr=rec.ptr(pay,X+0x68)
    shared_ptr=rec.ptr(pay,X+0x70)
    p=X+0x78
    if name_ptr==F: p=cstr_end(pay,p)
    if shared_ptr==F:                       # XSurfaceShared inline
        shflags=u(pay,p,4)
        data_ptr=rec.ptr(pay,p+0x10)        # data* (block6 when inline)
        dataSize=u(pay,p+0x18,4)
        p+=0x50
        if data_ptr==F and (shflags&1)==0:
            if b6 is not None and dataSize: b6.append((p,p+dataSize))   # inline verts = block6
            p+=dataSize
    surfs_at=p
    if surfs_ptr==F:
        p+=numSurfs*0x60
        for i in range(numSurfs):
            b=surfs_at+i*0x60
            rec.ptr(pay,b+0x10)             # shared (back-ref)
            vl=rec.ptr(pay,b+0x18)          # vertList
            nm=rec.ptr(pay,b+0x58)          # name
            vlc=pay[b+1]
            if vl==F and vlc>0:
                for _ in range(vlc):
                    ct=rec.ptr(pay,p+8); p+=0x10          # XRigidVertList (0x10), collisionTree* @+8
                    if ct==F:                             # XSurfaceCollisionTree (0x38)
                        nodeCount=u(pay,p+0x18,4); nodes_ptr=rec.ptr(pay,p+0x1C)
                        leafCount=u(pay,p+0x24,4); leafs_ptr=rec.ptr(pay,p+0x2C)
                        p+=0x38
                        if nodes_ptr==F: p+=nodeCount*0x10
                        if leafs_ptr==F: p+=leafCount*0x2
            if nm==F: p=cstr_end(pay,p)
    return p
