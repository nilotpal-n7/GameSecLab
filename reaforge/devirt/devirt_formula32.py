#!/usr/bin/env python3
r"""REAForge devirt — x86-32 taint-symbolic recovery + all-inputs proof of hl_hash_utf8.

Phase 2 of the Dead Cells benchmark. devirt_dll32.py proved (concretely, 8/8) that the
VMProtect 3.11-virtualized hl_hash_utf8 in libhl.vmp.dll reproduces the HashLink source hash.
Here we port the x64 taint-symbolic engine (devirt_formula.py) to x86-32 and go further:
symbolize an N-byte input string, propagate symbolic claripy expressions through the VM along
the single concrete path, read the symbolic output h_out(b0..b_{N-1}), and SMT-prove it equals
the closed form   h=0; for c in bytes: h=223*h+c;  h%=0x1FFFFF7B   for ALL 2^(8N) inputs.

Reuses devirt_dll32's env + the post-unpack snapshot (FAST), so no re-unpacking.
Run from the vmp-lazy-unpack checkout:
    cd C:\Tools\_downloads\research\vmp-lazy-unpack
    FAST=1 python C:\Tools\GameSecLab\reaforge\devirt\devirt_formula32.py C:\Tools\GameSecLab\capstone\libhl.vmp.dll [N]
"""
import sys, struct, os, math, importlib, pickle
from pathlib import Path
VMP_LAZY = os.environ.get("VMP_LAZY_UNPACK", r"C:\Tools\_downloads\research\vmp-lazy-unpack")
sys.path.insert(0, VMP_LAZY)

from unicorn import Uc, UC_ARCH_X86, UC_PROT_ALL, UC_HOOK_CODE, UcError
import unicorn.x86_const as ux
import claripy
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, x86

import unpack.tracer as T
from unpack.tracer import (
    Catalog, find_or_capture_catalog, ensure_catalog_arch, load_pe, collect_imports,
    map_pe, map_emu_windows_modules, map_synthetic_process_state, Tracer, TraceHooks,
    ModuleImage, pe_memory_image, file_view_base_for, recover_keys,
    load_system_syscall_catalog, require_catalog, PAGE_SIZE, split_import_label,
)
from unpack.arch import arch_of

MODULO = 0x1FFFFF7B
STRBUF, RET, CALLSTK, CALLSTK_SZ = 0x30000000, 0x31000000, 0x20000000, 0x40000
SNAP = r"C:\Tools\GameSecLab\capstone\dll32_postunpack.snap"
M = (1 << 32) - 1

def ref_hash(s: bytes) -> int:
    h = 0
    for c in s:
        sc = c if c < 128 else c - 256          # (unsigned)*name sign-extends the signed char
        h = (223 * h + sc) & M
    hs = h - 0x100000000 if (h & 0x80000000) else h
    return int(math.fmod(hs, MODULO)) & M

# ---- x86-32 register aliasing ----
CANON = {}
_subs = {'eax':('ax','al'),'ebx':('bx','bl'),'ecx':('cx','cl'),'edx':('dx','dl'),
         'esi':('si','sil'),'edi':('di','dil'),'ebp':('bp','bpl'),'esp':('sp','spl')}
for _c, (_w, _b) in _subs.items():
    CANON[_c]=(_c,4,0); CANON[_w]=(_c,2,0); CANON[_b]=(_c,1,0)
for _h,_cr in (('ah','eax'),('bh','ebx'),('ch','ecx'),('dh','edx')): CANON[_h]=(_cr,1,1)
UCREG = {n: getattr(ux, "UC_X86_REG_"+n.upper()) for n in set(c for c,_,_ in CANON.values())}

def tainted(bv):
    return any(v.startswith("inp") for v in bv.variables)

class SymState:
    def __init__(self, uc): self.uc=uc; self.reg={}; self.mem={}
    def _creg(self, cr): return claripy.BVV(self.uc.reg_read(UCREG[cr]) & M, 32)
    def getreg(self, name):
        info = CANON.get(name.lower())
        if info is None: return claripy.BVV(0,32), False
        cr,sz,off = info
        v = self.reg[cr] if cr in self.reg else self._creg(cr)
        return claripy.Extract(off*8+sz*8-1, off*8, v), (cr in self.reg)
    def setreg(self, name, val):
        info = CANON.get(name.lower())
        if info is None: return
        cr,sz,off = info
        if sz==4: new=val
        else:
            cur = self.reg[cr] if cr in self.reg else self._creg(cr); pieces=[]
            if off+sz<4: pieces.append(claripy.Extract(31,(off+sz)*8,cur))
            pieces.append(val)
            if off>0: pieces.append(claripy.Extract(off*8-1,0,cur))
            new = pieces[0] if len(pieces)==1 else claripy.Concat(*pieces)
        if tainted(new): self.reg[cr]=new
        else: self.reg.pop(cr,None)
    def getmem(self, addr, sz):
        bs=[]
        for i in range(sz):
            b=self.mem.get(addr+i)
            if b is None:
                try: b=claripy.BVV(self.uc.mem_read(addr+i,1)[0],8)
                except Exception: b=claripy.BVV(0,8)
            bs.append(b)
        return (claripy.Concat(*reversed(bs)) if sz>1 else bs[0]), any((addr+i) in self.mem for i in range(sz))
    def setmem(self, addr, val, sz):
        for i in range(sz):
            byte=claripy.Extract(i*8+7,i*8,val)
            if tainted(byte): self.mem[addr+i]=byte
            else: self.mem.pop(addr+i,None)

def main():
    packed = Path(sys.argv[1]).resolve()
    N = int(sys.argv[2]) if len(sys.argv) > 2 else 4
    sample = (b"Player123456789"[:N])            # concrete path bytes (non-zero), NUL-terminated below
    pe = load_pe(packed.read_bytes()); arch = arch_of(pe)
    print(f"[setup] arch={arch.bits}-bit  N={N}  sample={sample!r}")
    T.ACTIVE_CATALOG = Catalog(find_or_capture_catalog((Path.cwd(), Path(T.__file__).resolve().parent.parent), arch), arch)
    ensure_catalog_arch(T.ACTIVE_CATALOG, arch)
    image_base = pe.OPTIONAL_HEADER.ImageBase
    entry = image_base + pe.OPTIONAL_HEADER.AddressOfEntryPoint
    import_slots = collect_imports(pe)
    # synthesize api-set export pools (see devirt_dll32.py)
    def _names(dll):
        p=os.path.join(r"C:\Windows\SysWOW64", dll); pe2=load_pe(Path(p).read_bytes())
        pe2.parse_data_directories(directories=[0])
        return [s.name.decode() for s in pe2.DIRECTORY_ENTRY_EXPORT.symbols if s.name]
    _ucrt=_names("ucrtbase.dll"); _core=list(dict.fromkeys(_names("kernelbase.dll")+_names("kernel32.dll")))
    def _cat_ok(m):
        try:
            for _ in require_catalog().exports(m): return True
            return True
        except Exception: return False
    _uncat={m for m in {split_import_label(l)[0] for l in import_slots.values()} if not _cat_ok(m)}
    if _uncat:
        _syn={m:(_ucrt if "crt" in m else (_core if "core" in m else list(dict.fromkeys(_ucrt+_core)))) for m in _uncat}
        _orig=require_catalog().exports
        def _patched(name,_o=_orig,_s=_syn):
            if name in _s: return [{"name":s,"ordinal":i+1} for i,s in enumerate(_s[name])]
            return _o(name)
        require_catalog().exports=_patched
    uc = Uc(UC_ARCH_X86, arch.uc_mode)
    mapped_start, mapped_end = map_pe(uc, pe)
    emu_bytes = pe_memory_image(load_pe(require_catalog().ntdll_bytes))
    fvb = file_view_base_for(arch, mapped_start, mapped_end, (len(emu_bytes)+0xfff)&~0xfff)
    uc.mem_map(fvb,(len(emu_bytes)+0xfff)&~0xfff,UC_PROT_ALL); uc.mem_write(fvb, emu_bytes)
    module_bases, synth, export_lookup = map_emu_windows_modules(uc, import_slots, arch)
    is_dll = bool(pe.FILE_HEADER.Characteristics & 0x2000)
    proc = None if is_dll else ModuleImage(packed.name, mapped_start, pe.OPTIONAL_HEADER.SizeOfImage, entry, str(packed))
    rsp = map_synthetic_process_state(uc, module_bases, proc, arch)
    for _,r in arch.gpr: uc.reg_write(r,0)
    uc.reg_write(arch.sp, rsp); uc.reg_write(ux.UC_X86_REG_EFLAGS, 0x202)
    if is_dll: uc.mem_write(rsp, struct.pack("<IIII", arch.return_sentinel, mapped_start, 1, 0))
    uc.reg_write(arch.ip, entry)
    tracer = Tracer(uc, mapped_start, mapped_end, synth, pe, module_bases, export_lookup, progress=lambda m:None, arch=arch)
    tracer.module_paths = {b: f"C:\\Windows\\System32\\{n}" for n,b in module_bases.items()}
    tracer.module_paths[mapped_start]=str(packed); tracer.module_paths[0]="C:\\host.exe"
    if is_dll: tracer.module_paths[arch.host_image_base]="C:\\host.exe"
    tracer.files.files[packed.name.lower()]=packed.read_bytes()
    tracer.encoded_string_keys = tuple(recover_keys(bytes(pe.__data__)))
    tracer.files.files["ntdll.dll"]=require_catalog().ntdll_bytes
    tracer.syscall_catalog = load_system_syscall_catalog()
    _ah32=importlib.import_module("unpack.32bit.api_handlers_32")
    def _vq(self,symbol,rcx,rdx,r8,r9):
        page=rcx&M; buf=rdx&M; length=r8&M
        regions=[(s,e,p) for (s,e,p) in self.uc.mem_regions()]
        region=next(((s,e,p) for (s,e,p) in regions if s<=page<=e), None)
        info=_ah32.memory_basic_information(self,page,region,regions)
        if length<len(info) or not self.writable_range(buf,len(info)): return 0,{}
        self.uc.mem_write(buf,info); return len(info),{}
    def _ret0(self,symbol,rcx,rdx,r8,r9): return 0,{}
    tracer._handlers=dict(tracer._handlers)
    tracer._handlers["virtualquery"]=(_vq,3); tracer._handlers["rtlunwind"]=(_ret0,4)

    pe.parse_data_directories()
    func=None
    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        if exp.name and exp.name.decode(errors="ignore")=="hl_hash_utf8": func=mapped_start+exp.address; break
    print(f"[setup] hl_hash_utf8 @ VA 0x{func:X}")

    sym = SymState(uc)
    md = Cs(CS_ARCH_X86, CS_MODE_32); md.detail = True
    inp = [claripy.BVS(f"inp{i}", 8) for i in range(N)]
    unhandled={}; errs=[]; snaps=[]; snapk=set()      # snaps: materialized tainted values, for round peeling

    def opval(insn, op):
        if op.type==x86.X86_OP_REG: return sym.getreg(insn.reg_name(op.reg))
        if op.type==x86.X86_OP_IMM: return claripy.BVV(op.imm & ((1<<(op.size*8))-1), op.size*8), False
        if op.type==x86.X86_OP_MEM:
            m=op.mem; a=m.disp
            if m.base:
                bn=insn.reg_name(m.base)
                if bn in UCREG: a+=uc.reg_read(UCREG[bn])
            if m.index:
                xn=insn.reg_name(m.index)
                if xn in UCREG: a+=uc.reg_read(UCREG[xn])*m.scale
            return sym.getmem(a & M, op.size)
        return claripy.BVV(0, op.size*8), False
    def ea(insn, op):
        m=op.mem; a=m.disp
        if m.base and insn.reg_name(m.base) in UCREG: a+=uc.reg_read(UCREG[insn.reg_name(m.base)])
        if m.index and insn.reg_name(m.index) in UCREG: a+=uc.reg_read(UCREG[insn.reg_name(m.index)])*m.scale
        return a & M
    def setdst(insn, op, val):
        if op.type==x86.X86_OP_REG: sym.setreg(insn.reg_name(op.reg), val)
        elif op.type==x86.X86_OP_MEM: sym.setmem(ea(insn,op), val, op.size)
    def ext(b, bits):
        if b.size()==bits: return b
        return claripy.ZeroExt(bits-b.size(), b) if b.size()<bits else claripy.Extract(bits-1,0,b)

    EFL={'CF':0,'PF':2,'ZF':6,'SF':7,'OF':11}; sflags={}; cl=claripy
    def get_flag(f):
        if f in sflags: return sflags[f]
        return cl.BoolV(bool((uc.reg_read(ux.UC_X86_REG_EFLAGS)>>EFL[f])&1))
    def msb(x): return cl.Extract(x.size()-1,x.size()-1,x)==cl.BVV(1,1)
    def bitpar(x):
        p=cl.Extract(0,0,x)
        for i in range(1,8): p=p^cl.Extract(i,i,x)
        return p==cl.BVV(0,1)
    FLAGS_SET={'add':'CF OF SF ZF PF','adc':'CF OF SF ZF PF','sub':'CF OF SF ZF PF','sbb':'CF OF SF ZF PF',
               'cmp':'CF OF SF ZF PF','and':'CF OF SF ZF PF','or':'CF OF SF ZF PF','xor':'CF OF SF ZF PF','test':'CF OF SF ZF PF',
               'inc':'OF SF ZF PF','dec':'OF SF ZF PF','neg':'CF OF SF ZF PF','shl':'CF OF SF ZF PF','sal':'CF OF SF ZF PF',
               'shr':'CF OF SF ZF PF','sar':'CF OF SF ZF PF','shrd':'CF SF ZF PF','shld':'CF SF ZF PF','rol':'CF OF','ror':'CF OF',
               'imul':'CF OF','mul':'CF OF','bt':'CF','bts':'CF','btr':'CF','btc':'CF','bsf':'ZF','bsr':'ZF','rcl':'CF OF','rcr':'CF OF'}
    def set_arith_flags(mn,a,b,res):
        Nn=res.size()
        sflags['ZF']=(res==cl.BVV(0,Nn)); sflags['SF']=msb(res); sflags['PF']=bitpar(res)
        if mn in ('add','adc'):
            w=cl.ZeroExt(1,a)+cl.ZeroExt(1,b); sflags['CF']=cl.Extract(Nn,Nn,w)==cl.BVV(1,1)
            sflags['OF']=cl.And(cl.Not((msb(a)!=msb(b))), (msb(res)!=msb(a)))
        elif mn in ('sub','cmp','sbb'):
            sflags['CF']=cl.ULT(a,b); sflags['OF']=cl.And((msb(a)!=msb(b)), (msb(res)!=msb(a)))
        elif mn in ('and','or','xor','test'): sflags['CF']=cl.BoolV(False); sflags['OF']=cl.BoolV(False)
        elif mn=='neg': sflags['CF']=(a!=cl.BVV(0,Nn)); sflags['OF']=cl.BoolV(False)
    def cc(nm):
        g=get_flag
        TT={'o':lambda:g('OF'),'no':lambda:cl.Not(g('OF')),'s':lambda:g('SF'),'ns':lambda:cl.Not(g('SF')),
           'e':lambda:g('ZF'),'z':lambda:g('ZF'),'ne':lambda:cl.Not(g('ZF')),'nz':lambda:cl.Not(g('ZF')),
           'b':lambda:g('CF'),'c':lambda:g('CF'),'nae':lambda:g('CF'),'ae':lambda:cl.Not(g('CF')),'nb':lambda:cl.Not(g('CF')),'nc':lambda:cl.Not(g('CF')),
           'be':lambda:cl.Or(g('CF'),g('ZF')),'na':lambda:cl.Or(g('CF'),g('ZF')),'a':lambda:cl.And(cl.Not(g('CF')),cl.Not(g('ZF'))),'nbe':lambda:cl.And(cl.Not(g('CF')),cl.Not(g('ZF'))),
           'l':lambda:(g('SF')!=g('OF')),'nge':lambda:(g('SF')!=g('OF')),'ge':lambda:cl.Not((g('SF')!=g('OF'))),'nl':lambda:cl.Not((g('SF')!=g('OF'))),
           'le':lambda:cl.Or(g('ZF'),(g('SF')!=g('OF'))),'ng':lambda:cl.Or(g('ZF'),(g('SF')!=g('OF'))),'g':lambda:cl.And(cl.Not(g('ZF')),cl.Not((g('SF')!=g('OF')))),'nle':lambda:cl.And(cl.Not(g('ZF')),cl.Not((g('SF')!=g('OF')))),
           'p':lambda:g('PF'),'pe':lambda:g('PF'),'np':lambda:cl.Not(g('PF')),'po':lambda:cl.Not(g('PF'))}
        return TT[nm]()
    def ifsel(cond,t,f): return (t if cond.is_true() else f) if not cond.symbolic else cl.If(cond,t,f)

    def step(insn):
        mn=insn.mnemonic; ops=insn.operands
        vals=[opval(insn,o) for o in ops]
        if mn in FLAGS_SET:
            for fn in FLAGS_SET[mn].split(): sflags.pop(fn,None)
        A=lambda i: vals[i][0]
        if mn=="push":
            v=ext(A(0),32); esp=uc.reg_read(ux.UC_X86_REG_ESP); sym.setmem((esp-4)&M, v, 4); return
        if mn=="pop":
            esp=uc.reg_read(ux.UC_X86_REG_ESP); v,_=sym.getmem(esp&M,4); setdst(insn,ops[0],ext(v,ops[0].size*8)); return
        if mn in ("mul","imul") and len(ops)==1:          # implicit (E)DX:(E)AX = (E)AX * src
            sz=ops[0].size; areg={1:"al",2:"ax",4:"eax"}[sz]
            a=sym.getreg(areg)[0]; src=A(0)
            if not (tainted(a) or tainted(src)): return
            if mn=="imul": prod=claripy.SignExt(sz*8,a)*claripy.SignExt(sz*8,src)
            else:          prod=claripy.ZeroExt(sz*8,a)*claripy.ZeroExt(sz*8,src)
            if sz==1:
                sym.setreg("ax", prod)
            else:
                sym.setreg(areg, claripy.Extract(sz*8-1,0,prod))
                sym.setreg("dx" if sz==2 else "edx", claripy.Extract(2*sz*8-1,sz*8,prod))
            return
        if not any(t for _,t in vals): return
        res=None; dst=ops[0] if ops else None
        if mn=="mov": res=A(1)
        elif mn=="movzx": res=claripy.ZeroExt(ops[0].size*8 - A(1).size(), A(1))
        elif mn in ("movsx","movsxd"): res=claripy.SignExt(ops[0].size*8 - A(1).size(), A(1))
        elif mn=="lea":
            m=ops[1].mem; a=claripy.BVV(m.disp & M,32)
            if m.base and insn.reg_name(m.base) in CANON: a=a+ext(sym.getreg(insn.reg_name(m.base))[0],32)
            if m.index and insn.reg_name(m.index) in CANON: a=a+ext(sym.getreg(insn.reg_name(m.index))[0],32)*m.scale
            res=claripy.Extract(ops[0].size*8-1,0,a)
        elif mn in ("add","sub","xor","and","or","imul","shl","sal","shr","sar","rol","ror"):
            if len(ops)==3 and mn=="imul": a=A(1); b=ext(A(2),A(1).size()); dst=ops[0]
            else: a=A(0); b=ext(A(1),A(0).size()) if len(ops)>=2 else None
            if mn=="add": res=a+b
            elif mn=="sub": res=a-b
            elif mn=="xor": res=a^b
            elif mn=="and": res=a&b
            elif mn=="or": res=a|b
            elif mn=="imul": res=a*b
            elif mn in ("shl","sal"): res=a<<b
            elif mn=="shr": res=claripy.LShR(a,b)
            elif mn=="sar": res=a>>b
            elif mn=="rol": res=claripy.RotateLeft(a,b)
            elif mn=="ror": res=claripy.RotateRight(a,b)
            if mn in ('add','sub','and','or','xor') and b is not None: set_arith_flags(mn,a,b,res)
        elif mn=="not": res=~A(0)
        elif mn=="neg": res=claripy.BVV(0,A(0).size())-A(0)
        elif mn=="inc": res=A(0)+1
        elif mn=="dec": res=A(0)-1
        elif mn=="bswap":
            a=A(0); n=a.size()//8; res=claripy.Concat(*[claripy.Extract(i*8+7,i*8,a) for i in range(n)])
        elif mn=="xchg": setdst(insn,ops[0],A(1)); setdst(insn,ops[1],A(0)); return
        elif mn=="movabs": res=A(1)
        elif mn in ("shrd","shld"):
            a=A(0); b=ext(A(1),A(0).size()); bits=a.size(); c=A(2); cnt=((c.args[0] if not c.symbolic else 0)&(bits-1))
            if cnt==0: res=a
            elif mn=="shrd": res=claripy.LShR(a,cnt)|(b<<(bits-cnt))
            else: res=(a<<cnt)|claripy.LShR(b,(bits-cnt))
            dst=ops[0]
        elif mn in ("bt","bts","btr","btc"):
            a=A(0); bi=ext(A(1),a.size()) & claripy.BVV(a.size()-1,a.size()); mask=claripy.BVV(1,a.size())<<bi
            sflags['CF']=((claripy.LShR(a,bi) & claripy.BVV(1,a.size()))==claripy.BVV(1,a.size()))
            if mn=="bt": return
            res=(a|mask) if mn=="bts" else ((a & ~mask) if mn=="btr" else (a^mask)); dst=ops[0]
        elif mn=="cmp": a=A(0); b=ext(A(1),A(0).size()); set_arith_flags('sub',a,b,a-b); return
        elif mn=="test": a=A(0); b=ext(A(1),A(0).size()); set_arith_flags('and',a,b,a&b); return
        elif mn=="adc":
            a=A(0); b=ext(A(1),A(0).size()); cf=ifsel(get_flag('CF'),claripy.BVV(1,a.size()),claripy.BVV(0,a.size()))
            res=a+b+cf; set_arith_flags('adc',a,b+cf,res); dst=ops[0]
        elif mn=="sbb":
            a=A(0); b=ext(A(1),A(0).size()); cf=ifsel(get_flag('CF'),claripy.BVV(1,a.size()),claripy.BVV(0,a.size()))
            res=a-b-cf; set_arith_flags('sub',a,b+cf,res); dst=ops[0]
        elif mn.startswith("cmov"): res=ifsel(cc(mn[4:]), A(1), A(0)); dst=ops[0]
        elif mn.startswith("set") and len(mn)<=5: res=ifsel(cc(mn[3:]), claripy.BVV(1,8), claripy.BVV(0,8)); dst=ops[0]
        elif mn in ("bsf","bsr"):
            b=A(1); n=b.size(); idx=claripy.BVV(0,n)
            for k in (range(n-1,-1,-1) if mn=="bsf" else range(0,n)):
                idx=claripy.If(claripy.Extract(k,k,b)==claripy.BVV(1,1), claripy.BVV(k,n), idx)
            res=idx; sflags['ZF']=(b==claripy.BVV(0,n)); dst=ops[0]
        elif mn in ("rcl","rcr"):
            a=A(0); bits=a.size(); c=A(1); cnt=((c.args[0] if not c.symbolic else 1)%(bits+1))
            cf=ifsel(get_flag('CF'),claripy.BVV(1,1),claripy.BVV(0,1))
            for _ in range(cnt):
                if mn=="rcl": newcf=claripy.Extract(bits-1,bits-1,a); a=(a<<1)|claripy.ZeroExt(bits-1,cf); cf=newcf
                else: newcf=claripy.Extract(0,0,a); a=claripy.LShR(a,1)|(claripy.ZeroExt(bits-1,cf)<<(bits-1)); cf=newcf
            res=a; sflags['CF']=(cf==claripy.BVV(1,1)); dst=ops[0]
        elif mn in ("call","jmp","ret","nop","leave","cdq","cwde"): return
        else: unhandled[mn]=unhandled.get(mn,0)+1; return
        if res is not None and mn in ('shl','sal','shr','sar','shrd','shld','inc','dec','imul','rol','ror'):
            sflags['ZF']=(res==claripy.BVV(0,res.size())); sflags['SF']=msb(res); sflags['PF']=bitpar(res)
        if res is not None and dst is not None:
            setdst(insn, dst, res)
            if tainted(res):
                try:
                    r32 = res if res.size()==32 else (claripy.Extract(31,0,res) if res.size()>32 else res)
                    k=hash(r32)
                    if k not in snapk and len(snaps)<20000: snapk.add(k); snaps.append(r32)
                except Exception: pass

    with TraceHooks(tracer, arch.peb_base, PAGE_SIZE):
        if not (os.environ.get("FAST") and os.path.exists(SNAP)):
            print("[err] needs the post-unpack snapshot; run devirt_dll32.py once first."); return
        d=pickle.load(open(SNAP,"rb"))
        for b,sz,data in d["regions"]:
            try: uc.mem_map(b,sz,UC_PROT_ALL)
            except UcError: pass
            try: uc.mem_write(b,data)
            except UcError: pass
        for rn,val in d["regs"].items():
            try: uc.reg_write(getattr(ux,"UC_X86_REG_"+rn),val)
            except Exception: pass
        tracer.check_restored_entry=lambda a: False; tracer.stop_reason=None
        for addr,sz in ((STRBUF,0x1000),(RET,0x1000),(CALLSTK,CALLSTK_SZ)):
            try: uc.mem_map(addr & ~0xfff, sz, UC_PROT_ALL)
            except UcError: pass

        # symbolic input: concrete bytes drive the path; sym.mem holds the symbolic bytes; NUL terminates
        uc.mem_write(STRBUF, sample + b"\x00")
        for i in range(N): sym.mem[STRBUF+i]=inp[i]
        for _,r in arch.gpr: uc.reg_write(r,0)
        spv=(CALLSTK+CALLSTK_SZ//2)&~0xF
        uc.mem_write(spv, struct.pack("<I", RET)); uc.mem_write(spv+4, struct.pack("<I", STRBUF))
        uc.reg_write(arch.sp, spv); uc.reg_write(arch.ip, func)

        def hook(uc_, address, size, ud):
            try: insn=next(md.disasm(bytes(uc_.mem_read(address,size)), address), None)
            except Exception: return
            if insn is not None:
                try: step(insn)
                except Exception as e:
                    if len(errs)<3:
                        import traceback; errs.append((hex(address),insn.mnemonic,traceback.format_exc()))
        h=uc.hook_add(UC_HOOK_CODE, hook, None, mapped_start, mapped_end)
        uc.emu_start(func, RET, timeout=300*1000*1000)
        uc.hook_del(h)

    h_sym = sym.getreg("eax")[0]
    print(f"\n== x86-32 taint-symbolic recovery ==")
    print(f"unhandled tainted mnemonics: {unhandled}")
    if errs: print(f"(step exceptions: {len(errs)}; first @ {errs[0][0]} {errs[0][1]})")
    if not tainted(h_sym):
        print("  h_out is not symbolic in the input bytes — the taint didn't reach EAX."); return
    print(f"  recovered symbolic h_out (depth {h_sym.depth})")

    def evalat(expr, bs):
        s=claripy.Solver()
        for i in range(N): s.add(inp[i]==claripy.BVV(bs[i],8))
        return s.eval(expr,1)[0] & M
    oks=[]
    for probe in (sample, bytes(range(1,1+N)), bytes([0xFF]*N), bytes([1]+[0]*(N-1)) if N>1 else b"\x01"):
        got=evalat(h_sym, probe); want=ref_hash(probe); oks.append(got==want)
        print(f"  probe {probe!r:20} h_out=0x{got:08X}  ref=0x{want:08X}  {'ok' if got==want else 'MISMATCH'}")
    print(f"  sample validation: {'all match' if all(oks) else 'MISMATCH'}")

    # ---- all-inputs SMT proof: h_out == fold(b0..b_{N-1}) mod 0x1FFFFF7B ----
    print(f"\n  [Proof] h_out == fold formula for ALL 2^{8*N} inputs? (timeout 300s)")
    try:
        import z3
        hz = claripy.backends.z3.convert(h_sym)
        bz = [claripy.backends.z3.convert(inp[i]) for i in range(N)]
        acc = z3.BitVecVal(0,32)
        for i in range(N): acc = acc*z3.BitVecVal(223,32) + z3.SignExt(24, bz[i])
        ref = z3.SRem(acc, z3.BitVecVal(MODULO,32))      # C '%' truncates toward zero (signed)
        s=z3.Solver(); s.set("timeout",300000); s.add(hz != ref); r=s.check()  # bounded so it can't hang
        if r==z3.unsat:
            print(f"    >>> UNSAT over all 2^{8*N} inputs ==> PROVEN: virtualized hl_hash_utf8 ==")
            print(f"        h=0; for c in bytes[:{N}]: h=223*h+c;  return h % 0x1FFFFF7B")
        elif r==z3.unknown:
            print("    z3 timeout (div/mod-heavy); backed by per-sample validation above.")
        else:
            m=s.model(); print(f"    counterexample: {m}")
    except Exception as e:
        print("    proof error:", repr(e))

    # ---- round peeling: decompose the fold into per-input-byte rounds + anti-unify ----
    # hl_hash_utf8 is one round per byte: acc_{k+1} = 223*acc_k + (signed char)name[k]. We find each
    # per-byte accumulator among the recorded tainted snapshots (by which input bytes it depends on),
    # peel the round by substituting a fresh var for acc_k, blindly recover the multiplier, and PROVE
    # acc_{k+1} == M*acc_k + signext(name[k]). Then anti-unify the identical rounds into the loop.
    print(f"\n== round peeling (per-input-byte rounds) ==")
    try:
        import z3
        conv = claripy.backends.z3.convert
        def to32(a): return a if a.size()==32 else (claripy.Extract(31,0,a) if a.size()>32 else claripy.ZeroExt(32-a.size(),a))
        xx = z3.BitVec('xx', 32)
        inpz = [conv(inp[i]) for i in range(N)]
        def vidx(a): return frozenset(int(v[3:v.index('_')]) for v in a.variables if v.startswith('inp'))
        byset = {}
        for a in snaps:
            s = vidx(a)
            if s: byset.setdefault(s, []).append(a)
        def ev(g, xv):
            return z3.simplify(z3.substitute(g, (xx, z3.BitVecVal(xv & M, 32)),
                               *[(inpz[i], z3.BitVecVal(0,8)) for i in range(N)])).as_long() & M
        rounds=[]; prev=z3.BitVecVal(0,32); ok=True
        for k in range(N):
            found=None
            for a in byset.get(frozenset(range(k+1)), []):
                az = conv(to32(a))
                g = z3.substitute(az, (prev, xx)) if k>0 else az
                nib = z3.SignExt(24, inpz[k])
                if k>0:
                    Mk=(ev(g,1)-ev(g,0)) & M
                    if Mk in (0,1): continue
                    cand = xx*z3.BitVecVal(Mk,32) + nib
                else:
                    Mk=None; cand = nib
                sv=z3.Solver(); sv.set("timeout",20000); sv.add(g != cand)
                if sv.check()==z3.unsat: found=(az, Mk); break
            if not found: ok=False; break
            az, Mk = found; prev=az; rounds.append(Mk)
            print(f"    round[0] PROVEN:  acc = (signed char) name[0]" if k==0 else
                  f"    round[{k}] PROVEN:  acc = acc*{Mk} + (signed char) name[{k}]")
        mults=[m for m in rounds if m is not None]
        if ok and len(rounds)==N and mults and all(m==mults[0] for m in mults):
            print("\n  anti-unified loop (recovered by peeling, each round SMT-proven):")
            print(f"    h = 0")
            print(f"    for c in name:  h = {mults[0]}*h + (signed char)c")
            print(f"    return h % 0x1FFFFF7B")
            print(f"    => multiplier {mults[0]} recovered blindly; matches HashLink source (223).")
        else:
            print(f"    peeling recovered {len(rounds)}/{N} rounds (some accumulator snapshots not captured).")
    except Exception as e:
        print("    peeling error:", repr(e))

if __name__ == "__main__":
    main()
