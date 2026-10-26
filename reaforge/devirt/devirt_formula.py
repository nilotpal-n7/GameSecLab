#!/usr/bin/env python3
r"""REAForge devirt — blind SYMBOLIC formula recovery for check_license (VMProtect 3.11).

Reuse vmp-lazy-unpack's env, emulate to OEP, drive into the VM'd check_license. Symbolize the
volume serial and run a taint-symbolic trace (claripy) along the single concrete path: tainted
registers/memory carry claripy expressions; concrete values stay in Unicorn. Where a tainted value
meets our concrete marker (got) in a compare/arith op, that tainted expression is expected_key(serial)
— recovered with ZERO prior knowledge, then validated + simplified.

Run from the vmp-lazy-unpack checkout:
    cd C:\Tools\_downloads\research\vmp-lazy-unpack
    python C:\Tools\GameSecLab\reaforge\devirt\devirt_formula.py <packed.exe> <serial_hex>
"""
import sys, struct, os
from pathlib import Path
VMP_LAZY = os.environ.get("VMP_LAZY_UNPACK", r"C:\Tools\_downloads\research\vmp-lazy-unpack")
sys.path.insert(0, VMP_LAZY)

from unicorn import Uc, UC_ARCH_X86, UC_PROT_ALL, UC_HOOK_CODE, UcError
import unicorn.x86_const as ux
import claripy
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, x86

import unpack.tracer as T
from unpack.tracer import (
    Catalog, find_or_capture_catalog, ensure_catalog_arch, load_pe, collect_imports,
    map_pe, map_emu_windows_modules, map_synthetic_process_state, Tracer, TraceHooks,
    ModuleImage, pe_memory_image, file_view_base_for, recover_keys,
    load_system_syscall_catalog, require_catalog, PAGE_SIZE,
)
from unpack.arch import MODE64

CHECK_RVA = 0x1000
RET_SENTINEL = 0x7ff900002000
KEYBUF = 0x00000add00000000
MARKER = 0x13371337

def c0_expected_key(mid):
    acc = (0x1505 ^ mid) & 0xffffffff
    for i in range(8):
        acc = ((acc * 33) & 0xffffffff) ^ ((mid >> (i * 4)) & 0xF)
        acc = (acc + i * 7) & 0xffffffff
    return acc

CANON = {}
_subs = {'rax':('eax','ax','al'),'rbx':('ebx','bx','bl'),'rcx':('ecx','cx','cl'),'rdx':('edx','dx','dl'),
         'rsi':('esi','si','sil'),'rdi':('edi','di','dil'),'rbp':('ebp','bp','bpl'),'rsp':('esp','sp','spl')}
for _i in range(8,16): _subs[f'r{_i}'] = (f'r{_i}d',f'r{_i}w',f'r{_i}b')
for _c, (_e,_w,_b) in _subs.items():
    CANON[_c]=(_c,8,0); CANON[_e]=(_c,4,0); CANON[_w]=(_c,2,0); CANON[_b]=(_c,1,0)
for _h,_cr in (('ah','rax'),('bh','rbx'),('ch','rcx'),('dh','rdx')): CANON[_h]=(_cr,1,1)
UCREG = {n: getattr(ux, "UC_X86_REG_"+n.upper()) for n in set(c for c,_,_ in CANON.values())}

def tainted(bv):
    return any(v.startswith("serial") for v in bv.variables)

class SymState:
    def __init__(self, uc): self.uc=uc; self.reg={}; self.mem={}
    def _creg(self, cr): return claripy.BVV(self.uc.reg_read(UCREG[cr]) & ((1<<64)-1), 64)
    def getreg(self, name):
        info = CANON.get(name.lower())
        if info is None: return claripy.BVV(0,64), False
        cr,sz,off = info
        v = self.reg[cr] if cr in self.reg else self._creg(cr)
        return claripy.Extract(off*8+sz*8-1, off*8, v), (cr in self.reg)
    def setreg(self, name, val):
        info = CANON.get(name.lower())
        if info is None: return
        cr,sz,off = info
        if sz==8: new=val
        elif sz==4: new=claripy.ZeroExt(32, val)
        else:
            cur = self.reg[cr] if cr in self.reg else self._creg(cr); pieces=[]
            if off+sz<8: pieces.append(claripy.Extract(63,(off+sz)*8,cur))
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
    arch = MODE64
    packed = Path(sys.argv[1]).resolve()
    serial = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0xAABBCCDD
    T.ACTIVE_CATALOG = Catalog(find_or_capture_catalog((Path.cwd(), Path(T.__file__).resolve().parent.parent), arch), arch)
    ensure_catalog_arch(T.ACTIVE_CATALOG, arch)
    pe = load_pe(packed.read_bytes()); ib = pe.OPTIONAL_HEADER.ImageBase
    entry = ib + pe.OPTIONAL_HEADER.AddressOfEntryPoint
    import_slots = collect_imports(pe)
    uc = Uc(UC_ARCH_X86, arch.uc_mode)
    mapped_start, mapped_end = map_pe(uc, pe)
    emu_bytes = pe_memory_image(load_pe(require_catalog().ntdll_bytes))
    fvb = file_view_base_for(arch, mapped_start, mapped_end, (len(emu_bytes)+0xfff)&~0xfff)
    uc.mem_map(fvb,(len(emu_bytes)+0xfff)&~0xfff,UC_PROT_ALL); uc.mem_write(fvb, emu_bytes)
    module_bases, synth, export_lookup = map_emu_windows_modules(uc, import_slots, arch)
    proc = ModuleImage(packed.name, mapped_start, pe.OPTIONAL_HEADER.SizeOfImage, entry, str(packed))
    rsp = map_synthetic_process_state(uc, module_bases, proc, arch)
    for _,r in arch.gpr: uc.reg_write(r,0)
    uc.reg_write(arch.sp, rsp); uc.reg_write(ux.UC_X86_REG_EFLAGS, 0x202); uc.reg_write(arch.ip, entry)
    tracer = Tracer(uc, mapped_start, mapped_end, synth, pe, module_bases, export_lookup, progress=lambda m:None, arch=arch)
    tracer.module_paths = {b: f"C:\\Windows\\System32\\{n}" for n,b in module_bases.items()}
    tracer.module_paths[mapped_start]=str(packed); tracer.module_paths[0]="C:\\host.exe"
    tracer.files.files[packed.name.lower()]=packed.read_bytes()
    tracer.encoded_string_keys = tuple(recover_keys(bytes(pe.__data__)))
    tracer.files.files["ntdll.dll"]=require_catalog().ntdll_bytes
    tracer.syscall_catalog = load_system_syscall_catalog()
    check_license = mapped_start + CHECK_RVA

    serial_sym = claripy.BVS("serial", 32)
    sym = SymState(uc)
    md = Cs(CS_ARCH_X86, CS_MODE_64); md.detail = True
    captures = []; unhandled = {}; tlog = []; M = (1<<64)-1

    def opval(insn, op):
        if op.type == x86.X86_OP_REG:
            return sym.getreg(insn.reg_name(op.reg))
        if op.type == x86.X86_OP_IMM:
            return claripy.BVV(op.imm & ((1<<(op.size*8))-1), op.size*8), False
        if op.type == x86.X86_OP_MEM:
            m=op.mem; a=m.disp
            if m.base:
                bn=insn.reg_name(m.base)
                a += uc.reg_read(UCREG[bn]) if bn in UCREG else (uc.reg_read(ux.UC_X86_REG_RIP)+insn.size if bn=="rip" else 0)
            if m.index:
                xn=insn.reg_name(m.index)
                if xn in UCREG: a += uc.reg_read(UCREG[xn])*m.scale
            return sym.getmem(a & ((1<<64)-1), op.size)
        return claripy.BVV(0, op.size*8), False
    def ea(insn, op):
        m=op.mem; a=m.disp
        if m.base and insn.reg_name(m.base) in UCREG: a+=uc.reg_read(UCREG[insn.reg_name(m.base)])
        if m.index and insn.reg_name(m.index) in UCREG: a+=uc.reg_read(UCREG[insn.reg_name(m.index)])*m.scale
        return a & ((1<<64)-1)
    def setdst(insn, op, val):
        if op.type==x86.X86_OP_REG: sym.setreg(insn.reg_name(op.reg), val)
        elif op.type==x86.X86_OP_MEM: sym.setmem(ea(insn,op), val, op.size)
    def ext(b, bits):
        if b.size()==bits: return b
        return claripy.ZeroExt(bits-b.size(), b) if b.size()<bits else claripy.Extract(bits-1,0,b)

    def step(insn):
        mn=insn.mnemonic; ops=insn.operands
        vals=[opval(insn,o) for o in ops]
        for bv_i,t_i in vals:
            if not t_i:
                try:
                    if (not bv_i.symbolic) and bv_i.args[0]==MARKER:
                        for bv_j,t_j in vals:
                            if t_j: captures.append(bv_j)
                except Exception: pass
        A=lambda i: vals[i][0]
        # stack-machine moves: push/pop carry taint through [rsp] (implicit operand) -> handle pre-gate
        if mn=="push":
            v=ext(A(0),64); rsp=uc.reg_read(ux.UC_X86_REG_RSP); sym.setmem((rsp-8)&M, v, 8)
            if tainted(v) and len(tlog)<140: tlog.append((hex(insn.address),mn,insn.op_str,"->stk"))
            return
        if mn=="pop":
            rsp=uc.reg_read(ux.UC_X86_REG_RSP); v,t=sym.getmem(rsp&M,8); setdst(insn,ops[0],ext(v,ops[0].size*8))
            if t and len(tlog)<140: tlog.append((hex(insn.address),mn,insn.op_str,"stk->"))
            return
        if not any(t for _,t in vals): return
        if len(tlog)<140: tlog.append((hex(insn.address),mn,insn.op_str))
        res=None; dst=ops[0] if ops else None
        if mn=="mov": res=A(1)
        elif mn=="movzx": res=claripy.ZeroExt(ops[0].size*8 - A(1).size(), A(1))
        elif mn in ("movsx","movsxd"): res=claripy.SignExt(ops[0].size*8 - A(1).size(), A(1))
        elif mn=="cdqe": res=claripy.SignExt(32, A(0))
        elif mn=="lea":
            m=ops[1].mem; a=claripy.BVV(m.disp & ((1<<64)-1),64)
            if m.base and insn.reg_name(m.base) in CANON: a=a+ext(sym.getreg(insn.reg_name(m.base))[0],64)
            if m.index and insn.reg_name(m.index) in CANON: a=a+ext(sym.getreg(insn.reg_name(m.index))[0],64)*m.scale
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
        elif mn=="not": res=~A(0)
        elif mn=="neg": res=claripy.BVV(0,A(0).size())-A(0)
        elif mn=="inc": res=A(0)+1
        elif mn=="dec": res=A(0)-1
        elif mn=="bswap":
            a=A(0); n=a.size()//8; res=claripy.Concat(*[claripy.Extract(i*8+7,i*8,a) for i in range(n)])
        elif mn=="xchg":
            setdst(insn,ops[0],A(1)); setdst(insn,ops[1],A(0)); return
        elif mn=="movabs": res=A(1)
        elif mn in ("shrd","shld"):
            a=A(0); b=ext(A(1),A(0).size()); bits=a.size()
            c=A(2); cnt=((c.args[0] if not c.symbolic else 0) & (bits-1))
            if cnt==0: res=a
            elif mn=="shrd": res=claripy.LShR(a,cnt) | (b << (bits-cnt))
            else: res=(a << cnt) | claripy.LShR(b,(bits-cnt))
            dst=ops[0]
        elif mn=="bt": return
        elif mn in ("bts","btr","btc"):
            a=A(0); bi=A(1)
            if bi.symbolic: unhandled[mn]=unhandled.get(mn,0)+1; return
            k=(bi.args[0]) & (a.size()-1); mask=claripy.BVV(1<<k, a.size())
            res=(a|mask) if mn=="bts" else ((a & ~mask) if mn=="btr" else (a^mask)); dst=ops[0]
        elif mn in ("cmp","test","call","jmp","ret","nop"): return
        else:
            unhandled[mn]=unhandled.get(mn,0)+1; return
        if res is not None and dst is not None: setdst(insn, dst, res)

    with TraceHooks(tracer, arch.peb_base, PAGE_SIZE):
        uc.emu_start(entry, 0)
        tracer.check_restored_entry = lambda a: False; tracer.stop_reason=None
        def _gvi(self, symbol, rcx, rdx, r8, r9):
            self.uc.mem_write(r9, struct.pack("<I", serial & 0xffffffff))
            for i in range(4): sym.mem[r9+i]=claripy.Extract(i*8+7,i*8,serial_sym)
            return 1, {}
        tracer._handlers=dict(tracer._handlers); tracer._handlers["getvolumeinformationa"]=(_gvi,8)
        errs=[]
        def hook(uc_, address, size, ud):
            try: insn=next(md.disasm(bytes(uc_.mem_read(address,size)), address), None)
            except Exception: return
            if insn is not None:
                try: step(insn)
                except Exception as e:
                    if len(errs)<3:
                        import traceback
                        errs.append((hex(address), insn.mnemonic, insn.op_str, traceback.format_exc()))
        for a in (KEYBUF, RET_SENTINEL):
            try: uc.mem_map(a & ~0xfff, 0x1000, UC_PROT_ALL)
            except UcError: pass
        uc.mem_write(KEYBUF, f"{MARKER:08X}".encode()+b"\x00")
        sp=((uc.reg_read(arch.sp)&~0xF)-0x800)&~0xF
        uc.mem_write(sp, struct.pack("<Q", RET_SENTINEL))
        uc.reg_write(arch.sp, sp); uc.reg_write(ux.UC_X86_REG_RCX, KEYBUF); uc.reg_write(ux.UC_X86_REG_RIP, check_license)
        h=uc.hook_add(UC_HOOK_CODE, hook, None, mapped_start, mapped_end)
        uc.emu_start(check_license, RET_SENTINEL, timeout=600*1000*1000)
        uc.hook_del(h)

    print(f"\n== blind SYMBOLIC recovery (serial symbolized) ==")
    print(f"captured {len(captures)} candidates; unhandled tainted mnemonics: {unhandled}")
    print(f"tainted-instruction chain ({len(tlog)} logged):")
    for t in tlog[:60]: print("   ", t)
    print(f"step() exceptions ({len(errs)}):")
    for e in errs[:25]: print("   ", e)
    known = c0_expected_key(serial); best=None
    for expr in captures:
        try:
            e = ext(expr, 32)
            got = claripy.Solver().eval(e.replace(serial_sym, claripy.BVV(serial,32)), 1)[0]
            if got == known: best=e; break
        except Exception: continue
    if best is None:
        print("  no captured expression validated (coverage gap or MBA-hidden compare)"); return
    print(f"  VALIDATED: symbolic want(serial) reproduces key {known:08X} for serial {serial:#010x}")
    simp = claripy.simplify(best)
    print(f"  AST depth raw/simplified: {best.depth}/{simp.depth}")
    print(f"  simplified want(serial) [first 1500 chars]:\n{str(simp)[:1500]}")
    oks=[]
    for s2 in (0x11112222, 0xCAFEBABE, 0x00000001, 0xFFFFFFFF):
        try: oks.append(claripy.Solver().eval(best.replace(serial_sym, claripy.BVV(s2,32)),1)[0]==c0_expected_key(s2))
        except Exception: oks.append(False)
    print(f"  cross-validation on 4 more serials vs C0: {oks}  -> {'ALL CORRECT' if all(oks) else 'mismatch'}")

if __name__ == "__main__":
    main()
