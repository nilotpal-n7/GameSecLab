#!/usr/bin/env python3
r"""REAForge devirt — arch-agnostic taint-symbolic engine (x86-32 and x86-64).

One engine for both bitnesses. A SymEngine shadows concrete Unicorn execution with a claripy
symbolic state for tainted values: tainted registers/memory carry symbolic expressions, concrete
values stay in Unicorn. Drive it by calling step(insn) from a UC_HOOK_CODE hook.

Used by the whole devirt pipeline (recover / peel / prove) for both the x64 license_app campaign
and the x86 Dead Cells (libhl.dll) campaign — the arch is a parameter, not a fork.
"""
from __future__ import annotations

import claripy
import unicorn.x86_const as ux
from capstone import x86


def build_canon(bits):
    """register-aliasing table name -> (canonical_reg, size_bytes, byte_offset) for the given arch."""
    canon = {}
    if bits == 64:
        subs = {'rax':('eax','ax','al'),'rbx':('ebx','bx','bl'),'rcx':('ecx','cx','cl'),'rdx':('edx','dx','dl'),
                'rsi':('esi','si','sil'),'rdi':('edi','di','dil'),'rbp':('ebp','bp','bpl'),'rsp':('esp','sp','spl')}
        for i in range(8, 16): subs[f'r{i}'] = (f'r{i}d', f'r{i}w', f'r{i}b')
        for c, (e, w, b) in subs.items():
            canon[c]=(c,8,0); canon[e]=(c,4,0); canon[w]=(c,2,0); canon[b]=(c,1,0)
        for h, cr in (('ah','rax'),('bh','rbx'),('ch','rcx'),('dh','rdx')): canon[h]=(cr,1,1)
        full = 8
    else:
        subs = {'eax':('ax','al'),'ebx':('bx','bl'),'ecx':('cx','cl'),'edx':('dx','dl'),
                'esi':('si','sil'),'edi':('di','dil'),'ebp':('bp','bpl'),'esp':('sp','spl')}
        for c, (w, b) in subs.items():
            canon[c]=(c,4,0); canon[w]=(c,2,0); canon[b]=(c,1,0)
        for h, cr in (('ah','eax'),('bh','ebx'),('ch','ecx'),('dh','edx')): canon[h]=(cr,1,1)
        full = 4
    ucreg = {n: getattr(ux, "UC_X86_REG_"+n.upper()) for n in set(c for c, _, _ in canon.values())}
    return canon, ucreg, full


class SymEngine:
    def __init__(self, uc, bits=32, taint_prefix="inp", record=False):
        self.uc = uc; self.bits = bits; self.ptr = bits // 8; self.M = (1 << bits) - 1
        self.taint_prefix = taint_prefix
        self.CANON, self.UCREG, self.full = build_canon(bits)
        self.reg = {}; self.mem = {}; self.sflags = {}
        self.record = record; self.snaps = []; self._snapk = set()
        self.unhandled = {}; self.errs = []
        self.marker = None; self.captures = []   # opt-in: capture tainted operands that meet a concrete marker
        self._areg = {1:"al",2:"ax",4:"eax",8:"rax"}
        self._dreg = {2:"dx",4:"edx",8:"rdx"}

    # ---- taint ----
    def tainted(self, bv):
        return any(v.startswith(self.taint_prefix) for v in bv.variables)

    def _rec(self, res):
        if not (self.record and self.tainted(res)): return
        try:
            r = res if res.size()==32 else (claripy.Extract(31,0,res) if res.size()>32 else res)
            k = hash(r)
            if k not in self._snapk and len(self.snaps) < 20000:
                self._snapk.add(k); self.snaps.append(r)
        except Exception: pass

    # ---- register / memory symbolic store ----
    def _creg(self, cr): return claripy.BVV(self.uc.reg_read(self.UCREG[cr]) & self.M, self.bits)
    def getreg(self, name):
        info = self.CANON.get(name.lower())
        if info is None: return claripy.BVV(0, self.bits), False
        cr, sz, off = info
        v = self.reg[cr] if cr in self.reg else self._creg(cr)
        return claripy.Extract(off*8+sz*8-1, off*8, v), (cr in self.reg)
    def setreg(self, name, val):
        info = self.CANON.get(name.lower())
        if info is None: return
        cr, sz, off = info
        if sz == self.full: new = val
        elif self.bits == 64 and sz == 4: new = claripy.ZeroExt(32, val)   # x64: writing e** zeroes upper 32
        else:
            cur = self.reg[cr] if cr in self.reg else self._creg(cr); pieces = []
            if off+sz < self.full: pieces.append(claripy.Extract(self.full*8-1, (off+sz)*8, cur))
            pieces.append(val)
            if off > 0: pieces.append(claripy.Extract(off*8-1, 0, cur))
            new = pieces[0] if len(pieces)==1 else claripy.Concat(*pieces)
        if self.tainted(new): self.reg[cr] = new
        else: self.reg.pop(cr, None)
    def getmem(self, addr, sz):
        bs = []
        for i in range(sz):
            b = self.mem.get(addr+i)
            if b is None:
                try: b = claripy.BVV(self.uc.mem_read(addr+i, 1)[0], 8)
                except Exception: b = claripy.BVV(0, 8)
            bs.append(b)
        return (claripy.Concat(*reversed(bs)) if sz > 1 else bs[0]), any((addr+i) in self.mem for i in range(sz))
    def setmem(self, addr, val, sz):
        for i in range(sz):
            byte = claripy.Extract(i*8+7, i*8, val)
            if self.tainted(byte): self.mem[addr+i] = byte
            else: self.mem.pop(addr+i, None)

    # ---- operand helpers ----
    def opval(self, insn, op):
        if op.type == x86.X86_OP_REG: return self.getreg(insn.reg_name(op.reg))
        if op.type == x86.X86_OP_IMM: return claripy.BVV(op.imm & ((1<<(op.size*8))-1), op.size*8), False
        if op.type == x86.X86_OP_MEM:
            m = op.mem; a = m.disp
            if m.base:
                bn = insn.reg_name(m.base)
                if bn in self.UCREG: a += self.uc.reg_read(self.UCREG[bn])
                elif bn in ("rip","eip"): a += self.uc.reg_read(ux.UC_X86_REG_RIP if self.bits==64 else ux.UC_X86_REG_EIP) + insn.size
            if m.index:
                xn = insn.reg_name(m.index)
                if xn in self.UCREG: a += self.uc.reg_read(self.UCREG[xn]) * m.scale
            return self.getmem(a & self.M, op.size)
        return claripy.BVV(0, op.size*8), False
    def ea(self, insn, op):
        m = op.mem; a = m.disp
        if m.base and insn.reg_name(m.base) in self.UCREG: a += self.uc.reg_read(self.UCREG[insn.reg_name(m.base)])
        if m.index and insn.reg_name(m.index) in self.UCREG: a += self.uc.reg_read(self.UCREG[insn.reg_name(m.index)]) * m.scale
        return a & self.M
    def setdst(self, insn, op, val):
        if op.type == x86.X86_OP_REG: self.setreg(insn.reg_name(op.reg), val)
        elif op.type == x86.X86_OP_MEM: self.setmem(self.ea(insn, op), val, op.size)
    @staticmethod
    def ext(b, bits):
        if b.size() == bits: return b
        return claripy.ZeroExt(bits-b.size(), b) if b.size() < bits else claripy.Extract(bits-1, 0, b)

    # ---- symbolic EFLAGS ----
    EFL = {'CF':0,'PF':2,'ZF':6,'SF':7,'OF':11}
    FLAGS_SET = {'add':'CF OF SF ZF PF','adc':'CF OF SF ZF PF','sub':'CF OF SF ZF PF','sbb':'CF OF SF ZF PF',
                 'cmp':'CF OF SF ZF PF','and':'CF OF SF ZF PF','or':'CF OF SF ZF PF','xor':'CF OF SF ZF PF','test':'CF OF SF ZF PF',
                 'inc':'OF SF ZF PF','dec':'OF SF ZF PF','neg':'CF OF SF ZF PF','shl':'CF OF SF ZF PF','sal':'CF OF SF ZF PF',
                 'shr':'CF OF SF ZF PF','sar':'CF OF SF ZF PF','shrd':'CF SF ZF PF','shld':'CF SF ZF PF','rol':'CF OF','ror':'CF OF',
                 'imul':'CF OF','mul':'CF OF','bt':'CF','bts':'CF','btr':'CF','btc':'CF','bsf':'ZF','bsr':'ZF','rcl':'CF OF','rcr':'CF OF'}
    def get_flag(self, f):
        if f in self.sflags: return self.sflags[f]
        return claripy.BoolV(bool((self.uc.reg_read(ux.UC_X86_REG_EFLAGS) >> self.EFL[f]) & 1))
    @staticmethod
    def _msb(x): return claripy.Extract(x.size()-1, x.size()-1, x) == claripy.BVV(1, 1)
    @staticmethod
    def _par(x):
        p = claripy.Extract(0,0,x)
        for i in range(1,8): p = p ^ claripy.Extract(i,i,x)
        return p == claripy.BVV(0,1)
    def set_arith_flags(self, mn, a, b, res):
        cl = claripy; N = res.size(); sf = self.sflags
        sf['ZF'] = (res==cl.BVV(0,N)); sf['SF'] = self._msb(res); sf['PF'] = self._par(res)
        if mn in ('add','adc'):
            w = cl.ZeroExt(1,a)+cl.ZeroExt(1,b); sf['CF'] = cl.Extract(N,N,w)==cl.BVV(1,1)
            sf['OF'] = cl.And(cl.Not((self._msb(a)!=self._msb(b))), (self._msb(res)!=self._msb(a)))
        elif mn in ('sub','cmp','sbb'):
            sf['CF'] = cl.ULT(a,b); sf['OF'] = cl.And((self._msb(a)!=self._msb(b)), (self._msb(res)!=self._msb(a)))
        elif mn in ('and','or','xor','test'): sf['CF'] = cl.BoolV(False); sf['OF'] = cl.BoolV(False)
        elif mn == 'neg': sf['CF'] = (a!=cl.BVV(0,N)); sf['OF'] = cl.BoolV(False)
    def cc(self, nm):
        cl = claripy; g = self.get_flag
        T = {'o':lambda:g('OF'),'no':lambda:cl.Not(g('OF')),'s':lambda:g('SF'),'ns':lambda:cl.Not(g('SF')),
             'e':lambda:g('ZF'),'z':lambda:g('ZF'),'ne':lambda:cl.Not(g('ZF')),'nz':lambda:cl.Not(g('ZF')),
             'b':lambda:g('CF'),'c':lambda:g('CF'),'nae':lambda:g('CF'),'ae':lambda:cl.Not(g('CF')),'nb':lambda:cl.Not(g('CF')),'nc':lambda:cl.Not(g('CF')),
             'be':lambda:cl.Or(g('CF'),g('ZF')),'na':lambda:cl.Or(g('CF'),g('ZF')),'a':lambda:cl.And(cl.Not(g('CF')),cl.Not(g('ZF'))),'nbe':lambda:cl.And(cl.Not(g('CF')),cl.Not(g('ZF'))),
             'l':lambda:(g('SF')!=g('OF')),'nge':lambda:(g('SF')!=g('OF')),'ge':lambda:cl.Not((g('SF')!=g('OF'))),'nl':lambda:cl.Not((g('SF')!=g('OF'))),
             'le':lambda:cl.Or(g('ZF'),(g('SF')!=g('OF'))),'ng':lambda:cl.Or(g('ZF'),(g('SF')!=g('OF'))),'g':lambda:cl.And(cl.Not(g('ZF')),cl.Not((g('SF')!=g('OF')))),'nle':lambda:cl.And(cl.Not(g('ZF')),cl.Not((g('SF')!=g('OF')))),
             'p':lambda:g('PF'),'pe':lambda:g('PF'),'np':lambda:cl.Not(g('PF')),'po':lambda:cl.Not(g('PF'))}
        return T[nm]()
    @staticmethod
    def ifsel(cond, t, f):
        return (t if cond.is_true() else f) if not cond.symbolic else claripy.If(cond, t, f)

    # ---- the instruction stepper ----
    def step(self, insn):
        mn = insn.mnemonic; ops = insn.operands
        vals = [self.opval(insn, o) for o in ops]
        if self.marker is not None:          # capture want: a tainted operand meeting the concrete marker
            for bv, t in vals:
                if (not t) and (not bv.symbolic):
                    try:
                        if bv.args[0] == self.marker:
                            for bj, tj in vals:
                                if tj: self.captures.append(bj)
                    except Exception: pass
        if mn in self.FLAGS_SET:
            for fn in self.FLAGS_SET[mn].split(): self.sflags.pop(fn, None)
        A = lambda i: vals[i][0]
        cl = claripy; ext = self.ext
        if mn == "push":
            v = ext(A(0), self.bits); sp = self.uc.reg_read(self.UCREG["rsp" if self.bits==64 else "esp"])
            self.setmem((sp-self.ptr) & self.M, v, self.ptr); return
        if mn == "pop":
            sp = self.uc.reg_read(self.UCREG["rsp" if self.bits==64 else "esp"]); v,_ = self.getmem(sp & self.M, self.ptr)
            self.setdst(insn, ops[0], ext(v, ops[0].size*8)); return
        if mn in ("mul","imul") and len(ops) == 1:          # implicit (E/R)DX:(E/R)AX = (E/R)AX * src
            sz = ops[0].size; a = self.getreg(self._areg[sz])[0]; src = A(0)
            if not (self.tainted(a) or self.tainted(src)): return
            prod = (cl.SignExt(sz*8,a)*cl.SignExt(sz*8,src)) if mn=="imul" else (cl.ZeroExt(sz*8,a)*cl.ZeroExt(sz*8,src))
            if sz == 1: self.setreg("ax", prod)
            else:
                self.setreg(self._areg[sz], cl.Extract(sz*8-1,0,prod)); self.setreg(self._dreg[sz], cl.Extract(2*sz*8-1,sz*8,prod))
            return
        if not any(t for _, t in vals): return
        res = None; dst = ops[0] if ops else None
        if mn == "mov": res = A(1)
        elif mn == "movzx": res = cl.ZeroExt(ops[0].size*8 - A(1).size(), A(1))
        elif mn in ("movsx","movsxd"): res = cl.SignExt(ops[0].size*8 - A(1).size(), A(1))
        elif mn == "cdqe": res = cl.SignExt(32, A(0))
        elif mn == "lea":
            m = ops[1].mem; a = cl.BVV(m.disp & self.M, self.bits)
            if m.base and insn.reg_name(m.base) in self.CANON: a = a + ext(self.getreg(insn.reg_name(m.base))[0], self.bits)
            if m.index and insn.reg_name(m.index) in self.CANON: a = a + ext(self.getreg(insn.reg_name(m.index))[0], self.bits) * m.scale
            res = cl.Extract(ops[0].size*8-1, 0, a)
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
            elif mn=="shr": res=cl.LShR(a,b)
            elif mn=="sar": res=a>>b
            elif mn=="rol": res=cl.RotateLeft(a,b)
            elif mn=="ror": res=cl.RotateRight(a,b)
            if mn in ('add','sub','and','or','xor') and b is not None: self.set_arith_flags(mn,a,b,res)
        elif mn == "not": res = ~A(0)
        elif mn == "neg": res = cl.BVV(0,A(0).size())-A(0)
        elif mn == "inc": res = A(0)+1
        elif mn == "dec": res = A(0)-1
        elif mn == "bswap":
            a=A(0); n=a.size()//8; res=cl.Concat(*[cl.Extract(i*8+7,i*8,a) for i in range(n)])
        elif mn == "xchg": self.setdst(insn,ops[0],A(1)); self.setdst(insn,ops[1],A(0)); return
        elif mn == "movabs": res = A(1)
        elif mn in ("shrd","shld"):
            a=A(0); b=ext(A(1),A(0).size()); bits=a.size(); c=A(2); cnt=((c.args[0] if not c.symbolic else 0)&(bits-1))
            if cnt==0: res=a
            elif mn=="shrd": res=cl.LShR(a,cnt)|(b<<(bits-cnt))
            else: res=(a<<cnt)|cl.LShR(b,(bits-cnt))
            dst=ops[0]
        elif mn in ("bt","bts","btr","btc"):
            a=A(0); bi=ext(A(1),a.size()) & cl.BVV(a.size()-1,a.size()); mask=cl.BVV(1,a.size())<<bi
            self.sflags['CF']=((cl.LShR(a,bi) & cl.BVV(1,a.size()))==cl.BVV(1,a.size()))
            if mn=="bt": return
            res=(a|mask) if mn=="bts" else ((a & ~mask) if mn=="btr" else (a^mask)); dst=ops[0]
        elif mn == "cmp": a=A(0); b=ext(A(1),A(0).size()); self.set_arith_flags('sub',a,b,a-b); return
        elif mn == "test": a=A(0); b=ext(A(1),A(0).size()); self.set_arith_flags('and',a,b,a&b); return
        elif mn == "adc":
            a=A(0); b=ext(A(1),A(0).size()); cf=self.ifsel(self.get_flag('CF'),cl.BVV(1,a.size()),cl.BVV(0,a.size()))
            res=a+b+cf; self.set_arith_flags('adc',a,b+cf,res); dst=ops[0]
        elif mn == "sbb":
            a=A(0); b=ext(A(1),A(0).size()); cf=self.ifsel(self.get_flag('CF'),cl.BVV(1,a.size()),cl.BVV(0,a.size()))
            res=a-b-cf; self.set_arith_flags('sub',a,b+cf,res); dst=ops[0]
        elif mn.startswith("cmov"): res=self.ifsel(self.cc(mn[4:]), A(1), A(0)); dst=ops[0]
        elif mn.startswith("set") and len(mn)<=5: res=self.ifsel(self.cc(mn[3:]), cl.BVV(1,8), cl.BVV(0,8)); dst=ops[0]
        elif mn in ("bsf","bsr"):
            b=A(1); n=b.size(); idx=cl.BVV(0,n)
            for k in (range(n-1,-1,-1) if mn=="bsf" else range(0,n)):
                idx=cl.If(cl.Extract(k,k,b)==cl.BVV(1,1), cl.BVV(k,n), idx)
            res=idx; self.sflags['ZF']=(b==cl.BVV(0,n)); dst=ops[0]
        elif mn in ("rcl","rcr"):
            a=A(0); bits=a.size(); c=A(1); cnt=((c.args[0] if not c.symbolic else 1)%(bits+1))
            cf=self.ifsel(self.get_flag('CF'),cl.BVV(1,1),cl.BVV(0,1))
            for _ in range(cnt):
                if mn=="rcl": newcf=cl.Extract(bits-1,bits-1,a); a=(a<<1)|cl.ZeroExt(bits-1,cf); cf=newcf
                else: newcf=cl.Extract(0,0,a); a=cl.LShR(a,1)|(cl.ZeroExt(bits-1,cf)<<(bits-1)); cf=newcf
            res=a; self.sflags['CF']=(cf==cl.BVV(1,1)); dst=ops[0]
        elif mn in ("call","jmp","ret","nop","leave","cdq","cwde"): return
        else: self.unhandled[mn]=self.unhandled.get(mn,0)+1; return
        if res is not None and mn in ('shl','sal','shr','sar','shrd','shld','inc','dec','imul','rol','ror'):
            self.sflags['ZF']=(res==cl.BVV(0,res.size())); self.sflags['SF']=self._msb(res); self.sflags['PF']=self._par(res)
        if res is not None and dst is not None:
            self.setdst(insn, dst, res); self._rec(res)
