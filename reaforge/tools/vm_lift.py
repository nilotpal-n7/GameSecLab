#!/usr/bin/env python3
r"""Themida VM-region lifter — recover a virtualized function's semantics from a dump (no oracle).

Themida points a function's entry at a `jmp` into its SecureEngine VM (Falcon in the demo), so the
real code is never native on disk. This lifter recovers what the function computes, in the same
spirit as the VMProtect devirt engine — concrete emulation of the real VM from a dump, no hardcoded
handler model:

  1. STATIC   — read the dump, recover the native prologue bytes before the `jmp` into the VM, and
                report the VM entry target (localize the VM).
  2. EMULATE  — map the full-memory dump into Unicorn and run the function concretely from its native
                entry, stubbing the few OS calls it makes so machine state is deterministic
                (GetVolumeInformationA -> our serial; strtoul -> parse the key). The whole SecureEngine
                VM runs; we read off the 32-bit constant the parsed key is compared against = `want`.
                (Themida's VM juggles values through so many stack slots that byte-level taint does not
                survive it — which is exactly why it resists symbolic devirt — so we capture the
                constant concretely from a distinctive probe key instead.)
  3. VALIDATE — oracle-free self-check: a wrong key must reject, and feeding `want` back as the key
                must ACCEPT. If a reference keygen is given, also cross-check want == keygen(serial)
                (the oracle only checks the answer; it never drives the recovery).

  python -m reaforge.tools.vm_lift <dump> <main_module_substr> <func_rva_hex> [serial_hex]
  python -m reaforge.tools.vm_lift form <dump> <main_module_substr> <func_rva_hex> [serial_hex]

The plain form recovers the compared constant (self-validated). The `form` subcommand lifts the full
arithmetic FORM: taint mid, extract the symbolic want(mid), and SMT-prove the recovered recurrence
over all 2^32 mid via reaforge.core.peel.prove_recurrence.
"""
from __future__ import annotations

import os
import sys
from collections import Counter

from capstone import CS_ARCH_X86, CS_MODE_64, Cs, x86
from unicorn import UC_ARCH_X86, UC_HOOK_CODE, UC_MODE_64, UC_PROT_ALL, Uc, UcError
from unicorn.x86_const import (
    UC_X86_REG_EAX,
    UC_X86_REG_GS_BASE,
    UC_X86_REG_R9,
    UC_X86_REG_RAX,
    UC_X86_REG_RCX,
    UC_X86_REG_RIP,
    UC_X86_REG_RSP,
)

from reaforge.tools.themida_unwrap import export_map, load, map_all

KEY_BUF = 0x5000_0000
RET_SENTINEL = 0x5000_0800      # return address we push; emulation stops cleanly when RIP lands here
STACK_BASE, STACK_SZ = 0x7F0000000000, 0x200000
FLAG_OPS = ("cmp", "sub", "test", "xor")


def native_prologue(rdr, va, md, show=print):
    """Recover the native instructions before the jmp into the VM; return (insns, vm_entry)."""
    insns, vm_entry = [], None
    for ins in md.disasm(rdr.read(va, 0x40), va):
        insns.append((ins.address, ins.mnemonic, ins.op_str))
        if ins.mnemonic == "jmp":
            try: vm_entry = int(ins.op_str, 16)
            except ValueError: vm_entry = None
            break
    show("  native prologue (before the VM):")
    for a, m, o in insns:
        show(f"    {a:#x}  {m:8} {o}")
    show(f"  -> VM entry: {vm_entry:#x}" if vm_entry else "  -> no jmp found (not VM'd here?)")
    return insns, vm_entry


def emulate(rdr, segs, teb, md, amap, func_va, key, serial, max_insns=4_000_000):
    """Run the VM'd function concretely once. Returns (want_or_None, ret_eax, stats)."""
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    map_all(uc, rdr, segs)
    for addr, sz in ((STACK_BASE, STACK_SZ), (KEY_BUF & ~0xFFF, 0x2000)):
        try: uc.mem_map(addr, sz, UC_PROT_ALL)
        except UcError: pass
    if teb: uc.reg_write(UC_X86_REG_GS_BASE, teb)
    uc.mem_write(KEY_BUF, key + b"\x00")
    rsp = STACK_BASE + STACK_SZ // 2
    uc.mem_write(rsp, RET_SENTINEL.to_bytes(8, "little"))     # caller return addr -> clean stop
    uc.reg_write(UC_X86_REG_RSP, rsp)
    uc.reg_write(UC_X86_REG_RCX, KEY_BUF)                     # arg0 = const char *key

    api_at = amap
    st = {"n": 0, "want": [], "got": None, "ret_eax": None, "stopped": None,
          "getvol": 0, "strtoul": 0}

    def ret_with(u, rax):
        sp = u.reg_read(UC_X86_REG_RSP)
        u.reg_write(UC_X86_REG_RIP, int.from_bytes(u.mem_read(sp, 8), "little"))
        u.reg_write(UC_X86_REG_RSP, sp + 8)
        u.reg_write(UC_X86_REG_RAX, rax)

    def hook(u, addr, size, ud):
        if addr == RET_SENTINEL:                             # function returned to our sentinel
            st["ret_eax"] = u.reg_read(UC_X86_REG_EAX) & 0xFFFFFFFF
            u.emu_stop(); return
        st["n"] += 1
        if st["n"] > max_insns:
            st["stopped"] = f"instruction cap {max_insns}"; u.emu_stop(); return
        name = api_at.get(addr, "")
        ln = name.lower()
        if ln.endswith("!getvolumeinformationa"):
            st["getvol"] += 1
            r9 = u.reg_read(UC_X86_REG_R9)
            if r9: u.mem_write(r9, int(serial).to_bytes(4, "little"))
            ret_with(u, 1); return
        if ln.split("!")[-1] in ("strtoul", "_strtoul"):
            st["strtoul"] += 1
            kp = u.reg_read(UC_X86_REG_RCX)
            s = b""
            for i in range(32):
                c = u.mem_read(kp + i, 1)
                if c == b"\x00": break
                s += c
            try: val = int(s.decode(errors="ignore"), 16) & 0xFFFFFFFF
            except ValueError: val = 0
            st["got"] = val; ret_with(u, val); return
        # concrete want-capture: the constant the probe key (got) is checked against
        try:
            ins = next(md.disasm(bytes(u.mem_read(addr, 16)), addr))
        except StopIteration:
            return
        if ins.mnemonic in FLAG_OPS and len(ins.operands) == 2 and st["got"] is not None:
            v0, v1 = _opc(u, ins, ins.operands[0]), _opc(u, ins, ins.operands[1])
            g = st["got"]
            if v0 == g and v1 not in (None, g): st["want"].append(v1)
            elif v1 == g and v0 not in (None, g): st["want"].append(v0)

    h = uc.hook_add(UC_HOOK_CODE, hook)
    try:
        uc.emu_start(func_va, 0, count=0)
    except UcError as e:
        st["stopped"] = st["stopped"] or f"{e} @ {uc.reg_read(UC_X86_REG_RIP):#x}"
    finally:
        uc.hook_del(h)
    want = Counter(st["want"]).most_common(1)[0][0] if st["want"] else None
    return want, st["ret_eax"], st


def lift(dump, mod_sub, func_rva, serial=0x75685AB2, expected_key=None, show=print):
    mod_sub = mod_sub.lower()
    mf, rdr, segs, mods, teb = load(dump)
    main = next((m for m in mods if mod_sub in os.path.basename(m[0]).lower()), None)
    if not main:
        sys.exit(f"module ~{mod_sub!r} not in dump")
    base = main[1]
    func_va = base + func_rva
    md = Cs(CS_ARCH_X86, CS_MODE_64); md.detail = True
    amap = export_map(mods)

    show(f"== VM-lift ==  {os.path.basename(main[0])} base {base:#x}  func @ {func_va:#x} (rva {func_rva:#x})")
    show("\n[1] STATIC")
    _, vm_entry = native_prologue(rdr, func_va, md, show=show)

    show("\n[2] EMULATE  (full SecureEngine VM, concrete, from the dump)")
    want, eax_probe, st = emulate(rdr, segs, teb, md, amap, func_va, b"DEADBEEF", serial)
    show(f"  traced {st['n']} instrs  (getvol={st['getvol']} strtoul={st['strtoul']})  "
         f"stopped: {st['stopped'] or 'returned'}")
    if want is None:
        show("  could not capture the compared constant — trace did not reach the key check.")
        return {"vm_entry": vm_entry, "want": None, "traced": st["n"], "stopped": st["stopped"]}
    show(f"  recovered want = {want:#010x}   (probe key 'DEADBEEF' -> verdict {eax_probe})")

    show("\n[3] VALIDATE  (oracle-free)")
    _, eax_good, _ = emulate(rdr, segs, teb, md, amap, func_va,
                             f"{want:08X}".encode(), serial)
    show(f"  wrong key 'DEADBEEF' -> verdict {eax_probe}  (expect 0 reject)")
    show(f"  recovered key {want:08X}  -> verdict {eax_good}  (expect 1 accept)")
    self_ok = (eax_probe == 0 and eax_good == 1)
    show(f"  self-check: {'PASS — recovered constant is the valid key' if self_ok else 'inconclusive'}")
    if expected_key is not None:
        exp = expected_key(serial) & 0xFFFFFFFF
        show(f"  oracle cross-check: keygen({serial:#x}) = {exp:#010x} -> "
             f"{'MATCH' if exp == want else 'DIFFER'}")
    return {"vm_entry": vm_entry, "want": want, "verdict_wrong": eax_probe,
            "verdict_recovered": eax_good, "self_ok": self_ok, "traced": st["n"]}


def _emulate_symbolic(rdr, segs, teb, md, amap, func_va, serial, max_insns=4_000_000):
    """Run the VM'd function with `mid` tainted at the GetVolumeInformationA stub and a taint-recording
    SymEngine shadow. Returns (snaps, mid_sym, want) — want captured concretely from the probe key."""
    import claripy

    from reaforge.core.engine import SymEngine
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    map_all(uc, rdr, segs)
    for addr, sz in ((STACK_BASE, STACK_SZ), (KEY_BUF & ~0xFFF, 0x2000)):
        try: uc.mem_map(addr, sz, UC_PROT_ALL)
        except UcError: pass
    if teb: uc.reg_write(UC_X86_REG_GS_BASE, teb)
    uc.mem_write(KEY_BUF, b"DEADBEEF\x00")
    rsp = STACK_BASE + STACK_SZ // 2
    uc.mem_write(rsp, RET_SENTINEL.to_bytes(8, "little"))
    uc.reg_write(UC_X86_REG_RSP, rsp); uc.reg_write(UC_X86_REG_RCX, KEY_BUF)
    eng = SymEngine(uc, bits=64, taint_prefix="inp", record=True)
    mid_sym = claripy.BVS("inp_mid", 32)
    st = {"got": None, "want": [], "n": 0}

    def ret_with(u, rax):
        sp = u.reg_read(UC_X86_REG_RSP)
        u.reg_write(UC_X86_REG_RIP, int.from_bytes(u.mem_read(sp, 8), "little"))
        u.reg_write(UC_X86_REG_RSP, sp + 8); u.reg_write(UC_X86_REG_RAX, rax)

    def hook(u, addr, size, ud):
        if addr == RET_SENTINEL: u.emu_stop(); return
        st["n"] += 1
        if st["n"] > max_insns: u.emu_stop(); return
        ln = amap.get(addr, "").lower()
        if ln.endswith("!getvolumeinformationa"):
            r9 = u.reg_read(UC_X86_REG_R9)
            if r9:
                u.mem_write(r9, int(serial).to_bytes(4, "little"))
                for i in range(4): eng.mem[r9 + i] = claripy.Extract(i * 8 + 7, i * 8, mid_sym)
            ret_with(u, 1); return
        if ln.split("!")[-1] in ("strtoul", "_strtoul"):
            kp = u.reg_read(UC_X86_REG_RCX); s = b""
            for i in range(32):
                c = u.mem_read(kp + i, 1)
                if c == b"\x00": break
                s += c
            try: val = int(s.decode(errors="ignore"), 16) & 0xFFFFFFFF
            except ValueError: val = 0
            st["got"] = val; ret_with(u, val); return
        try: ins = next(md.disasm(bytes(u.mem_read(addr, 16)), addr))
        except StopIteration: return
        if ins.mnemonic in FLAG_OPS and len(ins.operands) == 2 and st["got"] is not None:
            v0, v1 = _opc(u, ins, ins.operands[0]), _opc(u, ins, ins.operands[1])
            g = st["got"]
            if v0 == g and v1 not in (None, g): st["want"].append(v1)
            elif v1 == g and v0 not in (None, g): st["want"].append(v0)
        try: eng.step(ins)
        except Exception: pass

    h = uc.hook_add(UC_HOOK_CODE, hook)
    try: uc.emu_start(func_va, 0, count=0)
    except UcError: pass
    finally: uc.hook_del(h)
    from collections import Counter
    want = Counter(st["want"]).most_common(1)[0][0] if st["want"] else None
    return eng.snaps, mid_sym, want


def lift_form(dump, mod_sub, func_rva, serial=0x75685AB2, expected_key=None, show=print):
    """Lift the VM'd function's full arithmetic FORM: the symbolic want(mid), then prove the recovered
    offset recurrence over all 2^32 mid (reaforge.core.peel.prove_recurrence)."""
    import z3

    from reaforge.core import peel
    mod_sub = mod_sub.lower()
    mf, rdr, segs, mods, teb = load(dump)
    main = next((m for m in mods if mod_sub in os.path.basename(m[0]).lower()), None)
    if not main:
        sys.exit(f"module ~{mod_sub!r} not in dump")
    base = main[1]; func_va = base + func_rva
    md = Cs(CS_ARCH_X86, CS_MODE_64); md.detail = True
    amap = export_map(mods)
    show(f"== VM-lift FORM ==  {os.path.basename(main[0])}  func @ {func_va:#x}  serial {serial:#010x}")
    show("\n[1] EMULATE (mid tainted, taint-recording shadow)")
    snaps, mid_sym, want = _emulate_symbolic(rdr, segs, teb, md, amap, func_va, serial)
    if want is None:
        show("  could not capture want — trace did not reach the key check."); return None
    show(f"  captured want({serial:#x}) = {want:#010x}  from {len(snaps)} recorded snaps")

    # the symbolic want(mid): the smallest recorded expr that evaluates to the captured constant
    Sz = peel.conv(mid_sym)
    def evS(z, sv):
        return z3.simplify(z3.substitute(z, (Sz, z3.BitVecVal(sv & 0xFFFFFFFF, 32)))).as_long() & 0xFFFFFFFF
    best = best_z = None
    for a in snaps:
        if not any(v.startswith("inp") for v in a.variables): continue
        try: z = peel.conv(peel.to32(a))
        except Exception: continue
        try:
            if evS(z, serial) == want and (best_z is None or peel._zsize(z) < peel._zsize(best_z)):
                best, best_z = a, z            # keep the claripy expr for prove_recurrence
        except Exception: pass
    show(f"  symbolic want(mid) extracted: {best is not None}")
    if best is None:
        return None

    show("\n[2] PROVE the recurrence")
    res = peel.prove_recurrence(best_z, Sz, out=show)

    show("\n[3] VALIDATE (oracle-free)")
    pts = [serial, 0x12345678, 0xAABBCCDD, 0x00000000, 0xFFFFFFFF, 0xDEADBEEF]
    show("  VM want(mid) sampled:")
    for p in pts:
        vmv = evS(best_z, p)
        line = f"    want({p:#010x}) = {vmv:#010x}"
        if expected_key is not None:
            ek = expected_key(p) & 0xFFFFFFFF
            line += f"   keygen={ek:#010x}  {'MATCH' if vmv == ek else 'DIFFER'}"
        show(line)
    return res


def _opc(u, ins, op):
    """Concrete 32-bit value of an operand read live from Unicorn (reg / imm / mem)."""
    try:
        if op.type == x86.X86_OP_IMM:
            return op.imm & 0xFFFFFFFF
        if op.type == x86.X86_OP_REG:
            return _reg(u, ins.reg_name(op.reg)) & 0xFFFFFFFF
        if op.type == x86.X86_OP_MEM:
            m = op.mem; ea = m.disp
            if m.base:
                bn = ins.reg_name(m.base)
                ea += (ins.address + ins.size) if bn == "rip" else _reg(u, bn)
            if m.index:
                ea += _reg(u, ins.reg_name(m.index)) * m.scale
            return int.from_bytes(u.mem_read(ea & 0xFFFFFFFFFFFFFFFF, 4), "little")
    except Exception:
        return None
    return None


_UCMAP = None
def _reg(u, name):
    global _UCMAP
    if _UCMAP is None:
        import unicorn.x86_const as ux
        _UCMAP = {k[len("UC_X86_REG_"):].lower(): getattr(ux, k)
                  for k in dir(ux) if k.startswith("UC_X86_REG_")}
    r = _UCMAP.get(name.lower())
    return u.reg_read(r) if r is not None else 0


def main(argv):
    form = len(argv) > 1 and argv[1] == "form"
    if form: argv = argv[:1] + argv[2:]
    if len(argv) < 4:
        sys.exit(__doc__)
    serial = int(argv[4], 16) if len(argv) > 4 else 0x75685AB2
    ek = None
    try:
        from targets.license_app.config import expected_key as ek
    except Exception:
        pass
    fn = lift_form if form else lift
    fn(argv[1], argv[2], int(argv[3], 16), serial=serial, expected_key=ek)


if __name__ == "__main__":
    main(sys.argv)
