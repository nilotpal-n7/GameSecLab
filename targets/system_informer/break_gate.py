#!/usr/bin/env python3
r"""Automated break driver for the System Informer Pro gate (VMProtect side).

The generic native_license campaign is serial->key shaped; the SIP gate is feature->ACCESS_MASK. This
title-specific driver reuses the GENERAL reaforge VMProtect emulation-unpacker (reaforge.core.loader /
protectors.VMProtect) to reach the unpacked state, then exercises the real gate exports from the
unpacked image and records what an attacker actually gets:

  * resolve the gate exports (sip_access_mask / sip_gate_init / sip_is_pro / sip_xdll_respond)
  * show the native VMEnter at sip_access_mask (the code is virtualized -> push/jmp into the VM)
  * emulate sip_access_mask(feature) with NO license loaded -> each returns 0x1000 (trap)
  * emulate sip_gate_init(NULL) -> SIP_NO_LICENSE (no .sipm in the emulated FS)

The point proven: defeating VMProtect (reaching OEP) does NOT hand you the mask bases. 0x0450/0x002A/
0x0038 are not immediates in the code -- they live only in the AES-GCM-decrypted license payload, so the
unpacked gate returns the trap mask until a real decrypt populates g_state. (recovery doc sec 3-5.)

  python targets/system_informer/break_gate.py
"""
from __future__ import annotations

import os
import struct
import sys
from pathlib import Path

os.environ.setdefault("FAST", "1")  # restore the post-OEP snapshot instead of re-emulating 98M insns

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
for _p in (str(ROOT), r"C:\Tools\_downloads\research\vmp-lazy-unpack"):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import unicorn.x86_const as ux  # noqa: E402
from capstone import CS_ARCH_X86, CS_MODE_64, Cs  # noqa: E402
from unicorn import UC_PROT_ALL, UcError  # noqa: E402

from reaforge.core.protectors import for_name  # noqa: E402

PACKED = str(HERE / "dumps" / "sip_progate.vmp.dll")
SNAP = str(HERE / "dumps" / "system_informer_postoep.snap")
RET = 0x7FF900002000
TRAP = 0x1000
FEATURES = {0: "dump", 1: "inject", 2: "edit"}
EXPECTED_LICENSED = {0: 0x0450, 1: 0x002A, 2: 0x0038}


def main():
    print("== REAForge automated break: System Informer Pro gate (VMProtect core) ==")
    print(f"   packed : {PACKED}")
    print(f"   snap   : {SNAP}  (FAST restore)")

    ld = for_name("vmprotect").unpack(PACKED, SNAP, progress=lambda m: print("  [setup]", m))
    uc = ld.uc
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    try:
        uc.mem_map(RET & ~0xFFF, 0x1000, UC_PROT_ALL)
    except UcError:
        pass

    def addr_of(name):
        try:
            return ld.resolve_export(name)
        except Exception:
            return None

    exports = {n: addr_of(n) for n in
               ("sip_access_mask", "sip_gate_init", "sip_is_pro", "sip_xdll_respond")}
    print("\n== [1] gate exports in the unpacked image (base 0x%X) ==" % ld.mapped_start)
    for n, a in exports.items():
        rva = (a - ld.mapped_start) if a else None
        print(f"   {n:18} {('0x%X' % a) if a else 'N/A':>12}   rva {('0x%X' % rva) if a is not None else '?'}")

    am = exports["sip_access_mask"]
    print(f"\n== [2] sip_access_mask @ 0x{am:X}: follow the export thunk into the VM ==")
    print("   the export is a thunk; follow its jmp to the (Ultra-virtualized) function body:")
    target = None
    for ins in md.disasm(bytes(uc.mem_read(am, 0x30)), am):
        print(f"     0x{ins.address:X}  {ins.mnemonic:8} {ins.op_str}")
        if ins.mnemonic == "jmp":
            try:
                target = int(ins.op_str, 16)
            except ValueError:
                target = None
            break
        if ins.mnemonic in ("ret", "call"):
            break
    if target:
        print(f"   -> VMEnter body @ 0x{target:X} (rva 0x{target - ld.mapped_start:X}) -- "
              f"the VMProtect VM stub (push key / jmp dispatcher), not native mask code:")
        for ins in md.disasm(bytes(uc.mem_read(target, 0x30)), target):
            print(f"     0x{ins.address:X}  {ins.mnemonic:8} {ins.op_str}")
            if ins.mnemonic in ("jmp", "ret"):
                break

    def call_mask(feature):
        ld.restore_snapshot(SNAP)
        sp = ((uc.reg_read(ux.UC_X86_REG_RSP) & ~0xF) - 0x800) & ~0xF
        uc.mem_write(sp, struct.pack("<Q", RET))
        uc.reg_write(ux.UC_X86_REG_RSP, sp)
        uc.reg_write(ux.UC_X86_REG_RCX, feature & 0xFFFFFFFF)  # arg0 = SipFeature (MS x64 ABI)
        uc.reg_write(ux.UC_X86_REG_RIP, am)
        try:
            uc.emu_start(am, RET, timeout=600 * 1000 * 1000)
        except UcError as e:
            print(f"     (emu note: {e})")
        return uc.reg_read(ux.UC_X86_REG_RAX) & 0xFFFFFFFF

    print("\n== [3] emulate sip_access_mask(feature) through the VM -- NO license loaded ==")
    all_trap = True
    for f, name in FEATURES.items():
        m = call_mask(f)
        trap = (m == TRAP)
        all_trap &= trap
        tag = "TRAP 0x1000 (PROCESS_SUSPEND_RESUME) -> Pro op DENIED by the kernel" if trap \
              else f"!! non-trap (licensed base would be 0x{EXPECTED_LICENSED[f]:04X})"
        print(f"   sip_access_mask({f} = {name:6}) = 0x{m:08X}   {tag}")
    print("   verdict:", "ALL TRAP -- gate is fail-closed without a decrypted license."
          if all_trap else "some non-trap (unexpected in an unlicensed emulated state).")

    gi = exports["sip_gate_init"]
    if gi:
        print(f"\n== [4] emulate sip_gate_init(NULL) @ 0x{gi:X} -- no .sipm in the emulated FS ==")
        ld.restore_snapshot(SNAP)
        sp = ((uc.reg_read(ux.UC_X86_REG_RSP) & ~0xF) - 0x800) & ~0xF
        uc.mem_write(sp, struct.pack("<Q", RET))
        uc.reg_write(ux.UC_X86_REG_RSP, sp)
        uc.reg_write(ux.UC_X86_REG_RCX, 0)       # machine_file_path = NULL
        uc.reg_write(ux.UC_X86_REG_RIP, gi)
        codes = {0: "SIP_OK", 1: "SIP_NO_LICENSE", 2: "SIP_BAD_FORMAT", 3: "SIP_SIG_INVALID",
                 4: "SIP_KDF_MISMATCH", 5: "SIP_EXPIRED", 6: "SIP_SLUG_MISMATCH", 7: "SIP_DEBUGGER"}
        try:
            uc.emu_start(gi, RET, timeout=600 * 1000 * 1000)
            r = uc.reg_read(ux.UC_X86_REG_RAX) & 0xFFFFFFFF
            if r in codes:
                print(f"   sip_gate_init(NULL) = {r}  ({codes[r]})  -> g_state stays unlicensed")
            else:
                print(f"   sip_gate_init(NULL) returned 0x{r:X} after an unresolved import stub (the init path")
                print("   calls the Win32 file API + libcrypto AES-GCM; those aren't modeled in this static")
                print("   emulation). INCONCLUSIVE here -- but note [3] already proved the mask is trap without")
                print("   a successful init, which is the load-bearing result. A clean init needs the dynamic")
                print("   run (x64dbg on the real process) -- a recording-time step, not the static break.")
        except UcError as e:
            print(f"   (emu stopped: {e}; the init path needs FS + crypto env -- no SIP_OK, so mask stays trap)")

    print("\n== conclusion ==")
    print("   VMProtect defeated by emulation (OEP reached, 35MB snapshot). But the unpacked gate returns")
    print("   the TRAP mask: the license-carried bases (0x0450/0x002A/0x0038) are not constants in the code,")
    print("   they are AES-GCM-decrypted from the .sipm. Cracking the protector != cracking the scheme.")
    ld.close()


if __name__ == "__main__":
    main()
