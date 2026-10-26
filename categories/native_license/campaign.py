#!/usr/bin/env python3
r"""REAForge category: native_license — VMProtect-protected native license checks (x64, MS ABI).

Generic, config-driven campaign for a virtualized `check_license(key)`-style function that:
  * takes a NUL-terminated key-string pointer in the first integer arg (RCX),
  * reads a machine/volume serial through an imported API (default GetVolumeInformationA, the
    out-pointer in R9) which we hook to inject a controllable serial,
  * returns 1 (licensed) / 0 (rejected).

A per-title config (``targets/<title>/config.py``) supplies the binary, the snapshot, the function
RVA, the reference keygen (used ONLY to validate / cross-check — never to drive recovery), and an
optional all-inputs proof callback. The mechanism here is title-agnostic.

Modes: validate | recover | peel | prove.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Callable, Optional, Sequence

import claripy
import unicorn.x86_const as ux
from capstone import CS_ARCH_X86, CS_MODE_64, Cs
from unicorn import UC_HOOK_CODE, UC_PROT_ALL, UcError

from reaforge.core import peel, protectors
from reaforge.core.engine import SymEngine

M = (1 << 32) - 1


@dataclass
class Config:
    """Everything that makes one native-license title concrete. Mechanism lives in run()."""
    name: str
    packed: str                     # packed binary (default; CLI arg can override)
    snap: str                       # post-unpack snapshot path (reused across runs)
    check_rva: int = 0x1000         # RVA of the virtualized check function
    expected: Callable[[int], int] = None          # reference keygen: serial -> valid key (cross-check only)
    prove: Optional[Callable[[object, object], None]] = None  # (want_sym, serial_sym) -> prints proof
    serials: Sequence[int] = (0x12345678, 0xAABBCCDD, 0xDEADBEEF, 0x00000000, 0xFFFFFFFF)
    default_serial: int = 0xAABBCCDD
    keybuf: int = 0x00000add00000000
    ret_sentinel: int = 0x7ff900002000
    marker: int = 0x13371337
    serial_api: str = "getvolumeinformationa"   # import hooked to inject the serial
    serial_api_argc: int = 8
    protector: str = "vmprotect"                 # which Protector reaches the unpacked state


def _build(cfg: Config, packed: str):
    ld = protectors.for_name(cfg.protector).unpack(packed, cfg.snap, progress=lambda m: print("  [setup]", m))
    for a in (cfg.keybuf, cfg.ret_sentinel):
        try: ld.uc.mem_map(a & ~0xfff, 0x1000, UC_PROT_ALL)
        except UcError: pass
    return ld, ld.resolve_rva(cfg.check_rva)


def run(cfg: Config, packed: str = None, modes=("validate", "recover", "peel", "prove")):
    packed = packed or cfg.packed
    uc_state = {"serial": cfg.default_serial, "eng": None, "serial_sym": None}

    def serial_hook(self_, symbol, rcx, rdx, r8, r9):   # GetVolumeInformationA: lpVolumeSerialNumber = R9 (arg4)
        if r9:
            self_.uc.mem_write(r9, struct.pack("<I", uc_state["serial"] & M))
            eng = uc_state["eng"]
            if eng is not None and uc_state["serial_sym"] is not None:
                for i in range(4):
                    eng.mem[r9 + i] = claripy.Extract(i * 8 + 7, i * 8, uc_state["serial_sym"])
        return 1, {}

    def call_check(ld, check, serial_, key, hook=None):
        uc = ld.uc; arch = ld.arch
        uc_state["serial"] = serial_
        uc.mem_write(cfg.keybuf, key.encode() + b"\x00")
        sp = ((uc.reg_read(arch.sp) & ~0xF) - 0x800) & ~0xF
        uc.mem_write(sp, struct.pack("<Q", cfg.ret_sentinel))
        uc.reg_write(arch.sp, sp)
        uc.reg_write(ux.UC_X86_REG_RCX, cfg.keybuf)      # arg0 = key pointer (MS x64 ABI)
        uc.reg_write(ux.UC_X86_REG_RIP, check)
        h = uc.hook_add(UC_HOOK_CODE, hook, None, ld.mapped_start, ld.mapped_end) if hook else None
        try: uc.emu_start(check, cfg.ret_sentinel, timeout=600 * 1000 * 1000)
        finally:
            if h is not None: uc.hook_del(h)
        return uc.reg_read(ux.UC_X86_REG_RAX) & M

    if "validate" in modes:
        ld, check = _build(cfg, packed); ld.add_handler(cfg.serial_api, serial_hook, cfg.serial_api_argc)
        print(f"\n== validation battery (VM {cfg.name} vs reference keygen) ==  check@0x{check:X}")
        ok = True
        for ser in cfg.serials:
            good = f"{cfg.expected(ser):08X}"; bad = "00000000" if good != "00000000" else "11111111"
            rg = call_check(ld, check, ser, good); rb = call_check(ld, check, ser, bad)
            p = (rg == 1 and rb == 0); ok &= p
            print(f"  serial={ser:#010x} key={good} -> {rg}  wrong -> {rb}  {'PASS' if p else 'FAIL'}")
        print(f"  {'ALL PASS — the VM computes the reference algorithm.' if ok else 'some FAILED'}")
        ld.close()

    if "bypass" in modes:
        # Defeat the check with a WRONG key, without recovering the algorithm: trace-diff a correct
        # vs a wrong run, find the one branch where they diverge (the verdict), and flip it.
        ld, check = _build(cfg, packed); ld.add_handler(cfg.serial_api, serial_hook, cfg.serial_api_argc)
        base = ld.mapped_start
        ser = cfg.default_serial
        good_key = f"{cfg.expected(ser):08X}"; wrong_key = "00000000" if good_key != "00000000" else "11111111"

        def tracer(seq):
            def h(uc_, address, size, ud): seq.append(address)
            return h

        good, bad = [], []
        rg = call_check(ld, check, ser, good_key, hook=tracer(good))
        rb = call_check(ld, check, ser, wrong_key, hook=tracer(bad))
        print(f"\n== dynamic bypass (defeat the check with a WRONG key, no keygen) ==  check@0x{check:X}")
        print(f"  correct key {good_key} -> {rg} (accept);  wrong key {wrong_key} -> {rb} (reject);  traces {len(good)}/{len(bad)} instrs")
        n = min(len(good), len(bad)); D = None
        for i in range(n):
            if good[i] != bad[i]:
                D = good[i - 1] if i else good[i]; break
        if D is None:
            print("  traces never diverge (keys indistinguishable here)."); ld.close(); return
        print(f"  key-dependent decision region begins at module+0x{D - base:X}  (traces then differ by {abs(len(good) - len(bad))} instrs)")
        # A VM'd verdict is NOT one native branch — the result is carried in VM state and the traces
        # diverge in many places, so flipping the first jcc does not flip the verdict. The reliable,
        # classic dynamic bypass is to force the check to return LICENSED: emulate `mov eax,1; ret` at entry.
        def retpatch(uc_, address, size, ud):
            if address == check:
                uc_.reg_write(ux.UC_X86_REG_RAX, 1); uc_.reg_write(ux.UC_X86_REG_RIP, cfg.ret_sentinel)

        rp = call_check(ld, check, ser, wrong_key, hook=retpatch)
        print(f"  patch check@0x{check:X} to `mov eax,1; ret` -> wrong key returns {rp}  "
              f"{'BYPASSED (LICENSED, check never runs)' if rp == 1 else 'unexpected'}")
        print("  live options: (a) patch the function prologue to `mov eax,1; ret` in x64dbg (shown above),")
        print("                (b) recover the key algorithmically — `recover` / `peel` modes (the deeper break).")
        ld.close()

    if any(m in modes for m in ("recover", "peel", "prove")):
        ld, check = _build(cfg, packed); ld.add_handler(cfg.serial_api, serial_hook, cfg.serial_api_argc)
        eng = SymEngine(ld.uc, bits=64, taint_prefix="serial", record=True); eng.marker = cfg.marker
        serial_sym = claripy.BVS("serial", 32)
        uc_state["eng"] = eng; uc_state["serial_sym"] = serial_sym
        md = Cs(CS_ARCH_X86, CS_MODE_64); md.detail = True

        def hook(uc_, address, size, ud):
            insn = next(md.disasm(bytes(uc_.mem_read(address, size)), address), None)
            if insn:
                try: eng.step(insn)
                except Exception:
                    if len(eng.errs) < 3:
                        import traceback
                        eng.errs.append(traceback.format_exc())

        call_check(ld, check, cfg.default_serial, f"{cfg.marker:08X}", hook=hook)
        print(f"\n== x64 taint-symbolic recovery ==  unhandled={eng.unhandled} snaps={len(eng.snaps)} captures={len(eng.captures)}")

        def evalat(expr, sval):
            s = claripy.Solver(); s.add(serial_sym == claripy.BVV(sval, 32)); return s.eval(expr, 1)[0] & M

        known = cfg.expected(cfg.default_serial); want = None
        for e in eng.captures:
            try:
                e32 = SymEngine.ext(e, 32)
                if evalat(e32, cfg.default_serial) == known: want = e32; break
            except Exception: pass
        if want is None:
            print("  no captured expression validated."); ld.close(); return
        print(f"  VALIDATED want(serial) reproduces key {known:08X} for serial {cfg.default_serial:#010x}")
        if "peel" in modes:
            peel.peel_offset_rounds(want, eng.snaps, serial_sym)
        if "prove" in modes and cfg.prove is not None:
            cfg.prove(want, serial_sym)
        ld.close()
