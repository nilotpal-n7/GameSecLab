#!/usr/bin/env python3
r"""REAForge category: hashlink — Haxe/Heaps/HashLink games (libhl export hashes).

HashLink ships the same runtime (``libhl.dll``) in every Haxe/Heaps game (Dead Cells, Northgard,
Evoland, ...). Its string-hash ``hl_hash_utf8`` (HashLink ``src/std/obj.c``) is therefore
CATEGORY-level ground truth, not a per-title secret:

    int hl_hash_utf8(const char *name){ int h=0; while(*name){ h=223*h+(unsigned)*name; name++; } h%=0x1FFFFF7B; return h; }
    (NB: (unsigned)*name sign-extends the signed char; the final %= is signed.)

A per-title config (``targets/<title>/config.py``) supplies only the packed binary + snapshot path.
The campaign resolves the protected export, validates it against the source hash, then recovers /
peels / proves it symbolically.

Modes: validate | recover | peel | prove.
"""
from __future__ import annotations

import math
import struct
from dataclasses import dataclass

import claripy
import unicorn.x86_const as ux
from capstone import CS_ARCH_X86, CS_MODE_32, Cs
from unicorn import UC_HOOK_CODE, UC_PROT_ALL, UcError

from reaforge.core import peel
from reaforge.core.engine import SymEngine
from reaforge.core.loader import VmpLoader

MODULO, MULT = 0x1FFFFF7B, 223                       # HashLink hl_hash_utf8 constants (category ground truth)
STRBUF, RET, CALLSTK, CALLSTK_SZ = 0x30000000, 0x31000000, 0x20000000, 0x40000
M = (1 << 32) - 1
TEST_STRINGS = (b"", b"a", b"Player", b"takeDamage", b"__string", b"value", b"Dead Cells", b"BiomeLevelGen")


@dataclass
class Config:
    name: str
    packed: str                 # packed libhl copy (default; CLI arg can override)
    snap: str                   # post-unpack snapshot path
    export: str = "hl_hash_utf8"
    N: int = 4                  # symbolic input length for recover/peel


def ref_hash(s: bytes) -> int:
    """Ground-truth hl_hash_utf8 over bytes (matches the signed-char + signed-modulo C semantics)."""
    h = 0
    for c in s:
        sc = c if c < 128 else c - 256          # (unsigned)*name sign-extends the signed char
        h = (MULT * h + sc) & M
    hs = h - 0x100000000 if (h & 0x80000000) else h
    return int(math.fmod(hs, MODULO)) & M


def _build(cfg: Config, packed: str):
    """Fresh loader at the clean post-unpack state (phases isolated so tracer state can't leak)."""
    ld = VmpLoader(packed, progress=lambda m: print("  [setup]", m))
    ld.reach_unpacked(cfg.snap)
    func = ld.resolve_export(cfg.export)
    for a, sz in ((STRBUF, 0x1000), (RET, 0x1000), (CALLSTK, CALLSTK_SZ)):
        try: ld.uc.mem_map(a & ~0xfff, sz, UC_PROT_ALL)
        except UcError: pass
    return ld, func


def _call(ld, func, s: bytes, hook=None):
    uc = ld.uc; arch = ld.arch
    uc.mem_write(STRBUF, s + b"\x00")
    for _, r in arch.gpr: uc.reg_write(r, 0)
    sp = (CALLSTK + CALLSTK_SZ // 2) & ~0xF
    uc.mem_write(sp, struct.pack("<I", RET)); uc.mem_write(sp + 4, struct.pack("<I", STRBUF))   # cdecl: ret, arg0
    uc.reg_write(arch.sp, sp); uc.reg_write(arch.ip, func)
    h = uc.hook_add(UC_HOOK_CODE, hook, None, ld.mapped_start, ld.mapped_end) if hook else None
    try: uc.emu_start(func, RET, timeout=300 * 1000 * 1000)
    finally:
        if h is not None: uc.hook_del(h)
    return uc.reg_read(ux.UC_X86_REG_EAX) & M


def run(cfg: Config, packed: str = None, modes=("validate", "recover", "peel", "prove")):
    packed = packed or cfg.packed
    N = cfg.N

    if "validate" in modes:
        ld, func = _build(cfg, packed)
        print(f"\n== validation battery (virtualized {cfg.export} vs HashLink source) ==  {cfg.export}@0x{func:X}")
        ok = True
        for s in TEST_STRINGS:
            try: got = _call(ld, func, s)
            except UcError as e: print(f"  {s!r:16} emu error {e}"); ok = False; continue
            p = got == ref_hash(s); ok &= p
            print(f"  {s!r:16} VM=0x{got:08X}  src=0x{ref_hash(s):08X}  {'PASS' if p else 'FAIL'}")
        print(f"  {'ALL PASS' if ok else 'some FAILED'}")
        ld.close()

    if any(m in modes for m in ("recover", "peel", "prove")):
        ld, func = _build(cfg, packed)           # fresh loader — symbolic trace needs a pristine tracer
        eng = SymEngine(ld.uc, bits=32, taint_prefix="inp", record=True)
        inp = [claripy.BVS(f"inp{i}", 8) for i in range(N)]
        md = Cs(CS_ARCH_X86, CS_MODE_32); md.detail = True

        def hook(uc_, address, size, ud):
            insn = next(md.disasm(bytes(uc_.mem_read(address, size)), address), None)
            if insn:
                try: eng.step(insn)
                except Exception:
                    if len(eng.errs) < 3:
                        import traceback
                        eng.errs.append(traceback.format_exc())

        sample = b"Player123456789"[:N]
        for i in range(N): eng.mem[STRBUF + i] = inp[i]
        _call(ld, func, sample, hook=hook)
        h_sym = eng.getreg("eax")[0]
        print(f"\n== x86-32 taint-symbolic recovery ==  unhandled={eng.unhandled} snaps={len(eng.snaps)}")
        if eng.errs: print("  first engine exc:\n" + eng.errs[0][-400:])
        if not eng.tainted(h_sym):
            print("  h_out not symbolic — taint didn't reach EAX."); ld.close(); return
        print(f"  recovered symbolic h_out (depth {h_sym.depth})")

        def evalat(expr, bs):
            s = claripy.Solver()
            for i in range(N): s.add(inp[i] == claripy.BVV(bs[i], 8))
            return s.eval(expr, 1)[0] & M

        if "recover" in modes:
            oks = []
            for probe in (sample, bytes(range(1, 1 + N)), bytes([0xFF] * N)):
                g = evalat(h_sym, probe); w = ref_hash(probe); oks.append(g == w)
                print(f"  probe {probe!r:18} h_out=0x{g:08X} ref=0x{w:08X} {'ok' if g == w else 'MISMATCH'}")
            print(f"  samples: {'all match' if all(oks) else 'MISMATCH'}")
        if "peel" in modes:
            peel.peel_byte_rounds(eng.snaps, inp, N)
        if "prove" in modes:
            peel.prove_fold(h_sym, inp, N, MODULO, MULT)
        ld.close()
