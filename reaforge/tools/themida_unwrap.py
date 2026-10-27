#!/usr/bin/env python3
r"""Themida IAT unwrapper — resolve API-wrapped IAT thunks by emulation (no oracle).

Themida's Advanced API-Wrapping points IAT slots at SecureEngine wrapper stubs instead of the real
APIs, so a dump's import table can't be reconstructed from the slots alone. This tool resolves them
the way a dedicated unwrapper does: map a full-memory dump of the UNPACKED process into Unicorn, read
each IAT thunk, and for any thunk that points into SecureEngine's allocated region (not a loaded
module) emulate the stub until control reaches a real DLL export — that export IS the wrapped API.

Spirit of reaforge.core.loader (VMProtect): the protector-specific mechanism (here, wrapper tracing)
behind a reusable tool; the arch-agnostic emulation does the work.

Make the dump with: Task Manager -> Details -> right-click the process (while it's at a post-unpack
state, e.g. paused in x64dbg) -> Create dump file.

  python -m reaforge.tools.themida_unwrap <dump.dmp> <main_module_substr> <iat_rva_hex> <iat_size_hex>
"""
from __future__ import annotations

import bisect
import os
import sys

import pefile
from minidump.minidumpfile import MinidumpFile
from unicorn import UC_ARCH_X86, UC_HOOK_CODE, UC_MODE_64, UC_PROT_ALL, Uc, UcError
from unicorn.x86_const import UC_X86_REG_GS_BASE, UC_X86_REG_RAX, UC_X86_REG_RIP, UC_X86_REG_RSP

SENTINEL = 0xDEAD0000      # fake return on the wrapper's stack; the real API is the TAIL-jmp (stack back here)

PAGE = 0x1000
STACK_BASE, STACK_SZ = 0x7F0000000000, 0x100000


def _align_dn(x): return x & ~(PAGE - 1)
def _align_up(x): return (x + PAGE - 1) & ~(PAGE - 1)


def load(path):
    mf = MinidumpFile.parse(path)
    rdr = mf.get_reader()
    segs = []
    if getattr(mf, "memory_segments_64", None):
        segs = mf.memory_segments_64.memory_segments
    elif getattr(mf, "memory_segments", None):
        segs = mf.memory_segments.memory_segments
    mods = [(m.name, m.baseaddress, m.baseaddress + m.size) for m in mf.modules.modules]
    teb = mf.threads.threads[0].Teb if mf.threads and mf.threads.threads else 0
    return mf, rdr, segs, mods, teb


def map_all(uc, rdr, segs):
    mapped = []
    for s in segs:
        va, size = s.start_virtual_address, s.size
        try:
            data = rdr.read(va, size)
        except Exception:
            continue
        b = _align_dn(va); e = _align_up(va + size)
        try:
            uc.mem_map(b, e - b, UC_PROT_ALL)
        except UcError:
            pass  # overlaps an already-mapped page
        try:
            uc.mem_write(va, data)
        except UcError:
            pass
        mapped.append((b, e))
    return mapped


def export_map(mods):
    """{address -> 'module!api'} and a sorted (addr,label) list, from the DLLs on disk."""
    amap = {}
    for name, base, _end in mods:
        if not os.path.exists(name):
            continue
        try:
            pe = pefile.PE(name, fast_load=True)
            pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]])
            bn = os.path.basename(name)
            for exp in getattr(pe, "DIRECTORY_ENTRY_EXPORT", type("x", (), {"symbols": []})).symbols:
                if exp.name:
                    amap[base + exp.address] = f"{bn}!{exp.name.decode(errors='ignore')}"
        except Exception:
            pass
    return amap


def unwrap(dump, mod_sub, iat_rva, iat_sz, show=print):
    """Resolve an API-wrapped IAT from a full-memory dump. Returns [(rva, slot_val, tag, api), ...]."""
    mod_sub = mod_sub.lower()
    mf, rdr, segs, mods, teb = load(dump)
    main_mod = next((m for m in mods if mod_sub in os.path.basename(m[0]).lower()), None)
    if not main_mod:
        sys.exit(f"module ~{mod_sub!r} not in dump. modules: {[os.path.basename(m[0]) for m in mods][:12]}")
    base = main_mod[1]
    iat_va = base + iat_rva
    mod_ranges = sorted((b, e, os.path.basename(n)) for n, b, e in mods)
    mr_starts = [b for b, _, _ in mod_ranges]

    main_lo, main_hi = main_mod[1], main_mod[2]

    def in_module(a):
        i = bisect.bisect_right(mr_starts, a) - 1
        return 0 <= i < len(mod_ranges) and mod_ranges[i][0] <= a < mod_ranges[i][1]

    def in_sys(a):                                         # a real API lives in a SYSTEM dll, not the exe
        return in_module(a) and not (main_lo <= a < main_hi)

    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    map_all(uc, rdr, segs)
    try: uc.mem_map(STACK_BASE, STACK_SZ, UC_PROT_ALL)
    except UcError: pass
    if teb: uc.reg_write(UC_X86_REG_GS_BASE, teb)
    amap = export_map(mods)
    exp_addrs = sorted(amap)

    def resolve_landing(a):
        if a in amap: return amap[a]
        i = bisect.bisect_right(exp_addrs, a) - 1          # nearest export at/below (jmp into export)
        if i >= 0 and in_sys(a) and a - exp_addrs[i] < 0x40:
            return amap[exp_addrs[i]] + f"+{a - exp_addrs[i]:#x}"
        return None

    def trace(stub):
        land = {"a": None}
        def hook(u, addr, size, ud):
            if in_sys(addr):
                sp = u.reg_read(UC_X86_REG_RSP)
                try: top = int.from_bytes(u.mem_read(sp, 8), "little")
                except UcError: top = 0
                if top == SENTINEL:                        # tail-jmp to the real API (stack back to entry)
                    land["a"] = addr; u.emu_stop()
                else:                                      # intermediate anti-analysis call -> skip past it
                    u.reg_write(UC_X86_REG_RIP, top); u.reg_write(UC_X86_REG_RSP, sp + 8)
                    u.reg_write(UC_X86_REG_RAX, 1)
        uc.reg_write(UC_X86_REG_RSP, STACK_BASE + STACK_SZ // 2)
        uc.mem_write(STACK_BASE + STACK_SZ // 2, SENTINEL.to_bytes(8, "little"))
        uc.reg_write(UC_X86_REG_RIP, stub)
        h = uc.hook_add(UC_HOOK_CODE, hook)
        try:
            uc.emu_start(stub, 0, count=300000)
        except UcError:
            pass
        finally:
            uc.hook_del(h)
        return land["a"]

    n = iat_sz // 8
    show(f"== Themida IAT unwrap ==  module {os.path.basename(main_mod[0])} base {base:#x}  IAT {iat_va:#x} x{n}")
    resolved = wrapped = direct = 0
    out = []
    for k in range(n):
        slot = iat_va + k * 8
        try:
            v = int.from_bytes(rdr.read(slot, 8), "little")
        except Exception:
            continue
        if v == 0:
            continue
        if in_sys(v):                                       # already a real export pointer
            api = resolve_landing(v) or "?"; direct += 1
            tag = "direct"
        else:                                              # wrapper stub -> emulate to the real API
            land = trace(v)
            api = (resolve_landing(land) if land else None)
            if api: resolved += 1; tag = "UNWRAPPED"
            else: wrapped += 1; tag = "unresolved"; api = f"(stub {v:#x}, landed {land:#x})" if land else f"(stub {v:#x})"
        out.append((slot - base, v, tag, api))
        show(f"  [+{slot-base:#06x}] {v:#018x}  {tag:10} {api}")
    show(f"\n  direct {direct}  UNWRAPPED {resolved}  unresolved {wrapped}  (of {len(out)})")
    return out


def main(argv):
    if len(argv) < 5:
        sys.exit(__doc__)
    return unwrap(argv[1], argv[2], int(argv[3], 16), int(argv[4], 16))


if __name__ == "__main__":
    main(sys.argv)
