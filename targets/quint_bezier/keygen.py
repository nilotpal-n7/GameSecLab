#!/usr/bin/env python3
r"""Quint Bezier registry-activation keygen (user's own software; research/testing).

Recovered from QuintGovernor.exe `sub_140005170` (the is-licensed predicate). The registry path
accepts when either equation holds, over 64-bit values ViewState / CacheTag and the LicensedTo name:

  A (machine-bound):       CacheTag == ViewState ^ MF ^ K
  B (machine-independent): CacheTag == ViewState ^ (nameSum << 48) ^ K

  K       = 0x917AA921821C49AB
  nameSum = sum of the UTF-16 code units of the LicensedTo name
  MF      = (OemId & 0xF)
            | (( ProcType&0xFFFF
               | (( NumProc&0xFF
                  | (( ((nameSum<<20) | ((ProcRev | (ProcLevel<<16)) & 0xFFFFF)) << 8)) << 16)) << 16)) << 4
            (all fields from GetSystemInfo)

Formula B is the clean keygen: pick a name, ViewState=0 -> CacheTag. No machine data, no server, no
private key. This file encodes the user's own licensing scheme — keep it private.

  python keygen.py "Licensed Name"                      # Formula B (machine-independent)
  python keygen.py "Licensed Name" --machine <sysinfo>  # Formula A (needs GetSystemInfo fields)
"""
from __future__ import annotations

import sys

K = 0x917AA921821C49AB
MASK64 = (1 << 64) - 1


def name_sum(name: str) -> int:
    # UTF-16 code units; for BMP chars this equals ord(c). Non-BMP would use surrogate pairs.
    return sum(ord(ch) for ch in name) & MASK64


def keygen_nameonly(name: str, viewstate: int = 0) -> tuple[int, int]:
    """Formula B: machine-independent. Returns (ViewState, CacheTag)."""
    cache = (viewstate ^ (name_sum(name) << 48) ^ K) & MASK64
    return viewstate & MASK64, cache


def machine_fingerprint(oem_id, proc_type, num_proc, proc_rev, proc_level, ns) -> int:
    inner1 = (proc_rev | (proc_level << 16)) & 0xFFFFF
    inner2 = ((ns << 20) | inner1) & MASK64
    inner3 = ((num_proc & 0xFF) | (inner2 << 8)) & MASK64
    inner4 = ((proc_type & 0xFFFF) | (inner3 << 16)) & MASK64
    return ((oem_id & 0xF) | (inner4 << 4)) & MASK64


def keygen_machine(name, oem_id, proc_type, num_proc, proc_rev, proc_level, viewstate=0):
    """Formula A: machine-bound. Returns (ViewState, CacheTag)."""
    mf = machine_fingerprint(oem_id, proc_type, num_proc, proc_rev, proc_level, name_sum(name))
    return viewstate & MASK64, (viewstate ^ mf ^ K) & MASK64


def _emit(name, vs, ct):
    print(f"  LicensedTo : {name!r}  (nameSum = {name_sum(name)})")
    print(f"  ViewState  : 0x{vs:016X}   ({vs})")
    print(f"  CacheTag   : 0x{ct:016X}   ({ct})")


def main(argv):
    if len(argv) < 2:
        sys.exit(__doc__)
    name = argv[1]
    if "--machine" in argv:
        # python keygen.py NAME --machine OemId ProcType NumProc ProcRev ProcLevel
        i = argv.index("--machine")
        vals = [int(x, 0) for x in argv[i + 1:i + 6]]
        if len(vals) != 5:
            sys.exit("--machine needs: OemId ProcType NumProc ProcRev ProcLevel (from GetSystemInfo)")
        vs, ct = keygen_machine(name, *vals)
        print("== Formula A (machine-bound) =="); _emit(name, vs, ct)
    else:
        vs, ct = keygen_nameonly(name)
        print("== Formula B (machine-independent) =="); _emit(name, vs, ct)
        print("\n  ViewState/CacheTag are 64-bit; write them in the type the key reader expects")
        print("  (confirm REG_QWORD vs REG_BINARY[8] and the subkey before deploying).")


if __name__ == "__main__":
    main(sys.argv)
