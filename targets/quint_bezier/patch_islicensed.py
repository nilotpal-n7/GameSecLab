#!/usr/bin/env python3
r"""Force-true patch for QuintGovernor's is-licensed predicate (user's own software; research).

Zero-dependency alternative to the keygen: overwrite the entry of `sub_140005170` (the is-licensed
BOOL, RVA 0x5170) with `mov eax, 1 ; ret` (B8 01 00 00 00 C3). At function entry RSP points at the
return address, so `ret` returns cleanly; nothing is allocated before, so it's safe. The predicate
then always reports LICENSED. Breaks Authenticode (expected — it's a patched copy for testing).

Runs on a COPY so the original in Program Files is untouched; Claude never reads the install dir.

  python patch_islicensed.py <QuintGovernor copy>.exe [--rva 0x5170] [--out <path>]
"""

from __future__ import annotations

import sys

import pefile

PATCH = bytes([0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3])  # mov eax,1 ; ret


def rva_to_off(pe, rva):
    for s in pe.sections:
        if s.VirtualAddress <= rva < s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData):
            return rva - s.VirtualAddress + s.PointerToRawData
    raise ValueError(f"RVA {rva:#x} not in any section")


def main(argv):
    if len(argv) < 2:
        sys.exit(__doc__)
    src = argv[1]
    rva = int(argv[argv.index("--rva") + 1], 0) if "--rva" in argv else 0x5170
    out = argv[argv.index("--out") + 1] if "--out" in argv else src.rsplit(".", 1)[0] + "_patched.exe"

    pe = pefile.PE(src)
    off = rva_to_off(pe, rva)
    data = bytearray(pe.__data__)
    before = bytes(data[off : off + len(PATCH)])
    data[off : off + len(PATCH)] = PATCH
    with open(out, "wb") as f:
        f.write(data)
    print(f"patched is-licensed @ RVA {rva:#x} (file offset {off:#x})")
    print(f"  before: {before.hex(' ')}")
    print(f"  after : {PATCH.hex(' ')}   (mov eax,1 ; ret)")
    print(f"  wrote : {out}")
    print("  -> replace the running QuintGovernor with this copy to test (Authenticode is now invalid).")


if __name__ == "__main__":
    main(sys.argv)
