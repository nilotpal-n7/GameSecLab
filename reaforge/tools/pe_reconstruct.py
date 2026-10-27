#!/usr/bin/env python3
r"""Rebuild a runnable PE from a protector dump — restore imports, OEP, fixed base, writable IAT.

Takes a Scylla/x64dbg dump of an unpacked process and makes it loadable again: restore the real
import table (resolving the protector's wrapped IAT slots), set the original OEP, pin the image base
(no ASLR) so hardcoded RVAs line up, make the import/data sections writable, and drop the protector's
TLS / bound-import / load-config dirs.

Two source modes for the import table + de-virtualized code:
  * orig=<clean PE>  — overlay the owner's original sections (code + imports). Valid only for YOUR OWN
    binary used as an oracle; it de-virtualizes the VM'd regions AND restores imports in one shot.
  * orig=None        — dump-only: keep the dump's sections, only fix headers. Pair with an IAT already
    unwrapped in place (themida_unwrap) — no reference binary, but the VM'd code stays virtualized
    until a VM-lifter recovers it.

  python -m reaforge.tools.pe_reconstruct <dump.exe> <out.exe> [orig_oracle.exe]
"""
from __future__ import annotations

import sys

import pefile

MEM_WRITE = 0x80000000
DYNAMIC_BASE = 0x0040
# data-directory indices
IMPORT, EXCEPTION, BASERELOC, TLS, LOAD_CONFIG, BOUND_IMPORT, IAT = 1, 3, 5, 9, 10, 11, 12


def reconstruct(dump, out, orig=None, oep=None, base=None, show=print):
    """Rebuild `dump` -> runnable `out`. With `orig` (your own clean PE) overlay its sections + dirs."""
    d = pefile.PE(dump)
    writ_rvas = []

    if orig is not None:
        o = pefile.PE(orig)
        idata_rva = None
        for s in o.sections:
            nm = s.Name.decode(errors="ignore").rstrip("\x00")
            data = s.get_data()
            if len(data) < s.Misc_VirtualSize:          # .bss etc: pad zeros so globals aren't packer garbage
                data += b"\x00" * (s.Misc_VirtualSize - len(data))
            d.set_bytes_at_rva(s.VirtualAddress, data)
            if nm == ".idata":
                idata_rva = s.VirtualAddress
            if s.Characteristics & MEM_WRITE:
                writ_rvas.append(s.VirtualAddress)
        if idata_rva is not None:
            writ_rvas.append(idata_rva)
        D, OD = d.OPTIONAL_HEADER.DATA_DIRECTORY, o.OPTIONAL_HEADER.DATA_DIRECTORY
        for i in (IMPORT, EXCEPTION, BASERELOC, IAT):   # restore the real import/exception/reloc/IAT dirs
            D[i].VirtualAddress, D[i].Size = OD[i].VirtualAddress, OD[i].Size
        for i in (TLS, LOAD_CONFIG, BOUND_IMPORT):      # drop the protector's dirs
            D[i].VirtualAddress, D[i].Size = 0, 0
        oep = o.OPTIONAL_HEADER.AddressOfEntryPoint if oep is None else oep
        base = o.OPTIONAL_HEADER.ImageBase if base is None else base

    if oep is not None:
        d.OPTIONAL_HEADER.AddressOfEntryPoint = oep
    if base is not None:
        d.OPTIONAL_HEADER.DllCharacteristics &= ~DYNAMIC_BASE    # no ASLR: hardcoded RVAs/IAT line up
        d.OPTIONAL_HEADER.ImageBase = base
    for s in d.sections:
        hi = s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData)
        if any(s.VirtualAddress <= r < hi for r in writ_rvas):
            s.Characteristics |= MEM_WRITE
            show("  writable: " + s.Name.decode(errors="ignore").rstrip("\x00") + f" {s.VirtualAddress:#x}")

    d.write(out)
    show(f"wrote {out}  OEP {d.OPTIONAL_HEADER.AddressOfEntryPoint:#x}  base {d.OPTIONAL_HEADER.ImageBase:#x}")
    return out


def main(argv):
    if len(argv) < 3:
        sys.exit(__doc__)
    reconstruct(argv[1], argv[2], argv[3] if len(argv) > 3 else None)


if __name__ == "__main__":
    main(sys.argv)
