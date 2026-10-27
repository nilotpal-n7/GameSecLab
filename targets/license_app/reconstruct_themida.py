#!/usr/bin/env python3
"""Reconstruct a runnable, unpacked license_app from the Themida dump + the original oracle.

- restore the original imports (resolves all 36 IAT entries incl. the 28 Themida-wrapped ones),
- restore the native code for the EPV'd entry + check_license's VM body,
- set the original OEP, load fixed-base, and neutralize Themida's TLS/bound-import dirs.
"""
import pefile

DUMP = r"C:\Tools\GameSecLab\targets\license_app\dumps\license_app.themida_dump.exe"
ORIG = r"C:\Tools\GameSecLab\targets\license_app\dumps\license_app_vm.exe"
OUT  = r"C:\Tools\GameSecLab\targets\license_app\dumps\license_app.themida_unpacked.exe"

orig = pefile.PE(ORIG)
dump = pefile.PE(DUMP)

# 1) overlay EVERY original section over the dump at its RVA (code + .rdata/.data/.pdata/.idata/...)
idata_rva = None
writ_rvas = []
for s in orig.sections:
    nm = s.Name.decode(errors="ignore").rstrip("\x00")
    data = s.get_data()
    if len(data) < s.Misc_VirtualSize:                 # .bss etc: pad with zeros so globals aren't Themida garbage
        data = data + b"\x00" * (s.Misc_VirtualSize - len(data))
    dump.set_bytes_at_rva(s.VirtualAddress, data)
    if nm == ".idata":
        idata_rva = s.VirtualAddress
    if s.Characteristics & 0x80000000:                 # original writable sections (.data/.bss)
        writ_rvas.append(s.VirtualAddress)
writ_rvas.append(idata_rva)                            # IAT must be writable for the loader

# 2) copy the original data directories (IMPORT/IAT/EXCEPTION/RELOC); drop Themida's TLS/LOADCFG/BOUND
D, OD = dump.OPTIONAL_HEADER.DATA_DIRECTORY, orig.OPTIONAL_HEADER.DATA_DIRECTORY
def setdir(i, rva, size):
    D[i].VirtualAddress, D[i].Size = rva, size
for i in (1, 3, 5, 12):                           # IMPORT, EXCEPTION, BASERELOC, IAT
    setdir(i, OD[i].VirtualAddress, OD[i].Size)
for i in (9, 10, 11):                             # TLS, LOAD_CONFIG, BOUND_IMPORT
    setdir(i, 0, 0)

# 4) original OEP (now native after the .text restore)
dump.OPTIONAL_HEADER.AddressOfEntryPoint = orig.OPTIONAL_HEADER.AddressOfEntryPoint   # 0x1490

# 5) load at the fixed base (no ASLR) so hardcoded RVAs/IAT line up; make the IAT section writable
dump.OPTIONAL_HEADER.DllCharacteristics &= ~0x0040                                    # clear DYNAMICBASE
dump.OPTIONAL_HEADER.ImageBase = orig.OPTIONAL_HEADER.ImageBase                       # 0x140000000
for s in dump.sections:
    hi = s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData)
    if any(s.VirtualAddress <= r < hi for r in writ_rvas):
        s.Characteristics |= 0x80000000                                              # IMAGE_SCN_MEM_WRITE
        print("writable:", s.Name.decode(errors="ignore").rstrip("\x00"), hex(s.VirtualAddress))

dump.write(OUT)
print("wrote", OUT)
print("OEP", hex(dump.OPTIONAL_HEADER.AddressOfEntryPoint), "base", hex(dump.OPTIONAL_HEADER.ImageBase),
      "import dir RVA", hex(D[1].VirtualAddress))
