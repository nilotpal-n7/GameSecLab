#!/usr/bin/env python3
"""REAForge devirt — Milestone 1: emulate the VMProtect'd check_license in isolation.

We can't run the dump (segfaults) and angr would drown in the VM's millions of instructions.
So we emulate the VM directly with Unicorn: map the unpacked binary's sections, feed a key +
a chosen volume serial (stubbing GetVolumeInformationA), let strtoul run from .text, and read
the verdict. A single concrete path through the VM -> no path explosion.

Authorized target only: our own license_app_c2 (unpacked dump).
Usage: python emulate_checklicense.py <serial_hex> <key_string>
"""
import sys, struct
import pefile
from unicorn import *
from unicorn.x86_const import *

BIN = r"C:\Tools\GameSecLab\capstone\license_app_c2_unpacked.exe"
CHECK_LICENSE = 0x140001000
IAT_GETVOLINFO = 0x1403b82d0      # GetVolumeInformationA slot (from rebuilt IAT)
STUB_GETVOLINFO = 0x900000        # our trampoline for it
STACK_BASE, STACK_SIZE = 0x7000000, 0x200000
KEY_ADDR = 0x6000000
STOP = 0xdead0000                 # fake return address -> emulation stops here

def c0_expected_key(mid):
    """The C0-recovered algorithm, for independent validation of the VM's result."""
    acc = (0x1505 ^ mid) & 0xffffffff
    for i in range(8):
        acc = ((acc * 33) & 0xffffffff) ^ ((mid >> (i * 4)) & 0xF)
        acc = (acc + i * 7) & 0xffffffff
    return acc

def align(x, a=0x1000): return (x + a - 1) & ~(a - 1)

def run(serial, key):
    pe = pefile.PE(BIN, fast_load=True)
    ib = pe.OPTIONAL_HEADER.ImageBase
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    # map the PE headers at the image base (the VM's self-checksumming reads them)
    hdr_sz = align(pe.OPTIONAL_HEADER.SizeOfHeaders)
    uc.mem_map(ib, hdr_sz, UC_PROT_ALL)
    uc.mem_write(ib, pe.__data__[:pe.OPTIONAL_HEADER.SizeOfHeaders])
    # map every section with its raw bytes
    for s in pe.sections:
        va = ib + s.VirtualAddress
        size = align(max(s.Misc_VirtualSize, s.SizeOfRawData))
        uc.mem_map(va, size, UC_PROT_ALL)
        data = s.get_data()
        if data:
            uc.mem_write(va, data)
    # stack, key buffer, stub page, stop page
    uc.mem_map(STACK_BASE, STACK_SIZE, UC_PROT_ALL)
    uc.mem_map(KEY_ADDR, 0x1000, UC_PROT_ALL)
    uc.mem_map(STUB_GETVOLINFO, 0x1000, UC_PROT_ALL)
    uc.mem_map(STOP & ~0xfff, 0x1000, UC_PROT_ALL)
    uc.mem_write(STUB_GETVOLINFO, b"\xc3")                 # a lone `ret`
    uc.mem_write(IAT_GETVOLINFO, struct.pack("<Q", STUB_GETVOLINFO))  # redirect IAT -> stub
    uc.mem_write(KEY_ADDR, key.encode() + b"\x00")

    # Windows env the VM/CRT touches: KUSER_SHARED_DATA, a TEB via GS.
    uc.mem_map(0x7ffe0000, 0x1000, UC_PROT_ALL)           # KUSER_SHARED_DATA
    uc.mem_write(0x7ffe0000 + 0x260, struct.pack("<I", 26100))   # NtBuildNumber
    uc.mem_write(0x7ffe0000 + 0x2d4, b"\x00")             # KdDebuggerEnabled = 0
    TEB = 0x8000000
    uc.mem_map(TEB, 0x4000, UC_PROT_ALL)
    try:
        uc.reg_write(UC_X86_REG_GS_BASE, TEB)
    except Exception:
        pass
    # lazy-map anything else it reads/writes to a zero page so a single concrete path can finish
    touched = []
    def on_unmapped(uc, access, address, size, value, ud):
        page = address & ~0xfff
        try: uc.mem_map(page, 0x1000, UC_PROT_ALL)
        except Exception: pass
        kind = "FETCH" if access in (UC_MEM_FETCH, UC_MEM_FETCH_PROT, UC_MEM_FETCH_UNMAPPED) else ("W" if access in (UC_MEM_WRITE, UC_MEM_WRITE_UNMAPPED) else "R")
        if len(touched) < 40: touched.append((kind, hex(address)))
        return True
    uc.hook_add(UC_HOOK_MEM_UNMAPPED, on_unmapped)

    # GetVolumeInformationA stub: write serial to [R9], return TRUE, then the `ret` runs
    gvi_hits = []
    def on_getvolinfo(uc, addr, size, ud):
        r9 = uc.reg_read(UC_X86_REG_R9)
        gvi_hits.append(r9)
        if r9:
            uc.mem_write(r9, struct.pack("<I", serial & 0xffffffff))
        uc.reg_write(UC_X86_REG_RAX, 1)
    uc.hook_add(UC_HOOK_CODE, on_getvolinfo, None, STUB_GETVOLINFO, STUB_GETVOLINFO)

    # set up the call: RCX = key ptr, push STOP as return address
    rsp = STACK_BASE + STACK_SIZE - 0x100
    uc.reg_write(UC_X86_REG_RSP, rsp)
    uc.mem_write(rsp, struct.pack("<Q", STOP))
    uc.reg_write(UC_X86_REG_RCX, KEY_ADDR)

    try:
        uc.emu_start(CHECK_LICENSE, STOP, timeout=60 * 1000 * 1000, count=0)
    except UcError as e:
        print("  lazy-mapped:", [(a, hex(x)) for a, x in touched[:12]])
        return None, f"UcError: {e} @ rip={uc.reg_read(UC_X86_REG_RIP):#x}"
    fetches = [t for t in touched if t[0] == "FETCH"]
    if fetches:
        print("  !! FETCH faults (VM divergence):", fetches[:8])
    print(f"  GetVolumeInformationA fired {len(gvi_hits)}x, R9s={[hex(x) for x in gvi_hits]}")
    eax = uc.reg_read(UC_X86_REG_RAX) & 0xffffffff
    return eax, None

if __name__ == "__main__":
    serial = int(sys.argv[1], 16) if len(sys.argv) > 1 else 0x12345678
    want = c0_expected_key(serial)
    key = sys.argv[2] if len(sys.argv) > 2 else f"{want:08X}"
    print(f"serial={serial:#010x}  C0-expected-key={want:08X}  feeding key={key!r}")
    eax, err = run(serial, key)
    if err:
        print("EMULATION FAILED:", err)
    else:
        print(f"check_license returned {eax}  -> {'LICENSED' if eax else 'INVALID'}")
