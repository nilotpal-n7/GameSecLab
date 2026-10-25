#!/usr/bin/env python3
r"""REAForge end-to-end devirtualizer (driver) — built ON vmp-lazy-unpack's env mechanism.

Why: faithfully emulating a VMProtect-virtualized function needs a full Windows process world
(PEB/TEB/LDR + synthetic module export tables + API/syscall stubs). vmp-lazy-unpack already builds
exactly that to reach OEP. We REUSE its env setup, then drive OUR OWN emulation PAST OEP into
check_license: inject a chosen volume serial (so machine_id is controllable), run the VM'd function,
and read the verdict. This is the base for symbolic formula/key recovery (next step).

Run from the vmp-lazy-unpack checkout (so the `unpack` package + its catalog are importable):
    cd C:\Tools\_downloads\research\vmp-lazy-unpack
    python C:\Tools\GameSecLab\reaforge\devirt\devirt_oep.py <packed.exe> <serial_hex> [key]

Authorized target only: our own license_app_c2.vmp.exe.
"""
import sys, struct, os
from pathlib import Path

# make vmp-lazy-unpack importable (its env mechanism is our building block)
VMP_LAZY = os.environ.get("VMP_LAZY_UNPACK", r"C:\Tools\_downloads\research\vmp-lazy-unpack")
sys.path.insert(0, VMP_LAZY)

from unicorn import Uc, UC_ARCH_X86, UC_PROT_ALL, UC_HOOK_CODE, UcError
import unicorn.x86_const as ux

import unpack.tracer as T
from unpack.tracer import (
    Catalog, find_or_capture_catalog, ensure_catalog_arch, load_pe, collect_imports,
    map_pe, map_emu_windows_modules, map_synthetic_process_state, Tracer, TraceHooks,
    ModuleImage, pe_memory_image, file_view_base_for, recover_keys,
    load_system_syscall_catalog, require_catalog, KUSER_SHARED_DATA_BASE, PAGE_SIZE,
)
from unpack.arch import MODE64, encode_ptr

CHECK_LICENSE_RVA = 0x1000          # check_license (sub_140001000)
RET_SENTINEL = 0x7ff900002000       # our own return marker (distinct from the kit's)
KEYBUF = 0x00000add00000000         # scratch buffer for the key string

def c0_expected_key(mid):
    acc = (0x1505 ^ mid) & 0xffffffff
    for i in range(8):
        acc = ((acc * 33) & 0xffffffff) ^ ((mid >> (i * 4)) & 0xF)
        acc = (acc + i * 7) & 0xffffffff
    return acc

def main():
    arch = MODE64
    packed = Path(sys.argv[1]).resolve()
    serial = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0x12345678
    key = sys.argv[3] if len(sys.argv) > 3 else f"{c0_expected_key(serial):08X}"
    prog = lambda m: print("  [setup]", m)

    # --- reuse vmp-lazy-unpack's catalog + env (verbatim from its run()) ---
    T.ACTIVE_CATALOG = Catalog(find_or_capture_catalog((Path.cwd(), Path(T.__file__).resolve().parent.parent), arch), arch)
    ensure_catalog_arch(T.ACTIVE_CATALOG, arch)
    pe = load_pe(packed.read_bytes())
    image_base = pe.OPTIONAL_HEADER.ImageBase
    entry = image_base + pe.OPTIONAL_HEADER.AddressOfEntryPoint
    import_slots = collect_imports(pe)
    uc = Uc(UC_ARCH_X86, arch.uc_mode)
    mapped_start, mapped_end = map_pe(uc, pe)
    emu_file_bytes = pe_memory_image(load_pe(require_catalog().ntdll_bytes))
    fvb = file_view_base_for(arch, mapped_start, mapped_end, (len(emu_file_bytes) + 0xfff) & ~0xfff)
    uc.mem_map(fvb, (len(emu_file_bytes) + 0xfff) & ~0xfff, UC_PROT_ALL); uc.mem_write(fvb, emu_file_bytes)
    module_bases, synth_targets, export_lookup = map_emu_windows_modules(uc, import_slots, arch)
    proc_img = ModuleImage(packed.name, mapped_start, pe.OPTIONAL_HEADER.SizeOfImage, entry, str(packed))
    rsp = map_synthetic_process_state(uc, module_bases, proc_img, arch)
    for _, reg in arch.gpr: uc.reg_write(reg, 0)
    uc.reg_write(arch.sp, rsp); uc.reg_write(ux.UC_X86_REG_EFLAGS, 0x202); uc.reg_write(arch.ip, entry)
    tracer = Tracer(uc, mapped_start, mapped_end, synth_targets, pe, module_bases, export_lookup,
                    progress=prog, diagnostics=None, arch=arch)
    tracer.module_paths = {b: f"C:\\Windows\\System32\\{n}" for n, b in module_bases.items()}
    tracer.module_paths[mapped_start] = str(packed); tracer.module_paths[0] = "C:\\host.exe"
    tracer.files.files[packed.name.lower()] = packed.read_bytes()
    tracer.encoded_string_keys = tuple(recover_keys(bytes(pe.__data__)))
    tracer.files.files["ntdll.dll"] = require_catalog().ntdll_bytes
    tracer.syscall_catalog = load_system_syscall_catalog()

    check_license = mapped_start + CHECK_LICENSE_RVA
    gvi = export_lookup.get((module_bases.get("kernel32.dll"), "getvolumeinformationa"))

    with TraceHooks(tracer, arch.peb_base, PAGE_SIZE):
        # 1) emulate the packer/unpacker to OEP (its env + API handling active)
        try:
            uc.emu_start(entry, 0)
        except UcError as e:
            print("unpack emu error:", e)
        print(f"OEP reached: stop={getattr(tracer,'stop_reason',None)}")

        # neutralize the unpacking detector so it doesn't stop OUR check_license run,
        # but keep on_block's API-stub handling + single-step support intact.
        tracer.check_restored_entry = lambda a: False
        tracer.stop_reason = None

        # 2) OUR driver: inject a controllable serial via a GetVolumeInformationA handler
        # (the Tracer stops on unhandled imports, so we add ours to its handler table).
        state = {"serial": 0}
        def _gvi(self, symbol, rcx, rdx, r8, r9):     # lpVolumeSerialNumber = r9
            if r9:
                self.uc.mem_write(r9, struct.pack("<I", state["serial"] & 0xffffffff))
            return 1, {}
        tracer._handlers = dict(tracer._handlers)
        tracer._handlers["getvolumeinformationa"] = (_gvi, 8)

        for addr in (KEYBUF, RET_SENTINEL):
            try: uc.mem_map(addr & ~0xfff, 0x1000, UC_PROT_ALL)
            except UcError: pass
        base_sp = uc.reg_read(arch.sp) & ~0xF

        def call_check(ser, k):
            """Run the VM'd check_license(k) with volume serial=ser from the live OEP state."""
            state["serial"] = ser
            uc.mem_write(KEYBUF, k.encode() + b"\x00")
            sp = (base_sp - 0x800) & ~0xF
            uc.mem_write(sp, struct.pack("<Q", RET_SENTINEL))
            uc.reg_write(arch.sp, sp); uc.reg_write(ux.UC_X86_REG_RCX, KEYBUF)
            uc.reg_write(ux.UC_X86_REG_RIP, check_license)
            uc.emu_start(check_license, RET_SENTINEL, timeout=120 * 1000 * 1000)
            return uc.reg_read(ux.UC_X86_REG_RAX) & 0xffffffff

        # Battery: for several serials, the VM must accept exactly C0's key and reject others.
        print("\n== devirtualizer validation battery (VM result vs C0 formula) ==")
        ok = True
        for ser in (0x12345678, 0xAABBCCDD, 0xDEADBEEF, 0x00000000, 0xFFFFFFFF):
            good = f"{c0_expected_key(ser):08X}"
            bad = "00000000" if good != "00000000" else "11111111"
            r_good = call_check(ser, good)
            r_bad = call_check(ser, bad)
            passed = (r_good == 1 and r_bad == 0)
            ok &= passed
            print(f"  serial={ser:#010x}  key={good} -> {r_good}   wrong -> {r_bad}   "
                  f"{'PASS' if passed else 'FAIL'}")
        print(f"\n{'ALL PASS — the VM computes the C0 algorithm; devirtualizer is faithful.' if ok else 'some cases FAILED'}")

if __name__ == "__main__":
    main()
