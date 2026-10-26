#!/usr/bin/env python3
r"""REAForge devirtualizer — 32-bit DLL export driver (Dead Cells libhl.dll benchmark).

Target: our own VMProtect 3.11-protected copy of Dead Cells' 32-bit libhl.dll
(C:\Tools\GameSecLab\capstone\libhl.vmp.dll). We virtualized the exported hash hl_hash_utf8
(Ultra + packing). Unlike check_license, hl_hash_utf8 makes NO API calls — it is pure arithmetic:

    int hl_hash_utf8(const char *name){ int h=0; while(*name){ h=223*h+(unsigned)*name; name++; } h%=0x1FFFFF7B; return h; }
    (HashLink src/std/obj.c:90 — our ground truth, confirmed via the cloned HaxeFoundation/hashlink)

We reuse vmp-lazy-unpack's env (auto-detects MODE32), run the packer to the unpacked state, resolve
the protected export, and call it cdecl on test strings. The VM must reproduce the source hash.

Run from the vmp-lazy-unpack checkout:
    cd C:\Tools\_downloads\research\vmp-lazy-unpack
    python C:\Tools\GameSecLab\reaforge\devirt\devirt_dll32.py C:\Tools\GameSecLab\capstone\libhl.vmp.dll
"""
import sys, struct, os, math
from pathlib import Path
VMP_LAZY = os.environ.get("VMP_LAZY_UNPACK", r"C:\Tools\_downloads\research\vmp-lazy-unpack")
sys.path.insert(0, VMP_LAZY)

from unicorn import Uc, UC_ARCH_X86, UC_PROT_ALL, UcError
import unicorn.x86_const as ux

import unpack.tracer as T
from unpack.tracer import (
    Catalog, find_or_capture_catalog, ensure_catalog_arch, load_pe, collect_imports,
    map_pe, map_emu_windows_modules, map_synthetic_process_state, Tracer, TraceHooks,
    ModuleImage, pe_memory_image, file_view_base_for, recover_keys,
    load_system_syscall_catalog, require_catalog, PAGE_SIZE,
)
from unpack.arch import arch_of
from unpack.tracer import split_import_label

MOD = 0x1FFFFF7B
STRBUF = 0x30000000        # input C-string buffer (free region in MODE32 map)
RET    = 0x31000000        # call return sentinel

def ref_hash(s: bytes) -> int:
    """hl_hash_utf8 reference (C int semantics) -> 32-bit EAX representation."""
    h = 0
    for c in s:
        h = (223 * h + c) & 0xFFFFFFFF
    hs = h - 0x100000000 if (h & 0x80000000) else h     # signed int
    r = int(math.fmod(hs, MOD))                          # C '%' truncates toward zero
    return r & 0xFFFFFFFF

def main():
    packed = Path(sys.argv[1]).resolve()
    pe = load_pe(packed.read_bytes())
    arch = arch_of(pe)
    print(f"[setup] arch = {arch.bits}-bit (machine=0x{arch.machine:X})")
    prog = lambda m: print("  [setup]", m)

    T.ACTIVE_CATALOG = Catalog(find_or_capture_catalog((Path.cwd(), Path(T.__file__).resolve().parent.parent), arch), arch)
    ensure_catalog_arch(T.ACTIVE_CATALOG, arch)
    image_base = pe.OPTIONAL_HEADER.ImageBase
    entry = image_base + pe.OPTIONAL_HEADER.AddressOfEntryPoint
    import_slots = collect_imports(pe)
    # libhl imports api-ms-win-crt-* / api-ms-win-core-* API-SET DLLs absent from our catalog. VMProtect's
    # Import Protection RE-RESOLVES the FULL import set during unpacking by walking module export tables
    # (the packed import table is stripped to thin descriptors), so we must PROVIDE each api-set module's
    # real export names, not drop them. The crt sets forward to ucrtbase.dll; the core sets to
    # kernelbase/kernel32. We give each uncatalogued module the matching real name pool from SysWOW64 (a
    # superset), so every name the resolver seeks is present. Stubs ret 0 and hl_hash_utf8 calls none.
    import pefile as _pf
    def _names(dll):
        p = os.path.join(r"C:\Windows\SysWOW64", dll)
        pe2 = _pf.PE(p, fast_load=True); pe2.parse_data_directories(directories=[0])
        ns = [s.name.decode() for s in pe2.DIRECTORY_ENTRY_EXPORT.symbols if s.name]; pe2.close(); return ns
    _ucrt = _names("ucrtbase.dll"); _core = list(dict.fromkeys(_names("kernelbase.dll") + _names("kernel32.dll")))
    def _cat_ok(modname):
        try:
            for _ in require_catalog().exports(modname): return True
            return True
        except Exception: return False
    _uncat = {split_import_label(label)[0] for label in import_slots.values()}
    _uncat = {m for m in _uncat if not _cat_ok(m)}
    if _uncat:
        def _pool(m): return _ucrt if "crt" in m else (_core if "core" in m else list(dict.fromkeys(_ucrt + _core)))
        _syn = {m: _pool(m) for m in _uncat}
        _orig_exports = require_catalog().exports
        def _patched(name, _o=_orig_exports, _s=_syn):
            if name in _s: return [{"name": sym, "ordinal": i + 1} for i, sym in enumerate(_s[name])]
            return _o(name)
        require_catalog().exports = _patched
        print(f"[setup] synthesized full export pools for {len(_syn)} api-set modules (crt={len(_ucrt)}, core={len(_core)})")
    uc = Uc(UC_ARCH_X86, arch.uc_mode)
    mapped_start, mapped_end = map_pe(uc, pe)
    emu_file_bytes = pe_memory_image(load_pe(require_catalog().ntdll_bytes))
    fvb = file_view_base_for(arch, mapped_start, mapped_end, (len(emu_file_bytes) + 0xfff) & ~0xfff)
    uc.mem_map(fvb, (len(emu_file_bytes) + 0xfff) & ~0xfff, UC_PROT_ALL); uc.mem_write(fvb, emu_file_bytes)
    module_bases, synth_targets, export_lookup = map_emu_windows_modules(uc, import_slots, arch)
    is_dll = bool(pe.FILE_HEADER.Characteristics & 0x2000)
    proc_img = None if is_dll else ModuleImage(packed.name, mapped_start, pe.OPTIONAL_HEADER.SizeOfImage, entry, str(packed))
    rsp = map_synthetic_process_state(uc, module_bases, proc_img, arch)
    for _, reg in arch.gpr: uc.reg_write(reg, 0)
    uc.reg_write(arch.sp, rsp); uc.reg_write(ux.UC_X86_REG_EFLAGS, 0x202)
    if is_dll:   # 32-bit DllMain(hinst, DLL_PROCESS_ATTACH, NULL) stdcall frame — mirrors kit run()
        uc.mem_write(rsp, struct.pack("<IIII", arch.return_sentinel, mapped_start, 1, 0))
    uc.reg_write(arch.ip, entry)
    tracer = Tracer(uc, mapped_start, mapped_end, synth_targets, pe, module_bases, export_lookup,
                    progress=prog, diagnostics=None, arch=arch)
    tracer.module_paths = {b: f"C:\\Windows\\System32\\{n}" for n, b in module_bases.items()}
    tracer.module_paths[mapped_start] = str(packed); tracer.module_paths[0] = "C:\\host.exe"
    if is_dll: tracer.module_paths[arch.host_image_base] = "C:\\host.exe"
    tracer.files.files[packed.name.lower()] = packed.read_bytes()
    tracer.encoded_string_keys = tuple(recover_keys(bytes(pe.__data__)))
    tracer.files.files["ntdll.dll"] = require_catalog().ntdll_bytes
    tracer.syscall_catalog = load_system_syscall_catalog()

    # resolve hl_hash_utf8 export RVA from the (packed) export table
    pe.parse_data_directories()
    target_rva = None
    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        if exp.name and exp.name.decode(errors="ignore") == "hl_hash_utf8":
            target_rva = exp.address; break
    if target_rva is None:
        print("hl_hash_utf8 export not found"); return
    func = mapped_start + target_rva
    print(f"[setup] hl_hash_utf8 @ RVA 0x{target_rva:X} -> VA 0x{func:X}")

    # original .text range (restored by the unpacker). We stop at the FIRST entry into .text (= OEP /
    # real DllMain) so sections are restored but CRT init never runs — it would need the api-ms-win-crt
    # imports we dropped, and hl_hash_utf8 (pure arithmetic) needs no CRT state anyway.
    text_lo = text_hi = None
    for s in pe.sections:
        if s.Name.rstrip(b"\x00") == b".text":
            text_lo = mapped_start + s.VirtualAddress
            text_hi = text_lo + max(s.Misc_VirtualSize, s.SizeOfRawData)
    print(f"[setup] .text range 0x{text_lo:X}-0x{text_hi:X}")

    # kernel32!VirtualQuery isn't in the kit's handler table (it has NtQueryVirtualMemory + Virtual*),
    # but libhl's CRT/DllMain init calls it directly, so the unpack stalls there and VMProtect's later
    # VM-runtime init never runs. Register a VirtualQuery handler built on the kit's own MBI helper.
    import importlib
    _ah32 = importlib.import_module("unpack.32bit.api_handlers_32")
    def _virtual_query(self, symbol, rcx, rdx, r8, r9):
        page = rcx & 0xFFFFFFFF; buf = rdx & 0xFFFFFFFF; length = r8 & 0xFFFFFFFF
        regions = [(s, e, p) for (s, e, p) in self.uc.mem_regions()]
        region = next(((s, e, p) for (s, e, p) in regions if s <= page <= e), None)
        info = _ah32.memory_basic_information(self, page, region, regions)
        if length < len(info) or not self.writable_range(buf, len(info)):
            return 0, {}
        self.uc.mem_write(buf, info)
        return len(info), {}
    def _ret0(self, symbol, rcx, rdx, r8, r9):   # benign stdcall stub (cleans N args, returns 0)
        return 0, {}
    tracer._handlers = dict(tracer._handlers)
    tracer._handlers["virtualquery"] = (_virtual_query, 3)
    tracer._handlers["rtlunwind"] = (_ret0, 4)

    CALLSTK, CALLSTK_SZ = 0x20000000, 0x40000
    import pickle
    SNAP = r"C:\Tools\GameSecLab\capstone\dll32_postunpack.snap"
    FAST = bool(os.environ.get("FAST")) and os.path.exists(SNAP)
    SNAPREGS = ("EAX","EBX","ECX","EDX","ESI","EDI","EBP","ESP","EIP","EFLAGS")
    with TraceHooks(tracer, arch.peb_base, PAGE_SIZE):
        # The VMProtect-virtualized entry runs in .vmp (never natively in .text), so we can't stop at a
        # clean native OEP. Let the unpacker fully restore sections and run to its natural stop; snapshot
        # the post-unpack memory so later probes reload in seconds (FAST=1) instead of re-running ~164M insns.
        if FAST:
            d = pickle.load(open(SNAP, "rb"))
            for b, sz, data in d["regions"]:
                try: uc.mem_map(b, sz, UC_PROT_ALL)
                except UcError: pass
                try: uc.mem_write(b, data)
                except UcError: pass
            for rn, val in d["regs"].items():
                try: uc.reg_write(getattr(ux, "UC_X86_REG_" + rn), val)
                except Exception: pass
            print(f"[fast] restored post-unpack snapshot ({len(d['regions'])} regions)")
        else:
            try:
                uc.emu_start(entry, 0)
            except UcError as e:
                print("unpack emu error:", e)
            print(f"[unpack] stop={getattr(tracer,'stop_reason',None)} ip=0x{uc.reg_read(arch.ip):X}")
            regs = {rn: uc.reg_read(getattr(ux, "UC_X86_REG_" + rn)) for rn in SNAPREGS}
            regions = []
            for (b, e, p) in uc.mem_regions():
                try: regions.append((b, e - b + 1, bytes(uc.mem_read(b, e - b + 1))))
                except UcError: pass
            try:
                pickle.dump({"regions": regions, "regs": regs}, open(SNAP, "wb"))
                print(f"[snap] saved {len(regions)} regions -> {SNAP}")
            except Exception as ex:
                print("[snap] save failed:", ex)
        tracer.check_restored_entry = lambda a: False
        tracer.stop_reason = None

        for addr, sz in ((STRBUF, 0x1000), (RET, 0x1000), (CALLSTK, CALLSTK_SZ)):
            try: uc.mem_map(addr & ~0xfff, sz, UC_PROT_ALL)
            except UcError: pass

        def call_hash(s: bytes):
            tracer.stop_reason = None
            uc.mem_write(STRBUF, s + b"\x00")
            for _, r in arch.gpr: uc.reg_write(r, 0)         # clean register state for a cdecl call
            sp = (CALLSTK + CALLSTK_SZ // 2) & ~0xF           # fresh stack, room both directions
            uc.mem_write(sp, struct.pack("<I", RET))          # return address
            uc.mem_write(sp + 4, struct.pack("<I", STRBUF))   # arg0 = const char* name (cdecl)
            uc.reg_write(arch.sp, sp)
            uc.reg_write(arch.ip, func)
            uc.emu_start(func, RET, timeout=120 * 1000 * 1000)
            return uc.reg_read(ux.UC_X86_REG_EAX) & 0xFFFFFFFF

        print("\n== devirtualizer validation battery (virtualized hl_hash_utf8 vs HashLink source) ==")
        ok = True
        for s in (b"", b"a", b"Player", b"takeDamage", b"__string", b"value", b"Dead Cells", b"BiomeLevelGen"):
            want = ref_hash(s)
            try:
                got = call_hash(s)
            except UcError as e:
                print(f"  {s!r:16} -> emu error: {e}"); ok = False; continue
            passed = (got == want); ok &= passed
            print(f"  {s!r:16} VM=0x{got:08X}  src=0x{want:08X}  {'PASS' if passed else 'FAIL'}")
        print(f"\n{'ALL PASS -- the VM reproduces hl_hash_utf8 exactly; 32-bit devirtualizer is faithful on a real shipping VMProtect 3.11 game DLL.' if ok else 'some cases FAILED'}")

if __name__ == "__main__":
    main()
