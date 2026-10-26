#!/usr/bin/env python3
r"""REAForge devirt — VMProtect loader environment (x86-32 / x86-64, EXE / DLL).

This is VMProtect's implementation of the unpack step — the `protectors.VMProtect` class is the seam
around it, and campaigns reach it via `protectors.for_name(cfg.protector).unpack(...)`, never by
importing `VmpLoader` directly. Note: VMProtect's *VM* is not modeled here or anywhere — the real VM
handlers run on Unicorn and the generic x86 SymEngine shadows them; only the *unpack* (below) is
VMProtect-specific.

Wraps vmp-lazy-unpack's env mechanism into one reusable object: map the packed PE, build the
synthetic Windows process world (PEB/TEB/LDR + module export tables + API/syscall stubs), synthesize
missing api-set exports (32-bit CRT), set up the EXE/DLL entry frame, register the API handlers the
unpacker needs, emulate to the unpacked state, and snapshot it so later analyses reload in seconds.

One object serves both campaigns (x64 license_app EXE, x86 Dead Cells libhl.dll).
"""
from __future__ import annotations

import importlib
import os
import pickle
import struct
from pathlib import Path

import unicorn.x86_const as ux
import unpack.tracer as T
from unicorn import UC_ARCH_X86, UC_PROT_ALL, Uc, UcError
from unpack.arch import arch_of
from unpack.tracer import (
    PAGE_SIZE,
    Catalog,
    ModuleImage,
    TraceHooks,
    Tracer,
    collect_imports,
    ensure_catalog_arch,
    file_view_base_for,
    find_or_capture_catalog,
    load_pe,
    load_system_syscall_catalog,
    map_emu_windows_modules,
    map_pe,
    map_synthetic_process_state,
    pe_memory_image,
    recover_keys,
    require_catalog,
    split_import_label,
)

VMP_LAZY = os.environ.get("VMP_LAZY_UNPACK", r"C:\Tools\_downloads\research\vmp-lazy-unpack")
SYSWOW64 = r"C:\Windows\SysWOW64"


class VmpLoader:
    def __init__(self, packed_path, progress=lambda m: None):
        self.packed = Path(packed_path).resolve()
        self.pe = load_pe(self.packed.read_bytes())
        self.arch = arch_of(self.pe)
        self.M = self.arch.mask
        self.is_dll = bool(self.pe.FILE_HEADER.Characteristics & 0x2000)
        self.prog = progress
        self._build()

    # ---- synthetic export pools for uncatalogued api-set DLLs (32-bit CRT) ----
    def _synth_exports(self, import_slots):
        def names(dll):
            p = Path(SYSWOW64) / dll; pe2 = load_pe(p.read_bytes()); pe2.parse_data_directories(directories=[0])
            return [s.name.decode() for s in pe2.DIRECTORY_ENTRY_EXPORT.symbols if s.name]
        def cat_ok(m):
            try:
                for _ in require_catalog().exports(m): return True
                return True
            except Exception: return False
        uncat = {m for m in {split_import_label(l)[0] for l in import_slots.values()} if not cat_ok(m)}
        if not uncat: return 0
        ucrt = names("ucrtbase.dll"); core = list(dict.fromkeys(names("kernelbase.dll") + names("kernel32.dll")))
        syn = {m: (ucrt if "crt" in m else (core if "core" in m else list(dict.fromkeys(ucrt+core)))) for m in uncat}
        orig = require_catalog().exports
        def patched(name, _o=orig, _s=syn):
            if name in _s: return [{"name": s, "ordinal": i+1} for i, s in enumerate(_s[name])]
            return _o(name)
        require_catalog().exports = patched
        return len(uncat)

    def _build(self):
        arch = self.arch; pe = self.pe
        T.ACTIVE_CATALOG = Catalog(find_or_capture_catalog((Path.cwd(), Path(T.__file__).resolve().parent.parent), arch), arch)
        ensure_catalog_arch(T.ACTIVE_CATALOG, arch)
        self.image_base = pe.OPTIONAL_HEADER.ImageBase
        self.entry = self.image_base + pe.OPTIONAL_HEADER.AddressOfEntryPoint
        import_slots = collect_imports(pe)
        n = self._synth_exports(import_slots)
        if n: self.prog(f"synthesized export pools for {n} api-set modules")
        uc = Uc(UC_ARCH_X86, arch.uc_mode); self.uc = uc
        self.mapped_start, self.mapped_end = map_pe(uc, pe)
        emu_bytes = pe_memory_image(load_pe(require_catalog().ntdll_bytes))
        fvb = file_view_base_for(arch, self.mapped_start, self.mapped_end, (len(emu_bytes)+0xfff)&~0xfff)
        uc.mem_map(fvb, (len(emu_bytes)+0xfff)&~0xfff, UC_PROT_ALL); uc.mem_write(fvb, emu_bytes)
        module_bases, synth, export_lookup = map_emu_windows_modules(uc, import_slots, arch)
        proc = None if self.is_dll else ModuleImage(self.packed.name, self.mapped_start, pe.OPTIONAL_HEADER.SizeOfImage, self.entry, str(self.packed))
        rsp = map_synthetic_process_state(uc, module_bases, proc, arch)
        for _, r in arch.gpr: uc.reg_write(r, 0)
        uc.reg_write(arch.sp, rsp); uc.reg_write(ux.UC_X86_REG_EFLAGS, 0x202)
        if self.is_dll:
            if arch.bits == 64:
                uc.reg_write(ux.UC_X86_REG_RCX, self.mapped_start); uc.reg_write(ux.UC_X86_REG_RDX, 1)
            else:
                uc.mem_write(rsp, struct.pack("<IIII", arch.return_sentinel, self.mapped_start, 1, 0))
        uc.reg_write(arch.ip, self.entry)
        tr = Tracer(uc, self.mapped_start, self.mapped_end, synth, pe, module_bases, export_lookup, progress=self.prog, arch=arch)
        tr.module_paths = {b: f"C:\\Windows\\System32\\{nm}" for nm, b in module_bases.items()}
        tr.module_paths[self.mapped_start] = str(self.packed); tr.module_paths[0] = "C:\\host.exe"
        if self.is_dll: tr.module_paths[arch.host_image_base] = "C:\\host.exe"
        tr.files.files[self.packed.name.lower()] = self.packed.read_bytes()
        tr.encoded_string_keys = tuple(recover_keys(bytes(pe.__data__)))
        tr.files.files["ntdll.dll"] = require_catalog().ntdll_bytes
        tr.syscall_catalog = load_system_syscall_catalog()
        self.tracer = tr; self.module_bases = module_bases; self.export_lookup = export_lookup
        self._register_unpack_handlers()

    def _register_unpack_handlers(self):
        # kernel32!VirtualQuery and RtlUnwind: needed to drive a 32-bit DLL's CRT/DllMain init to the
        # point where VMProtect's VM-context tables are populated (see Dead Cells campaign notes).
        if self.arch.bits != 32: return
        ah32 = importlib.import_module("unpack.32bit.api_handlers_32")
        def _vq(self_, symbol, rcx, rdx, r8, r9):
            page=rcx&self.M; buf=rdx&self.M; length=r8&self.M
            regions=[(s,e,p) for (s,e,p) in self_.uc.mem_regions()]
            region=next(((s,e,p) for (s,e,p) in regions if s<=page<=e), None)
            info=ah32.memory_basic_information(self_, page, region, regions)
            if length<len(info) or not self_.writable_range(buf, len(info)): return 0, {}
            self_.uc.mem_write(buf, info); return len(info), {}
        def _ret0(self_, symbol, rcx, rdx, r8, r9): return 0, {}
        self.tracer._handlers = dict(self.tracer._handlers)
        self.tracer._handlers["virtualquery"] = (_vq, 3)
        self.tracer._handlers["rtlunwind"] = (_ret0, 4)

    def add_handler(self, symbol, fn, argc):
        self.tracer._handlers = dict(self.tracer._handlers)
        self.tracer._handlers[symbol.lower()] = (fn, argc)

    # ---- export / RVA resolution ----
    def resolve_export(self, name):
        self.pe.parse_data_directories()
        for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name and exp.name.decode(errors="ignore") == name:
                return self.mapped_start + exp.address
        raise KeyError(f"export {name!r} not found")
    def resolve_rva(self, rva):
        return self.mapped_start + rva

    # ---- reach the unpacked state, with a reusable snapshot ----
    _SNAPREGS = None
    def reach_unpacked(self, snap_path=None):
        arch = self.arch; uc = self.uc
        regnames = [n for n, _ in arch.gpr] + ["EFLAGS"]
        def getr(n): return uc.reg_read(getattr(ux, "UC_X86_REG_"+n.upper()))
        def setr(n, v):
            try: uc.reg_write(getattr(ux, "UC_X86_REG_"+n.upper()), v)
            except Exception: pass
        self._hooks = TraceHooks(self.tracer, arch.peb_base, PAGE_SIZE); self._hooks.__enter__()
        fast = snap_path and os.environ.get("FAST") and os.path.exists(snap_path)
        if fast:
            self.restore_snapshot(snap_path)
        else:
            try: uc.emu_start(self.entry, 0)
            except UcError as e: self.prog(f"unpack emu error: {e}")
            self.prog(f"unpack stop={getattr(self.tracer,'stop_reason',None)}")
            if snap_path:
                regs = {rn.upper(): getr(rn) for rn in regnames}
                regions = []
                for (b, e, p) in uc.mem_regions():
                    try: regions.append((b, e-b+1, bytes(uc.mem_read(b, e-b+1))))
                    except UcError: pass
                try:
                    pickle.dump({"regions": regions, "regs": regs}, open(snap_path, "wb"))
                    self.prog(f"saved snapshot ({len(regions)} regions) -> {snap_path}")
                except Exception as ex: self.prog(f"snapshot save failed: {ex}")
        # neutralize the unpack detector so our own calls can run past OEP
        self.tracer.check_restored_entry = lambda a: False; self.tracer.stop_reason = None

    def restore_snapshot(self, snap_path):
        """Reset memory+registers to the clean post-unpack state (undo any prior calls' mutations)."""
        uc = self.uc
        d = pickle.load(open(snap_path, "rb"))
        for b, sz, data in d["regions"]:
            try: uc.mem_map(b, sz, UC_PROT_ALL)
            except UcError: pass
            try: uc.mem_write(b, data)
            except UcError: pass
        for rn, v in d["regs"].items():
            try: uc.reg_write(getattr(ux, "UC_X86_REG_"+rn), v)
            except Exception: pass
        self.tracer.check_restored_entry = lambda a: False; self.tracer.stop_reason = None
        self.prog(f"restored post-unpack snapshot ({len(d['regions'])} regions)")

    def close(self):
        try: self._hooks.__exit__(None, None, None)
        except Exception: pass
