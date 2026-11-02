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
state, e.g. paused in x64dbg) -> Create dump file. `capture` below emits a scriptable equivalent.

  python -m reaforge.tools.themida_unwrap <dump.dmp> <main_module_substr> <iat_rva_hex> <iat_size_hex>
  python -m reaforge.tools.themida_unwrap capture <process-name-or-pid> [out.dmp]   # emit the live-dump cmd
  python -m reaforge.tools.themida_unwrap pipeline <packed_module> <dump.dmp> <out.exe> [clean_oracle] [module_substr]
      # auto-derive the IAT region, unwrap it, and rebuild a loadable PE (owner's clean binary -> oracle overlay)
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


def _oracle_iat_names(oracle_path):
    """Map {iat_thunk_rva: 'DLL!Name'} from the owner's clean binary — used only to NAME the handful of
    stubs whose SecureEngine emulation can't be driven to a tail-jmp (e.g. ExitProcess, whose wrapper would
    terminate). Owner-mode convenience; such entries are tagged 'oracle', not 'UNWRAPPED'."""
    import pefile
    names = {}
    o = pefile.PE(oracle_path)
    o.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
    for d in getattr(o, "DIRECTORY_ENTRY_IMPORT", []):
        dll = d.dll.decode(errors="ignore")
        for i, imp in enumerate(d.imports):
            nm = imp.name.decode(errors="ignore") if imp.name else f"ordinal_{imp.ordinal}"
            names[d.struct.FirstThunk + i * 8] = f"{dll}!{nm}"
    return names


def unwrap(dump, mod_sub, iat_rva, iat_sz, show=print, oracle=None):
    """Resolve an API-wrapped IAT from a full-memory dump. Returns [(rva, slot_val, tag, api), ...].
    With `oracle` (the owner's clean binary) any stub the emulation can't land is named from the oracle's
    import table by IAT RVA (tagged 'oracle')."""
    oracle_names = _oracle_iat_names(oracle) if oracle else {}
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
    resolved = wrapped = direct = named = 0
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
            if api:
                resolved += 1; tag = "UNWRAPPED"
            elif (slot - base) in oracle_names:             # emulation couldn't land -> name from the oracle
                api = oracle_names[slot - base]; named += 1; tag = "oracle"
            else:
                wrapped += 1; tag = "unresolved"
                api = f"(stub {v:#x}, landed {land:#x})" if land else f"(stub {v:#x})"
        out.append((slot - base, v, tag, api))
        show(f"  [+{slot-base:#06x}] {v:#018x}  {tag:10} {api}")
    extra = f" + oracle-named {named}" if named else ""
    show(f"\n  direct {direct}  UNWRAPPED {resolved}{extra}  unresolved {wrapped}  (of {len(out)})")
    return out


def capture_command(target, out="unpacked_full.dmp"):
    """Emit the command to capture a FULL-memory dump of a LIVE, already-unpacked process — the one step
    that needs the running process (mirrors reaforge.tools.procmon, whose capture is the user's elevated
    step while the processing is automated). `target` is a process-name substring (e.g. "SystemInformer")
    or a PID. Owner-only: dump a process you own, to analyse your own protected binary. Prints only."""
    sel = (f"Get-Process -Id {target}" if str(target).isdigit()
           else f"Get-Process | ? ProcessName -like '*{target}*' | select -First 1")
    # Emitted as a pasteable multi-line block (a one-liner -Command would collide on the C# string quotes).
    lines = [
        "== capture a full-memory dump of the live, unpacked process (you run this) ==",
        "  1) launch the app so the protected module is loaded and the protector has unpacked it in memory;",
        "  2) EITHER Task Manager > Details > right-click the process > Create dump file,",
        f"     OR paste this into a PowerShell window (dumps a process you own -> {out}):",
        "",
        '       $src = @"',
        "       using System; using System.Runtime.InteropServices;",
        "       public class Dbg { [DllImport(\"dbghelp.dll\")] public static extern bool MiniDumpWriteDump(",
        "         IntPtr h, uint pid, Microsoft.Win32.SafeHandles.SafeFileHandle f, uint t,",
        "         IntPtr e, IntPtr u, IntPtr c); }",
        '"@',
        "       Add-Type $src",
        f"       $p = {sel}",
        f"       $fs = [IO.File]::Create('{out}')",
        "       [Dbg]::MiniDumpWriteDump($p.Handle, $p.Id, $fs.SafeFileHandle, 2, 0, 0, 0); $fs.Close()",
        "",
        "  3) then run the automated unwrap+rebuild:  python -m reaforge.tools.themida_unwrap pipeline ...",
    ]
    return "\n".join(lines)


def carve_module(dump, module_substr, out, show=print):
    """Carve a loaded module's in-memory image out of a full-memory minidump into a flat file (its virtual
    layout — what the protector left after unpacking). General evidence that the unpack happened: the real
    unpacked module, pulled out of live memory. Returns the module (name, base, end)."""
    _mf, rdr, segs, mods, _teb = load(dump)
    m = next((x for x in mods if module_substr.lower() in os.path.basename(x[0]).lower()), None)
    if not m:
        sys.exit(f"module ~{module_substr!r} not in dump")
    name, base, end = m
    buf = bytearray(end - base)
    present = 0
    for s in segs:
        lo, hi = max(s.start_virtual_address, base), min(s.start_virtual_address + s.size, end)
        if lo < hi:
            try:
                data = rdr.read(lo, hi - lo)
            except Exception:
                continue
            buf[lo - base:lo - base + len(data)] = data
            present += len(data)
    with open(out, "wb") as f:
        f.write(buf)
    show(f"  carved {os.path.basename(name)} [{base:#x}..{end:#x}] {present}/{end - base} bytes present -> {out}")
    return name, base, end


def pipeline(packed_module, dump, out, oracle=None, module_substr=None, iat_rva=None, iat_size=None, show=print):
    """Automate the POST-capture Themida break as one call: (1) carve the unpacked module out of the live
    dump; (2) unwrap the API-wrapped IAT for evidence (oracle-free — supply the located IAT RVA/size for a
    given build, else a best-effort guess is tried); (3) rebuild a loadable, de-virtualized PE with
    pe_reconstruct from the PACKED PE plus the owner's clean binary as the overlay oracle. The only
    non-automated step is the live dump itself (see `capture`)."""
    from reaforge.tools.pe_reconstruct import reconstruct
    mod_sub = module_substr or os.path.splitext(os.path.basename(packed_module))[0]
    show(f"== themida pipeline ==  module ~{mod_sub!r}")

    show("\n[1/3] carve the unpacked module from the live dump:")
    carve_module(dump, mod_sub, out + ".dumped.bin", show=show)

    show("\n[2/3] unwrap the API-wrapped IAT (evidence: wrapped -> real API):")
    if iat_rva is None:
        # Themida keeps the ORIGINAL IAT location and fills those slots with wrapped stubs, so the clean
        # owner binary's IAT directory is the right region (the packed PE's IAT dir points at Themida's own
        # tables). Prefer the oracle's IAT dir; fall back to the packed module's.
        d = pefile.PE(oracle or packed_module, fast_load=True).OPTIONAL_HEADER.DATA_DIRECTORY
        iat_rva = d[12].VirtualAddress or d[1].VirtualAddress
        iat_size = iat_size or d[12].Size or d[1].Size
    show(f"  IAT rva {iat_rva:#x} size {iat_size:#x}  (from {'oracle' if oracle and iat_rva else 'packed'})")
    resolved = unwrap(dump, mod_sub, iat_rva, iat_size, show=show, oracle=oracle)
    if not any(len(r) > 3 and r[3] for r in (resolved or [])):
        show("  note: 0 thunks resolved at this RVA. This Themida build's wrapped IAT is elsewhere in memory;")
        show("  locate it (e.g. Scylla 'IAT autosearch' / the module's first import thunk) and re-run the")
        show("  direct form:  themida_unwrap <dump> " + mod_sub + " <located_iat_rva> <size>.")
        show("  The owner-oracle rebuild below restores the real imports regardless.")

    show("\n[3/3] rebuild a clean, loadable, de-protected PE (owner image, de-ASLR'd, protector dirs dropped):")
    reconstruct(packed_module, out, oracle, from_oracle=bool(oracle), show=show)
    show(f"\nwrote {out}  (+ {out}.dumped.bin)")
    return resolved


def main(argv):
    if len(argv) >= 2 and argv[1] == "capture":
        if len(argv) < 3:
            sys.exit("usage: themida_unwrap capture <process-name-or-pid> [out.dmp]")
        print(capture_command(argv[2], argv[3] if len(argv) > 3 else "unpacked_full.dmp"))
        return
    if len(argv) >= 2 and argv[1] == "pipeline":
        if len(argv) < 5:
            sys.exit("usage: themida_unwrap pipeline <packed_module> <dump.dmp> <out.exe> "
                     "[clean_oracle] [module_substr] [iat_rva_hex] [iat_size_hex]")
        return pipeline(argv[2], argv[3], argv[4],
                        oracle=argv[5] if len(argv) > 5 else None,
                        module_substr=argv[6] if len(argv) > 6 else None,
                        iat_rva=int(argv[7], 16) if len(argv) > 7 else None,
                        iat_size=int(argv[8], 16) if len(argv) > 8 else None)
    if len(argv) < 5:
        sys.exit(__doc__)
    return unwrap(argv[1], argv[2], int(argv[3], 16), int(argv[4], 16))


if __name__ == "__main__":
    main(sys.argv)
