#!/usr/bin/env python3
r"""IDA headless analysis of the System Informer Pro gate (run inside IDA Pro / idat.exe).

Target-aware (keys off the opened file name):
  * sip_progate.dll  — the VMProtect core: show the gate EXPORT thunks (VMEnter -> jmp into the VM),
    the libcrypto/BCrypt crypto imports (the AES-GCM/HKDF the KDF rides on), and attempt a Hex-Rays
    decompile of each gate export (virtualized -> expect it to bail / show the VMEnter, which is the
    evidence that the logic is not native).
  * SystemInformer.exe / ExtendedTools  — the CALLERS: find xrefs to sip_access_mask and to
    NtOpenProcess/PhOpenProcess and Hex-Rays the small caller functions, so the gate wiring
    (PhOpenProcess(&h, sip_access_mask(SIP_FEAT_DUMP), pid)) shows up as readable C (recovery doc §2).

  idat.exe -A -S"reaforge\tools\ida_sip_gate.py" -L"<log>" "<copy of target>"
  output: $QN_OUT (default %TEMP%\ida_sip_gate.txt)
"""

import os

import ida_auto
import ida_bytes
import ida_funcs
import ida_hexrays
import ida_nalt
import idaapi
import idautils
import idc

ida_auto.auto_wait()
try:
    HR = ida_hexrays.init_hexrays_plugin()
except Exception:
    HR = False

OUT = os.environ.get("QN_OUT") or os.path.join(os.environ.get("TEMP", "."), "ida_sip_gate.txt")
GATE = ("sip_access_mask", "sip_gate_init", "sip_xdll_respond", "sip_is_pro", "sip_image_text_crc32")
CRYPTO_HINTS = ("EVP_", "HKDF", "AES", "SHA", "BCrypt", "Crypt")
NTOPEN = ("NtOpenProcess", "ZwOpenProcess", "PhOpenProcess")
L = []


def w(s=""):
    L.append(s)


def disasm(ea, n=10, follow_jmp=True):
    cur = ea
    for _ in range(n):
        if cur == idc.BADADDR:
            break
        w(f"    {cur:#x}  {idc.generate_disasm_line(cur, 0) or ''}")
        mnem = idc.print_insn_mnem(cur)
        if mnem == "jmp" and follow_jmp:
            tgt = idc.get_operand_value(cur, 0)
            if tgt and tgt != idc.BADADDR:
                w(f"    -> follow jmp to {tgt:#x}:")
                t = tgt
                for __ in range(8):
                    if t == idc.BADADDR:
                        break
                    w(f"      {t:#x}  {idc.generate_disasm_line(t, 0) or ''}")
                    if idc.print_insn_mnem(t) in ("jmp", "ret", "retn"):
                        break
                    t = ida_bytes.get_item_end(t)
            break
        if mnem in ("ret", "retn"):
            break
        cur = ida_bytes.get_item_end(cur)


infile = (ida_nalt.get_root_filename() or "").lower()
w(f"// ida_sip_gate  file={infile}  hexrays={HR}")
try:
    _base = idaapi.get_imagebase()
except Exception:
    _base = 0
try:
    import ida_ida

    _entry = ida_ida.inf_get_start_ea()
except Exception:
    _entry = idc.BADADDR
w(f"// image base {_base:#x}  entry {_entry:#x}")

# segments
w("\n== segments ==")
for s in idautils.Segments():
    w(f"  {idc.get_segm_name(s):<10} {s:#x}-{idc.get_segm_end(s):#x}")

# exports
w("\n== exports ==")
exps = {name: ea for (_, _, ea, name) in idautils.Entries() if name}
for name, ea in sorted(exps.items(), key=lambda kv: kv[1]):
    tag = "  <-- GATE" if name in GATE else ""
    w(f"  {ea:#x}  {name}{tag}")

# imports (flag crypto + NtOpenProcess)
w("\n== imports (crypto / NtOpenProcess flagged) ==")
imp_found = {"crypto": [], "ntopen": [], "count": 0}


def imp_cb(ea, name, ordinal):
    imp_found["count"] += 1
    if name:
        if any(h.lower() in name.lower() for h in CRYPTO_HINTS):
            imp_found["crypto"].append((ea, name))
        if any(h.lower() in name.lower() for h in NTOPEN):
            imp_found["ntopen"].append((ea, name))
    return True


for i in range(idaapi.get_import_module_qty()):
    idaapi.enum_import_names(i, imp_cb)
w(f"  total imports: {imp_found['count']}")
w(f"  CRYPTO imports ({len(imp_found['crypto'])}):")
for ea, name in imp_found["crypto"][:40]:
    w(f"    {ea:#x}  {name}")
w(f"  NtOpenProcess-family imports ({len(imp_found['ntopen'])}):")
for ea, name in imp_found["ntopen"]:
    w(f"    {ea:#x}  {name}")

# gate exports: disasm + try decompile
w("\n== gate export bodies ==")
for name in GATE:
    ea = exps.get(name) or idc.get_name_ea_simple(name)
    if ea is None or ea == idc.BADADDR:
        continue
    w(f"\n-- {name} @ {ea:#x} --")
    disasm(ea, 6, follow_jmp=True)
    if HR:
        try:
            w("  [hexrays]")
            for ln in str(ida_hexrays.decompile(ea)).splitlines():
                w("    " + ln)
        except Exception as e:
            w(f"  [hexrays failed: {e}]  (virtualized body -> no native C, as expected)")


def decompile_func(fea, label):
    fn = ida_funcs.get_func(fea)
    if not fn:
        return
    n = sum(1 for _ in idautils.Heads(fn.start_ea, fn.end_ea))
    w(f"\n  ==== {label} {ida_funcs.get_func_name(fea)} @ {fea:#x}  heads={n} ====")
    if n > 600:
        w(f"    (skipped: {n} instrs > 600)")
        return
    if HR:
        try:
            for ln in str(ida_hexrays.decompile(fea)).splitlines():
                w("    " + ln)
            return
        except Exception as e:
            w(f"    (decompile failed: {e})")
    for h in idautils.Heads(fn.start_ea, fn.end_ea):
        w(f"    {h:#x}  {idc.generate_disasm_line(h, 0)}")


# caller side (SI.exe / plugin): the explicit-load shim + the functions that reference the sip_* strings
# (the real gate call sites: the dumper, the Activate-Pro flow). Focused, not a broad PhOpenProcess sweep.
w("\n== gate shim + call sites (focused) ==")
seen = set()

# 1) named shim functions, if the symbols are present (PDB)
for nm in ("SipProgateModule", "sip_gate_init", "sip_access_mask", "sip_is_pro", "sip_xdll_respond"):
    ea = idc.get_name_ea_simple(nm)
    if ea != idc.BADADDR and ea not in seen:
        seen.add(ea)
        decompile_func(ea, "shim")

# 2) functions that reference the gate strings (GetProcAddress args / the .sipm path) = the real call sites
segs = []
for s in idautils.Segments():
    d = ida_bytes.get_bytes(s, idc.get_segm_end(s) - s) or b""
    segs.append((s, d))
STR_ANCHORS = (b"sip_access_mask", b"sip_gate_init", b"sip_xdll_respond", b"SystemInformer.sipm")
anchor_funcs = {}
for pat in STR_ANCHORS:
    for base, data in segs:
        i = data.find(pat)
        while i != -1:
            va = base + i
            for xr in idautils.XrefsTo(va):
                f = ida_funcs.get_func(xr.frm)
                if f:
                    anchor_funcs.setdefault(f.start_ea, set()).add(pat.decode())
            i = data.find(pat, i + 1)
w(f"\n  functions referencing the gate strings: {len(anchor_funcs)}")
for fea in sorted(anchor_funcs):
    if fea in seen:
        continue
    seen.add(fea)
    decompile_func(fea, f"refs={sorted(anchor_funcs[fea])}")

open(OUT, "w", encoding="utf-8", errors="replace").write("\n".join(L))
idc.qexit(0)
