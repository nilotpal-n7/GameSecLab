#!/usr/bin/env python3
r"""Generic IDA license-locator — the automated path for UNPROTECTED license RE.

reaforge's orchestrator automates the *protected* path (recon -> classify protector -> emulation
devirt). When recon classifies a target as plain/unprotected (standard compiler output, debug symbols,
moderate entropy), there's no VM to lift — the license check is in normal code and the job is to FIND
and read it. This tool is that step, generalized from the quint_bezier break: scan for license anchor
strings, follow BOTH direct refs AND pointer-table entries (robust to LTCG/optimized builds where
Strings()+xref misses), and Hex-Rays (or disasm) the referencing functions, skipping giant ones.

Runs inside IDA against whatever binary IDA opened. Parameterize via env so it's not target-specific:
  QN_ANCHORS  comma-separated anchor substrings (case-insensitive; ascii + utf-16le matched)
  QN_SEED     comma-separated hex addresses to always decompile (e.g. a known predicate)
  QN_CAP      skip decompiling functions with more than this many instrs (default 700)
  QN_OUT      output path (default %TEMP%\qn_license_decomp.txt)

  ida -A -S"<path>\license_recon.py" "<a COPY of the target>.exe"
"""
import os
import struct

import ida_auto
import ida_bytes
import ida_funcs
import ida_hexrays
import idautils
import idc

ida_auto.auto_wait()
try:
    have_hr = ida_hexrays.init_hexrays_plugin()
except Exception:
    have_hr = False

DEFAULT_ANCHORS = ("LicensedTo", "Registered User", "Activat", "activat", "ViewState", "CacheTag",
                   "Genuine", "License", "licen", "Serial", "serial", "unlock", "RegKey", "RegName",
                   ".key", "Trial", "Expired", "Gen1", "Gen2")
ANCHORS = tuple(a for a in os.environ.get("QN_ANCHORS", "").split(",") if a) or DEFAULT_ANCHORS
SEED = [int(x, 16) for x in os.environ.get("QN_SEED", "").replace(" ", "").split(",") if x]
HEAD_CAP = int(os.environ.get("QN_CAP", "700"))
OUT = os.environ.get("QN_OUT") or os.path.join(os.environ.get("TEMP", "."), "qn_license_decomp.txt")

segs = []
for s in idautils.Segments():
    data = ida_bytes.get_bytes(s, idc.get_segm_end(s) - s) or b""
    segs.append((s, data))


def find_all(pat):
    for base, data in segs:
        i = data.find(pat)
        while i != -1:
            yield base + i
            i = data.find(pat, i + 1)


funcs = {f for f in SEED if ida_funcs.get_func(f)}
hits = {}
for a in ANCHORS:
    vas = set()
    for pat in (a.encode("ascii", "ignore"), a.encode("utf-16-le")):
        if pat:
            vas.update(find_all(pat))
    for va in vas:
        for xr in idautils.XrefsTo(va):
            f = ida_funcs.get_func(xr.frm)
            if f:
                funcs.add(f.start_ea); hits.setdefault(f.start_ea, set()).add(a)
        for p in find_all(struct.pack("<Q", va)):               # pointer-table indirection
            for xr in idautils.XrefsTo(p):
                f = ida_funcs.get_func(xr.frm)
                if f:
                    funcs.add(f.start_ea); hits.setdefault(f.start_ea, set()).add(a + "*")

L = [f"// license_recon; hexrays={have_hr}; anchors={len(ANCHORS)}; functions={len(funcs)}; cap={HEAD_CAP}"]
for fea in sorted(funcs):
    f = ida_funcs.get_func(fea)
    n = sum(1 for _ in idautils.Heads(f.start_ea, f.end_ea))
    L.append(f"\n==== {ida_funcs.get_func_name(fea)} @ {fea:#x}  heads={n}  refs={sorted(hits.get(fea, []))} ====")
    if n > HEAD_CAP:
        L.append(f"  (skipped: {n} instrs > cap {HEAD_CAP})"); continue
    done = False
    if have_hr:
        try:
            L.append(str(ida_hexrays.decompile(fea))); done = True
        except Exception as e:
            L.append(f"  (decompile failed: {e}; disasm)")
    if not done:
        for h in idautils.Heads(f.start_ea, f.end_ea):
            L.append(f"  {h:#x}  {idc.generate_disasm_line(h, 0)}")

open(OUT, "w", encoding="utf-8").write("\n".join(L))
idc.qexit(0)
