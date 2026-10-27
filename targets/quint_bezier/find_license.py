#!/usr/bin/env python3
r"""IDA headless license-locator for the quint_bezier target (user's own software).

Finds the license-decision code without dumping the whole binary. Robust to LTCG/optimized builds
where strings are reached via a pointer table (IDA's Strings()+direct-xref misses those): scan every
segment for the anchor bytes (ASCII + UTF-16LE), then follow BOTH direct refs AND pointer-table
entries (an 8-byte LE pointer to the string) to the referencing functions, and Hex-Rays / disasm those.

Runs inside IDA against whatever binary IDA opened (reusable for QuintGovernor / QuintBezier /
qnActivate). Output -> %QN_OUT% or %TEMP%\qn_license_decomp.txt. Review/redact before sharing.

  ida -A -S"<path>\find_license.py" "<a COPY of the target>.exe"
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

OUT = os.environ.get("QN_OUT") or os.path.join(os.environ.get("TEMP", "."), "qn_license_decomp.txt")
ANCHORS = ("Quint Bezier Pro", "LicensedTo", "QN_ACTION_TOOK_LICENSE_EXPIRED", "probezier.key",
           "quintbezier.key", "Registered User", "ShowGraphLicenseName", "Genuine", "LICENSE_EXPIRED",
           "Activation", "RegKey", "RegName")

# snapshot every segment's bytes once
segs = []
for s in idautils.Segments():
    end = idc.get_segm_end(s)
    data = ida_bytes.get_bytes(s, end - s) or b""
    segs.append((s, data))


def find_all(pat):
    for base, data in segs:
        i = data.find(pat)
        while i != -1:
            yield base + i
            i = data.find(pat, i + 1)


# 1) anchor string VAs (ascii + utf-16le)
anchor_vas = {}
for a in ANCHORS:
    vas = set()
    for pat in (a.encode("ascii", "ignore"), a.encode("utf-16-le")):
        if pat:
            vas.update(find_all(pat))
    if vas:
        anchor_vas[a] = vas
all_vas = set().union(*anchor_vas.values()) if anchor_vas else set()

# 2) referencing addresses: direct code/data refs + pointer-table entries (a qword == the string VA)
ref_eas = set()
for va in all_vas:
    for xr in idautils.XrefsTo(va):
        ref_eas.add(xr.frm)
    for dr in idautils.DataRefsTo(va):
        ref_eas.add(dr)
    for ptr_ea in find_all(struct.pack("<Q", va)):            # pointer-table slot holding &string
        for xr in idautils.XrefsTo(ptr_ea):
            ref_eas.add(xr.frm)
        for dr in idautils.DataRefsTo(ptr_ea):
            ref_eas.add(dr)

# 3) map to functions
funcs = {}
for ea in ref_eas:
    f = ida_funcs.get_func(ea)
    if f:
        funcs.setdefault(f.start_ea, set()).add(ea)

L = [f"// anchors found: { {a: len(v) for a, v in anchor_vas.items()} }",
     f"// referencing sites: {len(ref_eas)}   functions: {len(funcs)}   hexrays={have_hr}"]
for fea, sites in sorted(funcs.items()):
    L.append(f"\n==== {ida_funcs.get_func_name(fea)} @ {fea:#x}   ({len(sites)} ref site(s)) ====")
    done = False
    if have_hr:
        try:
            L.append(str(ida_hexrays.decompile(fea))); done = True
        except Exception as e:
            L.append(f"  (decompile failed: {e}; disasm below)")
    if not done:
        f = ida_funcs.get_func(fea)
        for h in idautils.Heads(f.start_ea, f.end_ea):
            L.append(f"  {h:#x}  {idc.generate_disasm_line(h, 0)}")

if not funcs:
    L.append("\n// no referencing functions — anchor addresses for manual follow-up:")
    for a, vas in anchor_vas.items():
        L.append(f"//   {a!r}: " + ", ".join(hex(v) for v in sorted(vas)))

open(OUT, "w", encoding="utf-8").write("\n".join(L))
idc.qexit(0)
