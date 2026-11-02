#!/usr/bin/env python3
r"""IDA headless: pull the Gen2 / Pro gate only (no giant config dumps).

Targets the GUI Pro predicate (sub_140116E90) and any function that references the Gen1/Gen2
activation strings (the Gen2 validator + its helpers). Each function over a size cap is listed by
name/size instead of decompiled, so the output stays focused on the license logic.

  ida -A -S"<path>\gen2_hunt.py" "<a COPY of the target>.exe"
Output -> targets/quint_bezier/dumps/qn_gen2.txt
"""

import os

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

OUT = os.environ.get("QN_OUT") or r"C:\Tools\GameSecLab\targets\quint_bezier\dumps\qn_gen2.txt"
SEED = [0x140116E90]  # GUI "am I Pro?" predicate (only if this is QuintBezier.exe)
ANCHORS = ("Gen1", "Gen2", "redeem", "upgradeable", "Gen2 License", "Gen1 License", "Convert", "ValidCPU", "ea")  # Gen1/Gen2 dialog + the flags the activator wrote
HEAD_CAP = 700  # skip decompiling functions bigger than this many instrs

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


funcs = {f for f in SEED if ida_funcs.get_func(f)}
hits = {}
for a in ANCHORS:
    vas = set()
    for pat in (a.encode("ascii", "ignore"), a.encode("utf-16-le")):
        if pat:
            vas.update(find_all(pat))
    for va in vas:
        refs = list(idautils.XrefsTo(va))
        for xr in refs:
            f = ida_funcs.get_func(xr.frm)
            if f:
                funcs.add(f.start_ea)
                hits.setdefault(f.start_ea, set()).add(a)
        # pointer-table indirection
        import struct

        for p in find_all(struct.pack("<Q", va)):
            for xr in idautils.XrefsTo(p):
                f = ida_funcs.get_func(xr.frm)
                if f:
                    funcs.add(f.start_ea)
                    hits.setdefault(f.start_ea, set()).add(a + "*")

L = [f"// gen2 hunt; hexrays={have_hr}; functions={len(funcs)}"]
for fea in sorted(funcs):
    f = ida_funcs.get_func(fea)
    n = sum(1 for _ in idautils.Heads(f.start_ea, f.end_ea))
    tag = sorted(hits.get(fea, []))
    L.append(f"\n==== {ida_funcs.get_func_name(fea)} @ {fea:#x}  heads={n}  refs={tag} ====")
    if n > HEAD_CAP:
        L.append(f"  (skipped: {n} instrs > cap {HEAD_CAP})")
        continue
    if have_hr:
        try:
            L.append(str(ida_hexrays.decompile(fea)))
            continue
        except Exception as e:
            L.append(f"  (decompile failed: {e}; disasm)")
    for h in idautils.Heads(f.start_ea, f.end_ea):
        L.append(f"  {h:#x}  {idc.generate_disasm_line(h, 0)}")

open(OUT, "w", encoding="utf-8").write("\n".join(L))
idc.qexit(0)
