#!/usr/bin/env python3
r"""IDA headless: recover the registry plumbing the license check uses (subkey, hive, value type).

Decompiles the 64-bit value reader (sub_14003D3D0) and the LicensedTo reader (sub_140033A00), and
decompiles whatever functions set the subkey-path globals (qword_1401114B8 / qword_1401114C0) so the
subkey string literal is visible. Output -> targets/quint_bezier/dumps/qn_reg_details.txt
(review/redact before sharing).

  ida -A -S"<path>\reg_details.py" "<a COPY of QuintGovernor>.exe"
"""
import os

import ida_auto
import ida_funcs
import ida_hexrays
import idautils
import idc

ida_auto.auto_wait()
try:
    have_hr = ida_hexrays.init_hexrays_plugin()
except Exception:
    have_hr = False

OUT = os.environ.get("QN_OUT") or r"C:\Tools\GameSecLab\targets\quint_bezier\dumps\qn_reg_details.txt"
FUNCS = [0x14003D3D0, 0x140033A00, 0x140033260]          # value reader, LicensedTo read, subkey setter
GLOBALS = [0x1401114B8, 0x1401114C0]                      # subkey-path globals (ViewState/CacheTag, LicensedTo)

# add every function that references the subkey-path globals (the initializer with the literal)
for g in GLOBALS:
    for xr in idautils.XrefsTo(g):
        f = ida_funcs.get_func(xr.frm)
        if f and f.start_ea not in FUNCS:
            FUNCS.append(f.start_ea)

L = [f"// reg-details; hexrays={have_hr}; functions={[hex(f) for f in FUNCS]}"]
for fea in FUNCS:
    if not ida_funcs.get_func(fea):
        ida_funcs.add_func(fea)
    L.append(f"\n==== {ida_funcs.get_func_name(fea)} @ {fea:#x} ====")
    done = False
    if have_hr:
        try:
            L.append(str(ida_hexrays.decompile(fea))); done = True
        except Exception as e:
            L.append(f"  (decompile failed: {e}; disasm)")
    if not done:
        f = ida_funcs.get_func(fea)
        if f:
            for h in idautils.Heads(f.start_ea, f.end_ea):
                L.append(f"  {h:#x}  {idc.generate_disasm_line(h, 0)}")

open(OUT, "w", encoding="utf-8").write("\n".join(L))
idc.qexit(0)
