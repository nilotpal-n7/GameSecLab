# Decompile the license decision in an UNPACKED VMProtect dump: anchor on the (now-decrypted)
# "LICENSED" string -> the function that references it (main) -> decompile it + direct callees.
import os

import ida_auto
import ida_funcs
import ida_hexrays
import ida_pro
import idautils
import idc

ida_auto.auto_wait()
ida_hexrays.init_hexrays_plugin()

ANCHORS = ("LICENSED", "INVALID LICENSE", "hex-key", "%08X")
roots = set()
for s in idautils.Strings():
    if any(a in str(s) for a in ANCHORS):
        for xref in idautils.DataRefsTo(s.ea):
            f = ida_funcs.get_func(xref)
            if f:
                roots.add(f.start_ea)

targets = set(roots)
for ea in list(roots):
    for item in idautils.FuncItems(ea):
        for xref in idautils.CodeRefsFrom(item, 0):
            cf = ida_funcs.get_func(xref)
            if cf:
                targets.add(cf.start_ea)

def decomp(ea):
    try:
        return str(ida_hexrays.decompile(ea))
    except Exception as e:
        return "// decompile failed @ 0x%x: %s" % (ea, e)

lines = []
for ea in sorted(targets):
    lines.append("// ===== %s @ 0x%x =====" % (idc.get_func_name(ea), ea))
    lines.append(decomp(ea))
    lines.append("")

out = os.path.join(os.path.dirname(idc.get_idb_path()), "ida_unpacked.txt")
open(out, "w", encoding="utf-8").write("\n".join(lines))
ida_pro.qexit(0)
