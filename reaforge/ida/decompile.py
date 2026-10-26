"""IDA headless decompile script (run: idat.exe -A -S"ida_decompile.py" <target>).
Decompiles the license functions and writes pseudocode to targets/license_app/dumps/ida_decompile.txt.
Also usable from REAForge as an automated 'decompile' step.
"""
import ida_auto
import ida_hexrays
import idautils
import idc

ida_auto.auto_wait()
ok = ida_hexrays.init_hexrays_plugin()
out = [f"// hexrays available: {ok}"]
WANT = ("check_license", "expected_key", "machine_id", "main")
for ea in idautils.Functions():
    name = idc.get_func_name(ea)
    if any(w in name for w in WANT):
        try:
            out.append(f"\n// ===== {name} @ {ea:#x} =====\n" + str(ida_hexrays.decompile(ea)))
        except Exception as e:
            out.append(f"\n// {name}: decompile failed: {e}")
open(r"C:\Tools\GameSecLab\targets\license_app\dumps\ida_decompile.txt", "w", encoding="utf-8").write("\n".join(out))
idc.qexit(0)
