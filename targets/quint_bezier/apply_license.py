#!/usr/bin/env python3
r"""Quint Bezier one-shot deploy — keygen + ready-to-run registry commands (user's own software).

The last mile of the unprotected-license crack: given a LicensedTo name, run keygen.py and emit the
EXACT commands to apply the result, with CacheTag already substituted — nothing left to hand-copy.
Under the hard no-access rule Claude never touches the install dir or the machine registry, so this
only PRINTS the commands; you run them (elevated) and restart the governor/GUI.

Why HKLM by default: QuintGovernor runs as a SYSTEM service and reads HKLM before HKCU, so an HKCU-only
write is invisible to it and won't flip Pro.

  python apply_license.py "Licensed Name"                   # Formula C, HKLM (default)
  python apply_license.py "Name" --hive HKCU                # per-user (GUI only; won't flip the service)
  python apply_license.py "Name" --machine OemId ProcType NumProc ProcRev ProcLevel   # Formula A
  python -m reaforge.orchestrator apply quint_bezier "Name" # same, via the orchestrator
"""

from __future__ import annotations

import sys

try:  # run as a script (keygen.py sits next to this file on sys.path[0])
    from keygen import keygen_machine, keygen_nameonly, name_sum
except ImportError:  # imported as targets.quint_bezier.apply_license (tests / orchestrator)
    from targets.quint_bezier.keygen import keygen_machine, keygen_nameonly, name_sum

SUBKEY = r"Software\QuintBezier"


def render(name, viewstate=0, hive="HKLM", subkey=SUBKEY, machine=None):
    """Compute the Formula-C (or -A, with machine fields) values and render the deploy commands."""
    if machine is not None:
        vs, ct = keygen_machine(name, *machine, viewstate=viewstate)
        formula = "A (machine-bound)"
    else:
        vs, ct = keygen_nameonly(name, viewstate)
        formula = "C (machine-independent)"
    key = f"{hive}\\{subkey}"
    lines = [
        f"== Quint Bezier deploy - Formula {formula} ==",
        f"  LicensedTo : {name!r}  (nameSum = {name_sum(name)})",
        f"  ViewState  : 0x{vs:016X}",
        f"  CacheTag   : 0x{ct:016X}",
    ]
    if hive == "HKCU":
        lines.append("  ! HKCU is invisible to the SYSTEM-service governor — use HKLM to flip Pro.")
    lines += [
        "",
        "  # run elevated (you run it - Claude never touches the registry/install dir):",
        f'  reg add "{key}" /v LicensedTo /t REG_SZ    /d "{name}"   /f',
        f'  reg add "{key}" /v ViewState  /t REG_QWORD /d 0x{vs:X}   /f',
        f'  reg add "{key}" /v CacheTag   /t REG_QWORD /d 0x{ct:X}   /f',
        "",
        "  # verify, then restart QuintGovernor + QuintBezier:",
        f'  reg query "{key}" /s',
        "",
        "  # zero-crypto fallback (patch the predicate on a COPY instead of writing the registry):",
        "  python patch_islicensed.py <QuintGovernor copy>.exe --rva 0x5170",
    ]
    return "\n".join(lines)


def main(argv):
    if len(argv) < 2:
        sys.exit(__doc__)
    name = argv[1]
    hive = argv[argv.index("--hive") + 1].upper() if "--hive" in argv else "HKLM"
    viewstate = int(argv[argv.index("--viewstate") + 1], 0) if "--viewstate" in argv else 0
    machine = None
    if "--machine" in argv:
        i = argv.index("--machine")
        vals = argv[i + 1 : i + 6]
        if len(vals) != 5:
            sys.exit("--machine needs: OemId ProcType NumProc ProcRev ProcLevel (from GetSystemInfo)")
        machine = [int(x, 0) for x in vals]
    print(render(name, viewstate=viewstate, hive=hive, machine=machine))


if __name__ == "__main__":
    main(sys.argv)
