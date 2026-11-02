#!/usr/bin/env python3
r"""System Informer Pro one-shot deploy — issue a machine-locked .sipm with the oracle + emit the deploy
commands (user's own software; the user holds the issuer private key).

The honest last mile of the SIP break (recovery_system_informer.md sec 6): you cannot FORGE a license
without the private key, so the demonstration is the oracle ISSUING a valid one. Given the target HWID and
the protected DLL's image CRC (both printed by sip_report_tool), this renders the exact license_signer.py
issue command + the deploy/verify steps, with the values substituted — nothing to hand-copy. Under the
no-access rule Claude never writes into the install dir, so the deploy line is PRINTED; you run it.

  python apply_license.py "Reviewer" --hwid <hex> --text-crc 0x<crc>      # Pro .sipm for this machine
  python apply_license.py "Reviewer"                                      # prints how to get HWID+CRC first
  python -m reaforge.orchestrator apply system_informer "Reviewer" --hwid <hex> --text-crc 0x<crc>
"""

from __future__ import annotations

import sys

SLUG = "enterprise-forensics"


def render(subject, hwid=None, crc=None, tier="pro", out=None, install_exe="SystemInformer.exe"):
    """Render the oracle-issue + deploy commands. hwid/crc come from sip_report_tool (the user runs it on
    the target machine); without them, render the step that obtains them. Prints only — no I/O."""
    out = out or f"licenses/{subject}.sipm"
    lines = [f"== System Informer Pro deploy - subject {subject!r}, tier {tier} =="]

    if not hwid or crc is None:
        lines += [
            "  need the machine HWID + the protected DLL's image CRC first (run beside sip_progate.dll):",
            "    .\\sip_report_tool.exe                         # prints HWID=... and TEXT_CRC=0x...",
            f"  then re-run with:  apply_license.py {subject!r} --hwid <HWID> --text-crc 0x<CRC>",
        ]
        return "\n".join(lines)

    crc_hex = f"0x{crc:08X}" if isinstance(crc, int) else str(crc)
    lines += [
        f"  HWID      : {hwid}",
        f"  image CRC : {crc_hex}   (whole on-disk sip_progate.dll; a patched byte changes it)",
        f"  slug      : {SLUG}",
        "",
        "  # 1) issue (oracle; uses the issuer private key the user holds - framework step):",
        f'  python license_signer.py issue --hwid {hwid} --text-crc {crc_hex} --subject "{subject}" --tier {tier} --out {out}',
        "",
        "  # 2) verify the issued license (oracle-side, and the attack demo that shallow cracks fail):",
        f"  python license_signer.py verify {out} --hwid {hwid} --text-crc {crc_hex}",
        f"  python license_signer.py attack {out} --hwid {hwid} --text-crc {crc_hex}",
        "",
        "  # 3) deploy (you run it - Claude never writes the install dir): place it beside the exe,",
        f"  #    or use Help > About > Activate Pro to pick {out} from the GUI:",
        f'  copy "{out}" "<install dir>\\SystemInformer.sipm"',
        "",
        "  # 4) confirm the live gate flipped (licensed -> sip_access_mask(DUMP) = 0x0450):",
        "  .\\sip_report_tool.exe SystemInformer.sipm",
    ]
    return "\n".join(lines)


def _opt(argv, flag):
    return argv[argv.index(flag) + 1] if flag in argv else None


def main(argv):
    if len(argv) < 2:
        sys.exit(__doc__)
    subject = argv[1]
    hwid = _opt(argv, "--hwid")
    crc_arg = _opt(argv, "--text-crc")
    crc = int(crc_arg, 0) if crc_arg is not None else None
    tier = _opt(argv, "--tier") or "pro"
    print(render(subject, hwid=hwid, crc=crc, tier=tier))


if __name__ == "__main__":
    main(sys.argv)
