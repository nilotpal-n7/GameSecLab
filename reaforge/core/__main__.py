#!/usr/bin/env python3
r"""REAForge devirt CLI — one authorization-gated entry for every title campaign.

    python -m reaforge.core <title> [arg] [modes]

      <title>   a folder under targets/ with a config.py (e.g. license_app, dead_cells)
      arg       title-specific (license_app: serial hex; dead_cells: symbolic length N)
      modes     comma-separated subset of: validate,recover,peel,prove  (default: all)

The title's packed binary must be listed in reaforge/authorized_targets.json (only analyze what you
own / may analyze):

    python -m reaforge.orchestrator authorize "<path>" "why you may analyze this"

Run from anywhere; this bootstraps the repo root and the vmp-lazy-unpack checkout onto sys.path.
"""
from __future__ import annotations

import importlib
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]          # C:\Tools\GameSecLab
VMP_LAZY = os.environ.get("VMP_LAZY_UNPACK", r"C:\Tools\_downloads\research\vmp-lazy-unpack")
for _p in (str(ROOT), VMP_LAZY):
    if _p not in sys.path:
        sys.path.insert(0, _p)

ALLOW = ROOT / "reaforge" / "authorized_targets.json"
TARGETS = ROOT / "targets"


def _titles():
    return sorted(d.name for d in TARGETS.iterdir() if (d / "config.py").exists())


def _check_authorized(packed):
    p = str(Path(packed).resolve())
    data = json.loads(ALLOW.read_text()) if ALLOW.exists() else {}
    if p not in data:
        sys.exit(f"REFUSED: {p} is not in authorized_targets.json.\n"
                 f"Only analyze targets you own / are authorized for. Add it with:\n"
                 f'  python -m reaforge.orchestrator authorize "{p}" "why you may analyze this"')


def main(argv):
    if len(argv) < 2 or argv[1] in ("-h", "--help"):
        print(__doc__); print(f"  titles: {', '.join(_titles())}"); return
    title = argv[1]
    if title not in _titles():
        sys.exit(f"unknown title {title!r}. known: {', '.join(_titles())}")
    try:
        cfg_mod = importlib.import_module(f"targets.{title}.config")
    except Exception as e:
        sys.exit(f"could not load targets/{title}/config.py: {e}")

    arg = argv[2] if len(argv) > 2 and "," not in argv[2] and argv[2] not in (
        "validate", "recover", "peel", "prove") else None
    modes_tok = argv[3] if arg and len(argv) > 3 else (argv[2] if not arg and len(argv) > 2 else None)
    modes = tuple(modes_tok.split(",")) if modes_tok else ("validate", "recover", "peel", "prove")

    packed = getattr(cfg_mod, "CONFIG").packed
    _check_authorized(packed)
    cfg_mod.run(arg=arg, modes=modes)


if __name__ == "__main__":
    main(sys.argv)
