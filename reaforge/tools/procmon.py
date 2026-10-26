#!/usr/bin/env python3
r"""Procmon (Sysinternals) runtime-recon helper.

Procmon needs admin + its kernel driver, so the *capture* is your elevated step (this builds the
command); turning the exported CSV into facts is automated here and can feed the orchestrator.

  python -m reaforge.tools.procmon command <target.exe> [runtime_sec]    # the capture + export commands
  python -m reaforge.tools.procmon parse   <procmon.csv> [process_name]  # summarize into facts JSON
"""
from __future__ import annotations

import csv
import json
import os
import sys
from collections import Counter

PROCMON = next((p for p in (r"C:\Tools\ProcessMonitor\Procmon64.exe", r"C:\Tools\ProcessMonitor\Procmon.exe")
                if os.path.exists(p)), r"Procmon64.exe")


def command(target, runtime=20, backing="procmon.pml", csv_out="procmon.csv"):
    """Two elevated commands: capture for `runtime` s (run `target` during that window), then export CSV."""
    cap = f'"{PROCMON}" /AcceptEula /Quiet /Minimized /BackingFile "{backing}" /Runtime {runtime}'
    exp = f'"{PROCMON}" /OpenLog "{backing}" /SaveAs "{csv_out}"'
    return cap, exp


def _category(op: str) -> str:
    o = op.lower()
    if o.startswith("reg"): return "registry"
    if "tcp" in o or "udp" in o: return "network"
    if "process" in o or "thread" in o or o == "load image": return "process"
    if "file" in o or o.startswith("querydirectory"): return "file"
    return "other"


def summarize_csv(path, process=None):
    """Parse a Procmon CSV export into a recon summary (optionally filtered to one process name)."""
    cats = Counter(); writes = set(); regset = set(); images = set(); children = []
    total = 0
    with open(path, newline="", encoding="utf-8", errors="ignore") as f:
        for row in csv.DictReader(f):
            if process and process.lower() not in row.get("Process Name", "").lower():
                continue
            op = row.get("Operation", ""); p = row.get("Path", "")
            res = row.get("Result", ""); det = row.get("Detail", "")
            total += 1; cats[_category(op)] += 1
            ol = op.lower()
            if ("writefile" in ol or "setdispositioninformation" in ol) and res.upper().startswith("SUCCESS"):
                writes.add(p)
            if "regsetvalue" in ol: regset.add(p)
            if ol == "load image": images.add(p)
            if "process create" in ol: children.append(det or p)
    return {"total_events": total, "by_category": dict(cats),
            "files_written": sorted(writes)[:50], "registry_values_set": sorted(regset)[:50],
            "images_loaded": sorted(images)[:100], "child_processes": children[:20]}


def main(argv):
    if len(argv) >= 3 and argv[1] == "command":
        cap, exp = command(argv[2], int(argv[3]) if len(argv) > 3 else 20)
        print("# run elevated — capture (run your target during the window), then export:")
        print(cap); print(exp)
    elif len(argv) >= 3 and argv[1] == "parse":
        print(json.dumps(summarize_csv(argv[2], argv[3] if len(argv) > 3 else None), indent=2))
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main(sys.argv)
