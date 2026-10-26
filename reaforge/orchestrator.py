"""REAForge orchestrator (skeleton) — authorize -> static recon -> facts -> (LLM plan).

Grows into the full pipeline. Today: an authorization gate + static recon that chains the
installed tools (DIE, pefile, strings) into one facts JSON, then asks the LLM backend for next steps.

Usage:
  python -m reaforge.orchestrator authorize <path> "reason I own/may analyze this"
  python -m reaforge.orchestrator recon <path>
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ALLOW = HERE / "authorized_targets.json"


def _load_allow():
    return json.loads(ALLOW.read_text()) if ALLOW.exists() else {}


def _sha256(p: Path):
    h = hashlib.sha256()
    h.update(p.read_bytes())
    return h.hexdigest()


def authorize(path: str, reason: str):
    p = Path(path).resolve()
    if not p.exists():
        sys.exit(f"no such file: {p}")
    data = _load_allow()
    data[str(p)] = {"reason": reason, "sha256": _sha256(p)}
    ALLOW.write_text(json.dumps(data, indent=2))
    print(f"authorized: {p}\n  reason: {reason}")


def _check_authorized(p: Path):
    data = _load_allow()
    if str(p) not in data:
        sys.exit(f"REFUSED: {p} is not in authorized_targets.json.\n"
                 f"Only analyze targets you own/are authorized for. Add it with:\n"
                 f'  python -m reaforge.orchestrator authorize "{p}" "why you may analyze this"')


def recon(path: str):
    p = Path(path).resolve()
    if not p.exists():
        sys.exit(f"no such file: {p}")
    _check_authorized(p)
    facts = {"target": str(p), "sha256": _sha256(p), "size": p.stat().st_size, "tools": {}}

    # DIE (packer/compiler/entropy)
    die = r"C:\Tools\DIE\diec.exe"
    if Path(die).exists():
        try:
            facts["tools"]["die"] = subprocess.run([die, "-d", "-u", str(p)],
                capture_output=True, text=True, timeout=120).stdout.strip()
            facts["tools"]["die_entropy"] = subprocess.run([die, "-e", str(p)],
                capture_output=True, text=True, timeout=120).stdout.strip()
        except Exception as e:
            facts["tools"]["die"] = f"error: {e}"

    # pefile (PE structure) if it's a PE
    try:
        import pefile
        pe = pefile.PE(str(p), fast_load=True)
        facts["tools"]["pe"] = {
            "machine": hex(pe.FILE_HEADER.Machine),
            "sections": [s.Name.decode(errors="ignore").rstrip("\x00") for s in pe.sections],
            "dll_characteristics": hex(pe.OPTIONAL_HEADER.DllCharacteristics),
        }
    except Exception as e:
        facts["tools"]["pe"] = f"not a PE / error: {e}"

    out = HERE / "facts.json"
    out.write_text(json.dumps(facts, indent=2))
    print(json.dumps(facts, indent=2))
    print(f"\nwrote {out}")

    # Ask the LLM backend what to do next
    try:
        from llm_backend import get_backend
    except ImportError:
        from reaforge.llm_backend import get_backend
    b = get_backend()
    prompt = ("Given these static-recon facts about a binary I am authorized to analyze, "
              "list the 3 best next reverse-engineering steps and which installed tool to use for each.\n\n"
              + json.dumps(facts, indent=2))
    print(f"\n[LLM backend: {b.name}] planning next steps...\n")
    print(b.complete(prompt))


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    cmd = sys.argv[1]
    if cmd == "authorize" and len(sys.argv) >= 4:
        authorize(sys.argv[2], sys.argv[3])
    elif cmd == "recon" and len(sys.argv) >= 3:
        recon(sys.argv[2])
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
