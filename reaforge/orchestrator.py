"""REAForge orchestrator — authorize -> static recon -> facts -> (LLM plan) -> campaign.

The top-level entry for the lab: it gates on ownership, does static recon, and ties a title's
config to its category campaign so analysing a target is one command.

Usage:
  python -m reaforge.orchestrator authorize <path> "reason I own/may analyze this"
  python -m reaforge.orchestrator recon <path>
  python -m reaforge.orchestrator targets                       # list per-title workspaces
  python -m reaforge.orchestrator new-target <name> <category>  # scaffold targets/<name>/
  python -m reaforge.orchestrator run <title> [arg] [modes]     # recon + run the title's campaign
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
ALLOW = HERE / "authorized_targets.json"
TARGETS = ROOT / "targets"
CATEGORIES = ("native_license", "hashlink")


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


def recon(path: str, plan: bool = True):
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

    if not plan:
        return facts
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
    return facts


def protector_of(facts) -> str:
    """Classify the packer/protector from recon facts (delegates to the Protector registry)."""
    from reaforge.core.protectors import classify
    return classify(facts)


def list_titles():
    return sorted(d.name for d in TARGETS.iterdir() if (d / "config.py").exists()) if TARGETS.exists() else []


# ── per-category config scaffold (placeholders marked TODO) ───────────────────────────────────
_STUB = {
    "native_license": '''#!/usr/bin/env python3
r"""Title config: __NAME__ — native_license category. Fill in the TODOs, then `python -m reaforge.core __NAME__`."""
from __future__ import annotations
from pathlib import Path

from categories.native_license import campaign

HERE = Path(__file__).resolve().parent
DUMPS = HERE / "dumps"
M = (1 << 32) - 1


def expected_key(serial):
    """TODO: the reference keygen (clean-build algorithm) — used ONLY to validate/cross-check."""
    raise NotImplementedError("fill in __NAME__'s reference keygen")


CONFIG = campaign.Config(
    name="__NAME__ check",
    packed=str(DUMPS / "TODO_packed.exe"),       # TODO: your packed binary (then `orchestrator authorize` it)
    snap=str(DUMPS / "__NAME___postoep.snap"),
    check_rva=0x1000,                            # TODO: RVA of the virtualized check function
    expected=expected_key,
)


def run(packed=None, arg=None, modes=("validate", "recover", "peel")):
    serial = int(arg, 16) if arg else CONFIG.default_serial
    cfg = CONFIG if serial == CONFIG.default_serial else campaign.Config(**{**CONFIG.__dict__, "default_serial": serial})
    campaign.run(cfg, packed, modes)
''',
    "hashlink": '''#!/usr/bin/env python3
r"""Title config: __NAME__ — hashlink category. Fill in the paths, then `python -m reaforge.core __NAME__`."""
from __future__ import annotations
from pathlib import Path

from categories.hashlink import campaign

HERE = Path(__file__).resolve().parent
DUMPS = HERE / "dumps"

CONFIG = campaign.Config(
    name="__NAME__ libhl",
    packed=str(DUMPS / "TODO_libhl.vmp.dll"),    # TODO: your packed libhl copy (then `orchestrator authorize` it)
    snap=str(DUMPS / "__NAME___postunpack.snap"),
    export="hl_hash_utf8",
    N=4,
)


def run(packed=None, arg=None, modes=("validate", "recover", "peel", "prove")):
    cfg = CONFIG if not arg else campaign.Config(**{**CONFIG.__dict__, "N": int(arg)})
    campaign.run(cfg, packed, modes)
''',
}


def new_target(name: str, category: str):
    if category not in _STUB:
        sys.exit(f"unknown category {category!r}. known: {', '.join(_STUB)}")
    d = TARGETS / name
    if d.exists():
        sys.exit(f"targets/{name}/ already exists")
    (d / "dumps").mkdir(parents=True)
    (d / "__init__.py").write_text(f'"""{name} — per-title workspace ({category} category)."""\n')
    (d / "config.py").write_text(_STUB[category].replace("__NAME__", name))
    (d / "dumps" / ".gitkeep").write_text("")
    (d / "README.md").write_text(
        f"# Target: {name} ({category} category)\n\n"
        f"Fill in `config.py` (TODOs), drop the packed binary in `dumps/`, authorize it, then:\n\n"
        f"```bash\npython -m reaforge.orchestrator authorize \"<path to packed>\" \"why you own it\"\n"
        f"python -m reaforge.core {name}\n```\n")
    print(f"scaffolded targets/{name}/ ({category}) — edit config.py, add + authorize the binary, then run it.")


def run_title(title: str, rest):
    if title not in list_titles():
        sys.exit(f"unknown title {title!r}. known: {', '.join(list_titles())}")
    for pth in (str(ROOT), r"C:\Tools\_downloads\research\vmp-lazy-unpack"):
        if pth not in sys.path:
            sys.path.insert(0, pth)
    import importlib
    cfg_mod = importlib.import_module(f"targets.{title}.config")
    packed = cfg_mod.CONFIG.packed
    _check_authorized(Path(packed).resolve())
    if Path(packed).exists():
        from reaforge.core import protectors
        print(f"== recon: {title} ==")
        facts = recon(packed, plan=False)
        prot = protectors.for_facts(facts)
        print(f"  protector: {prot.name + ' ' + prot.classify_version(facts) if prot else 'unknown'}")
        if prot is not None and not prot.available():
            sys.exit(f"  {prot.unavailable_message()}\n"
                     f"  See targets/license_app/themida_plan.md for the unpack + protector-agnostic bypass route.")
    else:
        print(f"  (packed binary not present yet: {packed})")
    from reaforge.core.__main__ import main as core_main
    core_main(["reaforge.core", title, *rest])


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    cmd = sys.argv[1]
    if cmd == "authorize" and len(sys.argv) >= 4:
        authorize(sys.argv[2], sys.argv[3])
    elif cmd == "recon" and len(sys.argv) >= 3:
        recon(sys.argv[2])
    elif cmd == "targets":
        print("titles:", ", ".join(list_titles()) or "(none)")
    elif cmd == "new-target" and len(sys.argv) >= 4:
        new_target(sys.argv[2], sys.argv[3])
    elif cmd == "run" and len(sys.argv) >= 3:
        run_title(sys.argv[2], sys.argv[3:])
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
