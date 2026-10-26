# GameSecLab

Hands-on lab for learning game security and reverse engineering: how cheats work on a running
process, how anti-cheat detects them, and how commercial protectors (VMProtect / Themida / OLLVM)
obfuscate code — so you can both understand the attacks and build the defenses into your own games.

**You do the hands-on GUI work; the tooling here scripts, analyzes, and automates the rest.**

## Lab rules

1. Single-player / offline only. Never attach tools to a game connected to a public server.
2. Every target analyzed here is one you own and have authorized (enforced by
   `reaforge/authorized_targets.json`).
3. Every attack learned gets a matching defense noted in `knowledge/FIXLIST.md`.

## The three layers

Everything is organized so that **generic** capability and **category** knowledge are reusable, and
only the **per-title** specifics are pinned to one game:

```text
reaforge/        GENERIC — the framework (automated + AI), arch/target-agnostic
  core/            the VMProtect devirtualization engine
    engine.py        taint-symbolic execution (x86-32 AND x86-64 — arch is a parameter)
    loader.py        VMProtect process-world env (EXE/DLL, 32/64) on top of vmp-lazy-unpack
    peel.py          round peeling + anti-unification + z3 equivalence proofs
    protectors/      the protector seam: base + VMProtect / Themida / Denuvo (+ registry)
    __main__.py      `python -m reaforge.core <title>` — authorization-gated CLI
  orchestrator.py  authorize -> static recon -> facts -> LLM plan
  tool_registry.py detect every RE tool/lib installed on this machine
  llm_backend.py   pluggable AI backend (Anthropic API | Ollama | manual bridge | Claude Code)
  ida/ pintools/ tools/   generic IDA drivers, Intel Pin probes, external-tool wrappers (GAMBA, Frida)
  tests/           quick smoke tests across the arch x format matrix (x86/x64 x EXE/DLL)

categories/      CATEGORY — reusable per game CATEGORY, never a single title
  native_license/  VMProtect-protected native license checks (x64 MS ABI)    -> campaign.py
  hashlink/        Haxe/Heaps/HashLink games (libhl hl_hash_utf8 ground truth) -> campaign.py
  unreal/          Unreal Engine recon / anti-cheat review notes
  voxel_rust/      Rust/voxel games: memory-scan + pointer methodology

targets/         PER-TITLE — one workspace per game (binaries + dumps gitignored; src/recovery tracked)
  license_app/     our own x64 VMProtect 3.11 crackme   (native_license category)
  dead_cells/      our own VMProtect'd libhl.dll (x86)  (hashlink category)
  veloren/         Rust voxel game pointer-scan notes
  <title>/         config.py (the only place specifics live) + src/ recovery/ dumps/ README

knowledge/       REFERENCE — generic, title-independent
  papers/          academic PDFs (DBI, VM obfuscation, deobfuscation)
  vmprotect_3.11/  VMProtect 3.11 architecture + MBA deobfuscation analyses + pipeline
  method/          technique-by-technique RE method (static recon, memory editing, Pin lab, ...)
  GLOSSARY.md  FIXLIST.md  binary_protection.txt

vmlab/           local Tigress/crackme lab ("child's play" — keycheck*, single and nested VM)
NOTES.md  ENVIRONMENTS.md   running lab logs
```

## Run the devirtualizer

```bash
python -m reaforge.core license_app                 # x64 EXE: validate, recover, peel, prove
python -m reaforge.core license_app AABBCCDD bypass  # defeat the check with a WRONG key (no keygen)
python -m reaforge.core dead_cells validate,recover,peel   # x86 DLL
python -m reaforge.core --help                      # list titles + usage
```

Modes: `validate` (VM == reference), `recover` (blind symbolic key), `peel` (round peeling + proofs),
`prove` (all-inputs SMT), `bypass` (trace-diff the verdict branch and flip it — defeats the check
without recovering the algorithm; prints the live-patch RVA for x64dbg).

The orchestrator is the one-command front door (gate → recon → classify protector → campaign):

```bash
python -m reaforge.orchestrator authorize "<path>" "why you own / may analyze this"
python -m reaforge.orchestrator targets                      # list per-title workspaces
python -m reaforge.orchestrator new-target <name> <category> # scaffold targets/<name>/ (native_license | hashlink)
python -m reaforge.orchestrator run <title> [arg] [modes]    # recon + run the campaign
```

## Quick checks

```bash
python -m ruff check .                               # lint
python -m reaforge.tests.test_smoke                  # fast tests (imports, keygens, arch matrix)
set RUN_CAMPAIGNS=1 && python -m reaforge.tests.test_smoke   # + run the real x64-EXE / x86-DLL campaigns
```

## Adding a new game

```bash
python -m reaforge.orchestrator new-target <title> <category>   # scaffolds config.py + dumps/ + README
```

Then fill the `config.py` TODOs (binary path, snapshot, the few title specifics), drop the packed
binary in `dumps/`, authorize it, and `python -m reaforge.core <title>`. The category's
`campaign.run(cfg)` does the rest — the category and generic layers never name a specific title.

> The devirt engine is **VMProtect-specific**. For a Themida/Oreans target the recon step classifies
> the protector and routes you to the unpack + protector-agnostic bypass plan instead (see
> `targets/license_app/themida_plan.md`).
