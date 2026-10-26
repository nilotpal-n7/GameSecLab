# GameSecLab

Hands-on lab for learning game security and reverse engineering: how cheats work on a running
process, how anti-cheat detects them, and how commercial protectors (VMProtect / Themida / OLLVM)
obfuscate code — so you can both understand the attacks and build the defenses into your own games.

**You do the hands-on GUI work; the tooling here scripts, analyzes, and automates the rest.**

## Lab rules

1. Single-player / offline only. Never attach tools to a game connected to a public server.
2. Legit copies only — your own builds and your own protected binaries. No DRM / anti-cheat bypass of
   third-party products. Every target analyzed here is one you own and have authorized (enforced by
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
  method/          phase-by-phase RE method (static recon, memory editing, Pin lab, ...)
  GLOSSARY.md  FIXLIST.md  binary_protection_instrumentation_reference.txt

vmlab/           local Tigress/crackme lab ("child's play" — keycheck*, single and nested VM)
NOTES.md  RECON.md  ENVIRONMENTS.md   running lab logs
```

## Run the devirtualizer

```bash
python -m reaforge.core license_app                 # x64 EXE: validate, recover, peel, prove
python -m reaforge.core dead_cells validate,recover,peel   # x86 DLL
python -m reaforge.core --help                      # list titles + usage
```

A title's packed binary must be authorized first:

```bash
python -m reaforge.orchestrator authorize "<path>" "why you own / may analyze this"
```

## Quick checks

```bash
python -m ruff check .                               # lint
python -m reaforge.tests.test_smoke                  # fast tests (imports, keygens, arch matrix)
set RUN_CAMPAIGNS=1 && python -m reaforge.tests.test_smoke   # + run the real x64-EXE / x86-DLL campaigns
```

## Adding a new game

1. Pick (or add) the **category** under `categories/` that matches the engine/protection pattern.
2. Create `targets/<title>/config.py` with the binary path, snapshot path, and the few title
   specifics (the category's `campaign.run(cfg)` does the rest).
3. Authorize the binary, then `python -m reaforge.core <title>`.

The category and generic layers never name a specific title — new titles are added by configuration.
