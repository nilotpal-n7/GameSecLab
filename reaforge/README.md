# REAForge — our own AI-driven RE orchestrator

A small, growable framework that **detects every RE tool installed on this machine**, runs them in a
pipeline, and uses an **LLM backend** to plan/interpret — so next time a similar target shows up, it's a few
commands, not from scratch. Built as we learn, so by the end you understand every step *and* have it automated.

## Scope / ethics guard (built in)

REAForge operates **only on targets you own or are explicitly authorized to analyze** — your own code, your
own protected builds, CTF/crackme challenges, games you own and are allowed to mod. It refuses to run until a
target is recorded in `authorized_targets.json` with a reason. It is an analysis/learning orchestrator, not a
DRM/anti-cheat circumvention tool for third-party products.

## Architecture

```txt
reaforge/                    # GENERIC framework (this package)
  core/              # the VMProtect devirtualization engine (arch/target-agnostic)
    engine.py          # taint-symbolic execution, x86-32 AND x86-64 (arch is a parameter)
    loader.py          # VMProtect process-world env (EXE/DLL, 32/64) on vmp-lazy-unpack
    peel.py            # round peeling + anti-unification + z3 equivalence proofs
    __main__.py        # `python -m reaforge.core <title>` — authorization-gated CLI
  tool_registry.py   # detects installed tools (Ghidra, x64dbg, DIE, IDA, Tigress, Frida, py libs, gcc)
  llm_backend.py     # pluggable AI: Anthropic API | local Ollama | manual bridge | Claude Code driver
  orchestrator.py    # pipeline: authorize -> static recon -> collect facts -> LLM plan -> report
  authorized_targets.json   # allowlist (path + reason + sha256); the CLI refuses anything not listed
  ida/  pintools/  tools/    # generic IDA drivers, Intel Pin probes, external-tool wrappers (GAMBA, Frida)
  tests/             # quick smoke tests across the arch x format matrix (x86/x64 x EXE/DLL)
```

The generic engine is driven by **category** engines (`categories/<cat>/campaign.py`, reusable per
game category) and **per-title** configs (`targets/<title>/config.py`, the only place specifics live).
See the repo-root `README.md` for the full three-layer map.

## The AI backend — honest options

A standalone program **cannot call this Claude Code chat session** as an API; this session isn't an endpoint
local code can POST to. So REAForge's "AI" is a pluggable backend:

- **Anthropic API** (`ANTHROPIC_API_KEY`) — best quality; needs your own key (none set yet).
- **Local Ollama** (`http://localhost:11434`) — fully offline; needs Ollama installed (not installed yet).
- **Manual bridge** — REAForge writes the prompt to a file; you paste it here (to me), paste the answer back.
  Works today with zero setup, and is how we'll "embed" this chat while we build.
- **Claude Code driver** — when REAForge is run *from this session*, I (Claude Code) act as the planner,
  reading its JSON facts and deciding next steps. That's the live AI loop until you wire a key/Ollama.

## Usage (as it grows)

```bash
python -m reaforge.tool_registry            # capability report: what's installed
python -m reaforge.orchestrator recon <path>  # static recon on an AUTHORIZED target -> facts JSON
```
