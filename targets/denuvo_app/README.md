# Target: denuvo_app (PLACEHOLDER — no target yet)

Placeholder workspace for a future **Denuvo Anti-Tamper** study. We have **no access** to a Denuvo
target and won't break it on a shipping title — this dir just reserves the layout so the work can
start cleanly if we ever build our own Denuvo-free/Denuvo-protected analog.

**Status:** empty on purpose. No `config.py` yet, so `orchestrator targets` does not list it as runnable.

## Why it's only a placeholder

Denuvo is **online / anti-tamper DRM**, not a self-contained VM you statically devirtualize like
VMProtect or Themida. It mutates per-build, ties activation to hardware + a license server, and
peppers the binary with tamper checks. The reaforge protector class `reaforge/core/protectors/denuvo.py`
already *recognizes* it and refuses cleanly, pointing here.

## Scope rule (unchanged)

Only ever analyze a target you **own / are authorized for** — breaking Denuvo on a third-party game is
DMCA §1201 territory and out of scope. The only in-scope path is **your own** protected analog.

## When we do have a target (future)

1. Build/obtain an authorized binary; drop it in `dumps/`, then
   `python -m reaforge.orchestrator authorize "<path>" "why you own it"`.
2. Add a `recovery/` write-up (dynamic analysis only — trace activation, tamper checks; no static devirt).
3. If a category fits, scaffold a `config.py` via `orchestrator new-target`; Denuvo is dynamic-only, so
   this may stay a notes-and-traces workspace rather than an automated campaign.
