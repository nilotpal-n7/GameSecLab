# reaforge/core/protectors — the protector seam

Nothing in the devirt engine is hardcoded to VMProtect. A `Protector` subclass owns everything
specific to one protector *family*; the engine (`engine.py`) and peeler (`peel.py`) stay generic, and
the campaigns reach the unpacked state through the registry — never by importing a loader directly.

```
base.py       Protector ABC + cheap classify(facts) (string match, no heavy import)
vmprotect.py  VMProtect — emulation-unpack via VmpLoader; version-aware (3.x); available() checks vmp-lazy-unpack
themida.py    Themida/WinLicense (Oreans) — not automated: unpack() routes to the manual plan + tools to get
denuvo.py     Denuvo — recognized and refused (online anti-tamper, out of scope on third-party titles)
__init__.py   for_name(name) / for_facts(facts) (lazy-import the concrete class) + classify
```

## Key design choice — the VM is emulated, not hardcoded

We never wrote VMProtect's (or any protector's) VM opcode handlers. The real VM runs on Unicorn and the
arch-agnostic `SymEngine` shadows it, so a new VM **sub-version** needs no code change. `vm_model()`
returns `None` for an emulated protector; override it only if a subclass genuinely ships a handler model.
The one protector-specific thing is the **unpack** (reaching OEP), which each subclass's `unpack()` owns —
"use a tool if available, else our own unpacker, else say what to get" (`available()` / `required_tools()`).

## Contract for `unpack()`'s returned environment

Campaigns use: `uc`, `arch`, `mapped_start`/`mapped_end`, `resolve_export(name)`, `resolve_rva(rva)`,
`add_handler(symbol, fn, argc)`, `restore_snapshot(path)`, `close()`.

## Add a protector

1. Subclass `Protector` in a new module; set `name` + `aliases`, implement `available()`,
   `required_tools()`, `classify_version()`, and `unpack()` (or leave it raising if manual-only).
2. Add its aliases to `base.ALIASES` and a branch in `__init__.for_name`.
3. A title selects it with `Config(protector="<name>")` (default `"vmprotect"`).
