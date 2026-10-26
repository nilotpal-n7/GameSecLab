# C2 break log — fighting VMProtect 3.11's anti-debug/anti-DBI

Chronological record of the break attempts on `license_app_c2.vmp.exe` (VMProtect Ultimate 3.11.0,
virtualize + pack + memory-protection + User/Kernel debugger detection). Evidence in `screenshots/` and
`reaforge/pintools/`.

## Attempt 1 — x64dbg + ScyllaHide (ring-3 debugger)

- Default ScyllaHide "VMProtect" profile → **"A debugger has been found"** (`screenshots/c2_02…`).
- Maxed the profile to 36+ hooks → **still detected** (`screenshots/c2_03…`).
- x64dbg exception config (pass `EXCEPTION_SINGLE_STEP 0x80000004` to debuggee) → **still detected**.
- **Root cause** (from `docs/…DBI_Tools.pdf`): VMProtect anti-debug = **single-step/trap-flag exception** that
  must fire into VMProtect's own handler. ScyllaHide hides flags/APIs but has **no single-step handler**, so it
  can't cover this. Explained in `docs/pdf_analysis.md`.

## Attempt 2 — Intel Pin (DBI instead of a debugger)

Rationale: Pin JIT-recompiles the target, it is not a debugger, so debugger-API checks don't apply. But the
PDF (Table 1) says VMProtect also has **anti-DBI** = the same single-step technique, which trips Pin too.

**Toolchain built** (reusable): `reaforge/pintools/build.bat` compiles pintools via Pin's own make +
Hikari clang-cl + msys make (the MSBuild/ClangCL route fails in VS2026). Validated on the clean app
(2.7M instrs, 17 cpuid traced).

**Result on the protected binary** (`reaforge/pintools/vmp_probe.cpp` → `vmp_probe.log`):

| observation | value |
| --- | --- |
| instructions executed before death | **~792,000,000** (vs 2.7M clean) — the whole VM runs |
| exceptions delivered to the app (`CTXCHG`) | **0** — the single-step exception never fires under Pin |
| demo nag / output | none |
| exit | code **4**, no clean exit, our Fini never ran |
| syscalls | normal pattern (0x50 ×many early = the packer's page ops), then abrupt death |

**Interpretation:** confirms the PDF's theory on our 3.11 binary — under Pin the trap-flag single-step
exception is **not raised** (Pin's JIT doesn't honor TF), so VMProtect's handler never runs and it detects the
instrumentation. The kill happens *late* (after the VM executes), via a path that is not a hookable export and
not a visible exception.

## Where this leaves us (honest)

- VMProtect 3.11 defeats **both** a ring-3 debugger (x64dbg+ScyllaHide) **and** plain Pin. This is a real,
  documented result — modern VMProtect anti-analysis is strong, and public tooling lags it by years.
- **Beating it = open research.** The academic bypass (re-raise the single-step exception from the DBI tool)
  targets VMProtect **3.0.9**; on 3.11 the detection fires after ~792M instructions with no exception surfaced,
  so a correct bypass must (a) synthesize the single-step exception delivery Pin omits, and likely (b) handle
  additional vectors. Uncertain effort.

## Options from here

1. **Attempt the single-step re-raise pintool** (the paper's method) — honor the DBI path; research gamble on 3.11.
2. **Bank this + the Pin toolchain**, rebuild C2 with **Debugger detection OFF** (keep virtualize + pack +
   memory-protection), and learn the rest of the break now: reach OEP, Scylla-dump, find the native `test/je`,
   flip ZF at runtime vs the integrity CRC.
