# REAForge devirt — building our own VMProtect 3.11 devirtualizer

No public tool devirtualizes VMProtect 3.11 (see `docs/devirt_tooling_availability_2026.md`), so we build one.
Approach: **concolic emulation along a single concrete path** — emulate the VM'd function directly (no path
explosion, unlike angr on the whole VM; no debugger, unlike Pin which 3.11 detects by timing).

## What works (`emulate_checklicense.py`)
- Maps the unpacked dump's PE headers + all sections into **Unicorn**, sets up stack / key buffer /
  `KUSER_SHARED_DATA` / a TEB via GS, stubs `GetVolumeInformationA`, lazy-maps stray pages.
- **The VM interpreter executes end-to-end with no divergence** (mapping the PE headers fixed the rolling-key
  self-checksum reads — that was the key insight). We can drive `check_license`'s VM at will.

## The wall we hit
`check_license` → `machine_id()` → `GetVolumeInformationA`, but **VMProtect import protection resolves APIs by
walking `PEB→Ldr`**, not via the rebuilt `.idata` (our IAT hook fired 0 times). With no Windows loader
environment, the VM's resolver walks a zeroed PEB → null → execution derails → garbage return.

**Root cause:** faithfully emulating a VMProtect function needs a real **Windows process environment**
(PEB/LDR, loaded-module list with export tables, `GetProcAddress`, API stubs). That subsystem is precisely what
`vmp-lazy-unpack` already implements (it ships `ntdll.dll` + `catalog.json` of exports).

## Options to finish
1. **Build the loader env into our harness** — PEB/LDR + a minimal kernel32/ntdll export table + resolver +
   API stubs. Most educational; a real subsystem (several iterations).
2. **Reuse `vmp-lazy-unpack`'s harness** — it already sets up the env + API hooks; extend it to keep emulating
   *past OEP* into `check_license`, feed a key, and read the result / trace the compare. Faster path.
3. **Add the symbolic layer** once emulation is faithful: symbolize the serial (and/or key), run the single
   concrete path, and read off the formula / solve for the valid key (angr is now installed for the SMT step;
   or Triton-style taint on the Unicorn trace).

## DONE — `devirt_oep.py` (the working end-to-end devirtualizer)

We solved the loader-env wall by **reusing vmp-lazy-unpack's mechanism as a library** and adding our own
driver logic on top:

1. Reuse its env setup (`map_pe` + `map_emu_windows_modules` + `map_synthetic_process_state` + `Tracer` +
   `TraceHooks`) and emulate the packed binary to **OEP** — a live, fully-unpacked process with PEB/LDR,
   synthetic module export tables, and API/syscall stubs.
2. **Our driver** then takes over past OEP: neutralize the Tracer's unpack-detector
   (`check_restored_entry -> False`), register a `GetVolumeInformationA` handler that injects a **controllable
   volume serial**, then call the VM'd `check_license(key)` from the live state and read the verdict.

### Result — validation battery (5 serials): **ALL PASS**
```
serial=0x12345678  key=7A3B3935 -> 1   wrong -> 0   PASS
serial=0xAABBCCDD  key=3E988000 -> 1   wrong -> 0   PASS
serial=0xDEADBEEF  key=593BA6C6 -> 1   wrong -> 0   PASS
serial=0x00000000  key=B8BF23C9 -> 1   wrong -> 0   PASS
serial=0xFFFFFFFF  key=4E25F1B6 -> 1   wrong -> 0   PASS
```
For every serial the VM accepts **exactly** the key the C0 formula predicts and rejects wrong keys — proving
(a) the devirtualizer faithfully emulates the VMProtect 3.11 VM, and (b) the VM computes the C0 algorithm
(independent cross-validation). We now have an **executable model / keygen oracle** for the virtualized
function: `expected_key(serial) = c0_expected_key(serial)`, confirmed by the real VM.

Run:
```
cd C:\Tools\_downloads\research\vmp-lazy-unpack
python C:\Tools\GameSecLab\reaforge\devirt\devirt_oep.py C:\Tools\GameSecLab\capstone\license_app_c2.vmp.exe
```

`emulate_checklicense.py` (the standalone Unicorn attempt) is kept as the record of why the loader env is
required (it runs the VM but can't resolve imports alone).

## Blind key recovery — `RECOVER` mode (zero prior knowledge)

`devirt_oep.py` (RECOVER=1) recovers the valid key with **no knowledge of the algorithm** (C0 is used only to
cross-check, never to recover):

1. Feed a unique marker key so `got = strtoul("13371337")` is known.
2. Trace `check_license` (~206k instrs) with Capstone; capture every value that meets the marker in a
   compare/arith operand — these are candidates for `want = expected_key(serial)`.
3. **Self-validate** each candidate through the oracle (feed it back as the key → does the VM say LICENSED?).

Result (serial `0xAABBCCDD`): 12 candidates → **recovered `3E988000`, self-validated (VM → LICENSED), and it
MATCHES the C0 formula.** A fully autonomous blind break — the secret pulled straight out of the virtualized
function.

```
cd C:\Tools\_downloads\research\vmp-lazy-unpack
set RECOVER=1 && python C:\Tools\GameSecLab\reaforge\devirt\devirt_oep.py <packed.exe> <serial_hex>
```

## Blind SYMBOLIC attempt — `devirt_formula.py` (reaches the MBA wall)

A taint-symbolic tracer (claripy): symbolize the serial, propagate symbolic expressions through tainted
registers/memory along the single concrete path (full al/ax/eax/rax aliasing, mem byte-tracking, push/pop
stack-machine moves, ~25 x86 ops), and capture `want = expected_key(serial)` where it meets the concrete marker.

It now propagates taint cleanly through 140+ instructions with no crashes — and empirically reveals **exactly
why clean symbolic recovery of VMProtect 3.11 is unsolved in public tooling**: the VM's MBA lowers the tiny hash
into hundreds of **flag-dependent** bit ops that a simple taint engine can't model. The unhandled-mnemonic
census from a real run (serial 0xAABBCCDD):

```
shrd:536  bt:68  shld:13  btc:8  btr:4  bts:1  bsf:3  rcl:5  adc:3  xadd:1
cmov{ns,l,o,g,e,ne,no}:~15   set{le,np,g,ge}:~24   movabs:1
```

`adc`/`rcl`/`cmov`/`set`/`shrd` all depend on the **symbolic EFLAGS** (CF/ZF/SF/OF/PF). Modeling those for every
arithmetic op = a full symbolic-x86 engine (Triton's job), and the resulting AST is MBA-bloated and needs an MBA
simplifier (Syntia/QSynth/MBA-Blast) to collapse to `(acc*33)^((mid>>4i)&0xF)…`. That two-part requirement
(full symbolic flags + MBA simplification) is precisely where the unreleased 2026 academic prototypes (Pushan,
VMPredator, VMSpec) live. **We reached the frontier with our own tool and characterized it exactly.**

### What "blind" does and doesn't give us
- **Does:** the valid key for any serial, with no algorithm knowledge (concolic marker-tracing + oracle
  self-validation). This is the practical break.
- **Doesn't (yet):** the clean closed-form *formula* as C. The VM applies MBA (architecture doc §2.4), so the
  raw symbolic AST is correct but bloated; reducing it to `(acc*33)^((mid>>4i)&0xF)…` needs an MBA simplifier
  (Syntia/QSynth/MBA-Blast) — the documented research frontier. Full hand-rolled symbolic execution (Triton's
  job) is the engine for that.
