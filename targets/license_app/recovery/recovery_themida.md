# Themida layer — recovery (license_app.themida.exe)

Target: `license_app.themida.exe` — **Themida x64 3.2.4 (2026, demo)** protecting `license_app_vm.exe`
(the clean check with `check_license`'s body wrapped in `VM_START/VM_END`). DIE: `Themida/Winlicense(3.XX)`.

## What the protection did

- **Entry Point Virtualization:** the first 18 bytes of the entry (`0x1490–0x14A2`) are virtualized.
- **check_license virtualized:** macro region `0x14FB–0x158E` (our `VM_START/VM_END`) runs in a SecureEngine VM.
- **Demo restriction:** *all* virtualization macros are forced to **Falcon Tiny** (the weakest VM) regardless
  of the EAGLE64 Black selection — true EAGLE64 needs a licensed Themida.
- Full-strength otherwise: packing (112 KB → 1.8 MB), anti-debug, Advanced API-Wrapping, string encryption,
  Detect File/Registry Monitors, Anti-File-patching, Anti-Sandbox.

## Break notes (x64dbg)

- **Anti-debug beaten** by ScyllaHide's `Themida x86/x64` profile — the demo nag appeared under the debugger
  with no "debugger found".
- **Hardware breakpoints are detected** (Themida reads the DR registers → "debugger found"). Enabling
  ScyllaHide **DRx Protection** hides them, but then it also blocks x64dbg from *installing* its own HW BPs.
- **Clean OEP capture resisted** (HW BP neutralized; memory-access BPs fire on SecureEngine's decrypt reads).
  Modern Themida resists public unpacking the same way VMProtect 3.11 resists NoVmp — that version lag IS the
  lesson. A full clean dump (with the wrapped IAT rebuilt) is the hard, licensed-tool / manual frontier.
- **Clean dump — DONE (code-complete).** Scylla targeting the exe (imagebase `0x140000000`, OEP `base+0x1490`):
  Dump + Fix Dump → `dumps/license_app.themida_dump_SCY.exe`. The dump holds the original code at the original
  RVAs — `main @0x2490`, `check_license @0x14E0` (prologue then `jmp` into the SecureEngine VM), the verdict
  branch `test eax,eax / jnz` at `0x24AE/0x24B0`, strings intact. **IDA Hex-Rays decompiles `main` cleanly** —
  the full licence-check control flow recovered from the protected binary.
  Gotcha that cost us several tries: at the `GetVolumeInformationA` break RIP is inside kernel32, so the
  integrated Scylla first dumped **kernel32** (imagebase `0x7FFE35320000`, our code absent). Fix: **Pick DLL →
  the exe** so the target base is `0x140000000`.
- **IAT: 8 valid / 28 wrapped** of 36 (Advanced API-Wrapping; `DIRECT IMPORTS = 0`) — Scylla can't resolve
  modern Themida wrappers directly.
- **Runnable reconstruction — DONE** (`reconstruct_themida.py`). Using our own `license_app_vm.exe` as the
  oracle (legitimate — our binary), rebuild a runnable, de-Themida'd PE from the dump: restore the original
  import table in place (resolves all 36 IAT entries incl. the 28 wrapped), overlay the original sections to
  de-virtualize the EPV entry + `check_license` VM body, set OEP `0x1490`, fixed base, make the IAT section
  writable, zero `.bss`, drop Themida's TLS/bound dirs. Result `dumps/license_app.themida_unpacked.exe` runs
  correctly: `75685AB2 → LICENSED (0)`, `00000000 → INVALID (1)`. One-byte verdict patch (`0x24B0 75→EB`) →
  `dumps/license_app.themida_cracked.exe`: **any key → LICENSED**.
  Honest frame: without the oracle you'd trace each of the 28 wrapper stubs to its real API and lift the two VM
  regions by hand (the dedicated-unwrapper / VM-lifter work). The oracle shortcut is valid only because we own
  the original — it demonstrates exactly what a full unwrap+lift would produce.
- **IAT unwrapper — DONE, oracle-free** (`reaforge/tools/themida_unwrap.py`). The real frontier, built as a
  reusable reaforge tool: map a full-memory process dump (Task Manager → Create dump file) into Unicorn, read
  the IAT, and **emulate each wrapper stub to its real API** — stopping on the TAIL-jmp (stack back to the
  wrapper's entry) and skipping Themida's intermediate **anti-analysis API calls** (the first cut landed 4
  kernel32 wrappers on `Sleep` until the tail-jmp fix). Result on this binary: **36/36 imports resolved,
  validated 36/36 against the oracle** — the oracle only checked the answer, never drove it. The IAT can now be
  rebuilt from a dump with **no reference binary**; only the two VM'd regions (EPV entry, `check_license` body)
  still need a VM-lifter.
  Run: `python -m reaforge.tools.themida_unwrap <dump.dmp> license_app.themida 8250 168`
- **VM-lifter — DONE, oracle-free** (`reaforge/tools/vm_lift.py`). The last frontier: de-virtualize the
  `check_license` VM body itself. It is `push rsi/rbx; sub rsp,0x58; mov rsi,rcx; jmp 0x1402bd04c` — a native
  prologue then a `jmp` into the SecureEngine VM (region `0x140021000`+0x2ee000, Falcon in the demo). The lifter
  maps the full-memory dump into Unicorn and **runs the whole VM concretely from the native entry** (16,621
  instrs), stubbing the two OS calls the body makes (`GetVolumeInformationA` → our serial, `strtoul` → parse the
  key). Themida's VM juggles the value through so many stack slots that **byte-level taint does not survive** it
  (exactly why it resists symbolic devirt — observed: the tainted parsed-key is clobbered within ~40 VM instrs),
  so the constant is captured **concretely**: feed a distinctive probe key and read the 32-bit value it is
  compared against. Result: **recovered `want = 0x39853C6F`**, self-validated oracle-free — wrong key `DEADBEEF`
  → verdict `0` (reject), recovered key `39853C6F` → verdict `1` (**accept**); independent oracle cross-check
  `expected_key(0x75685AB2) = 0x39853C6F` → **MATCH**. The virtualized licence constant comes straight out of the
  running SecureEngine VM, no reference binary.
  Run: `python -m reaforge.tools.vm_lift <dump.DMP> themida 14e0`
- **VM-lifter: full arithmetic FORM — DONE, oracle-free** (`vm_lift.py form` + `reaforge.core.peel.prove_recurrence`).
  Not just the constant for one machine — the whole keygen as a function of a **tainted machine-id**. `machine_id()`
  runs *before* `strtoul` and the `expected_key` recurrence stays largely in registers, so tainting `mid` at the
  `GetVolumeInformationA` stub (with the taint-recording SymEngine shadow) **survives the VM for ~1,625 instrs** —
  far enough to recover the symbolic `want(mid)` straight from the SecureEngine VM. `peel.prove_recurrence` then peels
  the rounds off `best`'s **own z3 subterms** (the VM's bit-sliced `Concat/Extract` representation defeats passing
  captured snaps as candidates — the same representation that scrambles structural peeling) and SMT-proves each round
  over all 2^32 mid. Recovered + **PROVEN**: `acc = 0x1505 ^ mid; for i in 0..7: acc = ((acc*33) ^ ((mid>>4i)&0xF)) + C_i`
  — seed `0x1505`, multiplier **33**, nibble shifts `[0,4,8,…,28]`, mask `0xF`, **8 rounds each proven over all 2^32
  inputs** (the per-round `K`/`C` are the proven equivalents of the VM's folded bit-sliced form). Sampled vs the keygen
  at 6 machine-ids: all **MATCH**. A monolithic z3 proof of the 8-chained-multiply equality is intractable (`unknown`
  at 570s) — the per-round transitive proof is what makes it provable. This is `expected_key` recovered **and proven**
  blind from the Themida VM, oracle-free.
  Run: `python -m reaforge.tools.vm_lift form <dump.DMP> themida 14e0`
- **VM-lifter: EPV entry — DONE, oracle-free** (`vm_lift.py entry`). The last virtualized region: the Entry-Point-
  Virtualization block (`0x1490`, `jmp 0x1402d2a08` into the VM). Unlike `check_license` this is **control flow**, not a
  computed value, so the lift recovers the block's *effect*: run the VM from `0x1490` with **sentinel registers** and a
  clean stack, and stop when control leaves the VM segment back into native code. Recovered (2,704 VM instrs):
  `rax = 0x140007080; mov dword [0x140007080], 0; jmp 0x1400010A0` (RSP delta 0 — no call/push). Oracle cross-check:
  the native entry is `mov rax,[0x14043870]` (= `0x140007080`) / `mov [rax],0` / `jmp 0x1400010A0` — **exit-target
  match, register + store match**. The exit edge and state delta are read straight from the VM; the oracle only confirms.
  Run: `python -m reaforge.tools.vm_lift entry <dump.DMP> themida 1490 [oracle.exe]`

**Devirt complete:** both virtualized regions (the `check_license` VM body *and* the EPV entry) are now lifted
oracle-free — the constant, the full keygen recurrence (proven over all 2^32 mid), and the entry block's effect.

## The bypass (no unpack, no devirt)

`main` is **native** — only `check_license`'s body is in the VM. IDA Hex-Rays / objdump of the clean build:

```
1400024a9  call  check_license
1400024ae  test  eax, eax
1400024b0  jnz   loc_1400024CA     ; taken → "LICENSED", fall-through → "INVALID LICENSE"
```

**Patch `0x1400024b0`: `75` → `EB`** (jnz → jmp) ⇒ any key prints `LICENSED`. If Themida's Memory-Guard reverts
the byte edit, force the register instead (make `eax = 1` right after `call check_license`) so nothing on the
code page is modified.

## Ground truth (Hex-Rays of the clean build — confirms our keygen)

```c
check_license: acc = serial ^ 0x1505;
               do { acc = (33*acc ^ ((serial >> (4*i)) & 0xF)) + 7*i; } for i in 0..7;
               return strtoul(key,16) == acc;   // == expected_key() in config.py
```

## Takeaway

Commercial VM protectors move the cost to **understanding** the code (unpack + devirt), not to **defeating the
check** — the native verdict branch falls to a one-byte patch regardless of VM strength. The demo additionally
caps the VM to Falcon Tiny, so even the devirt here would be easy; a licensed EAGLE64 build is the real frontier.
