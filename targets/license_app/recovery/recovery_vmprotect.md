# VMProtect layer — virtualization (protect side done; break path is a decision)

**Layer added:** the whole `check_license` algorithm is turned into **VMProtect VM bytecode** (not native
instructions), plus the binary is packed. This is the real step up from OLLVM: OLLVM only changed how the native
instructions *looked*; VMProtect removes the native arithmetic entirely and runs it on an embedded interpreter.

## Protect side — DONE (scripted, no GUI)

- **Protector:** VMProtect **Ultimate v3.11.0 (build 2835)**, Demo, console (`VMProtect_Con.exe`).
- **Target:** `license_app_hardened.c` — identical algorithm to clean/OLLVM, but `machine_id()`/`expected_key()` are
  `always_inline` into `check_license`, whose body is wrapped in
  `VMProtectBeginVirtualization("check_license") … VMProtectEnd()` so the arithmetic lands inside the VM.
- **Build (marker build):**

  ```bash
  clang license_app_hardened.c -O2 -I"<VMP>\Include\C" "<VMP>\Lib\Windows\VMProtectSDK64.lib" -o license_app_hardened.exe
  ```

- **Protect — done by hand in the VMProtect GUI** (the learning step; not the CLI). Opened
  `license_app_hardened.exe`, the SDK marker auto-added `check_license` → set **Compilation Type = Virtualization**,
  and enabled **Pack**, **Memory Protection** (integrity CRC), **Import Protection**, and
  **Detection: Debugger = User+Kernel**. Output: `license_app.vmp.exe`.

### Verification

| check | result |
| --- | --- |
| marker found & virtualized | `Loading [V] 140001010 … "check_license"` |
| semantics preserved through the VM | `.\license_app.vmp.exe 75685AB2` → `LICENSED`; junk → `INVALID LICENSE` |
| SDK DLL dependency after protection | **none** |
| size | 143,360 → **1,507,328 bytes (~1050%)** (heavier than CLI default — extra layers on) |
| demo watermark | startup messagebox "protected with demo version of VMProtect" (Demo only) |
| DIE | `Protector: VMProtect[packed]`, high-entropy packed section |

## Break side — the tooling reality (why the plan changes)

The original plan was **NoVmp + VTIL** devirtualization. Checked before building it:

- NoVmp (can1357) devirtualizes VMProtect x64 **3.0–3.5**; the NoVmpy fork reaches **3.6**. Both require an
  **unpacked** input. Project is an experimental PoC, **last updated Aug 2021**.
- Our target is **3.11.0 (2026)** — far beyond either, and packed.

**Conclusion: NoVmp/VTIL will not devirtualize this binary.** Building it (hours in VS2026) to watch it fail
on 3.11 is a negative result, not a skill. So the break path is a real choice (see below). This version
coupling *is* a genuine lesson: public automated devirtualizers lag the protector by years, which is exactly
why modern VMProtect is considered strong.

## Break options (pick one — tracked in the next-step box)

1. **Manual VM analysis (recommended, version-independent, mostly my hands).** Build a **virtualize-only /
   unpacked** variant so the VM is visible statically, then in IDA find the VM entry (`push … jmp vm_entry`),
   the dispatcher loop, and the handler table — the real devirtualization skill that works on any VMProtect
   version. I script/drive the headless IDA; you get the walkthrough.
2. **Unpack practice (your GUI hands, I guide).** Take the packed `…_vmp.exe` through **x64dbg + ScyllaHide**
   (past anti-debug) → **Scylla** dump at OEP. Produces the unpacked image option (1) analyzes. This is the
   half of the original plan that still applies.
3. **Dynamic bypass ("get past the popup").** We already know the algorithm (clean build). Use x64dbg / Intel Pin /
   Triton to locate the final compare in the running VM and patch or observe the branch — the full-bypass-chain "defeat the
   check without devirtualizing" goal. Fast, practical.
4. **NoVmp anyway** — build it and document it failing on 3.11 (honest negative; costly, low skill value).

Recommended: **1 + 2** together (unpack, then manually recover the VM) — that is the actual modern-VMProtect
RE workflow. NoVmp (4) only if you specifically want to see the version wall firsthand.

## Artifacts (git-ignored binaries)

`license_app_hardened.c` (committed), `license_app_hardened.exe` (marker build), `license_app.vmp.exe` (virtualized +
packed). Rebuild per the commands above (copy `VMProtectSDK64.dll` beside the marker build to run it
pre-protection).
