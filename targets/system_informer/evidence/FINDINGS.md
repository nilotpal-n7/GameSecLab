# System Informer Pro — automated break evidence (VMProtect core)

Raw logs in `logs/`. This is a pointer sheet: what each log shows, what line to look at, what it means.
Everything here is the automated reaforge pass on `sip_progate.vmp.dll` (the user's own fork). No runtime
dump was needed — the VMProtect side is defeated purely by emulation.

Pipeline:  `recon (DIE)` → `emulation-unpack to OEP (reaforge.core.loader)` → `gate devirt (break_gate.py)`

Binaries under test (locked copies + MD5 in `locked_binaries/`):
- `sip_progate.vmp.dll`  — VMProtect-packed licensing core (carries the gate + KDF)   MD5 `F354B36A…`
- `ExtendedTools.dll`    — Themida-packed plugin (handshake)                           MD5 `A13D552D…`
- `SystemInformer.exe`   — host, plain MSVC by design                                  MD5 `F0177730…`

---

## 00_recon_die — classify the protectors
LOOK AT: the `Protector:` lines.
```
sip_progate.vmp.dll  -> Protector: VMProtect[packed]   (+ Library: OpenSSL)
ExtendedTools.dll    -> Protector: Themida/Winlicense(3.XX)
SystemInformer.exe   -> Protector: VMProtect(new)[DS]   <- heuristic FALSE POSITIVE (host is unprotected)
```
MEANS: two different protector families on the same scheme (the point of the dual-protector lab). The
`OpenSSL` library line on `sip_progate` is the thread that matters next — it imports `libcrypto`.

## 01_vmprotect_unpack (FIRST RUN — the wall) → superseded by 02
LOOK AT: the last line.
```
ValueError: export not in captured catalog libcrypto-1_1-x64.dll!EVP_DecryptInit_ex
```
MEANS: the emulation-unpacker's synthetic Windows world only cataloged **system** DLLs. `sip_progate`
imports OpenSSL (`libcrypto`) for AES-GCM, which wasn't in the catalog, so building its import stubs failed.
FIX (general, in `reaforge/core/loader.py`): catalog **any** uncatalogued import DLL from its real on-disk
export table. Re-run = 02.

## 02_vmprotect_unpack (AFTER THE FIX — the unpack succeeds)
LOOK AT:
```
[setup] catalogued 4397 real exports from libcrypto-1_1-x64.dll     <- the fix working
[setup] crc 0 lzma 6 stack copies 19                                <- inside VMProtect's unpack stub
[setup] emulation_reached_unpacked_entry ... instruction_count=98370832   <- OEP reached (98.3M insns)
[setup] saved snapshot (27 regions) -> ...\system_informer_postoep.snap   <- 35 MB post-OEP snapshot
```
MEANS: **VMProtect is defeated by emulation.** We reach the original entry point and snapshot the unpacked
image — no debugger, no manual dump. (The `validation battery ... FAIL` lines below are the *generic
serial-crackme* harness, which is the wrong shape for a feature→mask gate — ignore them; `03` is the real
analysis.)

## 03_gate_devirt — the gate, from the snapshot (`break_gate.py`)
LOOK AT [1] — exports resolve at the exact RVAs the recovery doc predicted:
```
sip_access_mask 0x1249   sip_gate_init 0x1320   sip_xdll_respond 0x16F4   sip_is_pro 0x1DF2
```
LOOK AT [2] — `sip_access_mask` is virtualized (VMProtect Ultra VMEnter), not native mask code:
```
0x180001249  jmp 0x180003540
0x180003540  mov [rsp+8],rbx ; push rdi ; sub rsp,0x20 ; mov ebx,ecx ; lea rcx,[rip+0x7f405] ; jmp 0x18017b38b
             ^-- saves the feature arg (ecx), loads the VM bytecode ptr, jmps into the VM dispatcher
```
LOOK AT [3] — THE HEADLINE. Emulated through the VM with **no license loaded**:
```
sip_access_mask(0=dump  ) = 0x00001000   TRAP
sip_access_mask(1=inject) = 0x00001000   TRAP
sip_access_mask(2=edit  ) = 0x00001000   TRAP
verdict: ALL TRAP -- gate is fail-closed without a decrypted license.
```
MEANS: this is the whole thesis on one screen. You defeated the protector, you can run the gate — and it
still hands you `0x1000` (`PROCESS_SUSPEND_RESUME`), the **trap mask**. The licensed bases
(`0x0450`/`0x002A`/`0x0038`) are **not constants in the code**; they only exist after the `.sipm` is
AES-GCM-decrypted into `g_state`. **Cracking the protector ≠ cracking the scheme.**

[4] `sip_gate_init(NULL)` is INCONCLUSIVE in static emulation (its path calls the Win32 file API + libcrypto
AES-GCM, not modeled here) — but [3] is the load-bearing result and doesn't depend on it.

---

## 04_ida_sip_progate — IDA Pro 9.1 (Hex-Rays) static view of the packed core
LOOK AT [exports]: gate exports at the same RVAs the emulation found (`sip_access_mask` 0x1249,
`sip_gate_init` 0x1320, `sip_xdll_respond` 0x16F4, `sip_is_pro` 0x1DF2).
LOOK AT [gate export bodies]: IDA shows them as **raw data** (`db 7 dup(?)`, `dq 1Ah dup(?)`) and Hex-Rays
`decompile = None`.
```
-- sip_access_mask @ 0x180001249 --
    0x180001249  db 7 dup(?)        <- IDA can't even make it code
  [hexrays]
    None                            <- no C to read
```
MEANS: **static IDA is defeated by VMProtect** — the gate logic isn't native, so there's nothing to
decompile. (Our emulation-unpack is what recovered the `jmp 0x3540` VMEnter; IDA alone can't.)
LOOK AT [imports]: the crypto dependency is still visible in the IAT even though the code is hidden:
```
EVP_DecryptInit_ex   (OpenSSL AES-GCM)      BCryptSetProperty   (Windows CNG)
```
MEANS: the KDF/decrypt rides on AES-GCM — statically provable from the imports, which is the thread §4 says
to pull. VMProtect section names (`.yr)`, `._Xa`, `.v6v`) confirm the packing.

## 05_dynamic_licensed_mask — the gate run for real (licensed vs unlicensed)
`sip_report_tool.exe` loads the **real** VMProtect DLL (no debugger → anti-debug passes) and runs the gate.
LOOK AT:
```
[A] LICENSED (deployed .sipm):   sip_gate_init = 0 (OK)   sip_is_pro = 1   sip_access_mask(DUMP) = 0x0450
[B] UNLICENSED (missing .sipm):  sip_gate_init = 2 (bad)  sip_is_pro = 0   sip_access_mask(DUMP) = 0x1000
    HWID=c30e127afb5ab2d9e4b8af5200848f5c   TEXT_CRC=0x3AEAAED9
```
MEANS: this is the dynamic counterpart to the static `0x1000`. The **same** `sip_access_mask` returns the
real base **0x0450** once — and only once — `sip_gate_init` succeeds (AES-GCM decrypt → `g_state`). No
license ⇒ `0x1000`. The licensed base is data the decrypt produces, not a constant you can lift. This is the
`NtOpenProcess` DesiredAccess the dumper would pass: `0x0450` licensed vs `0x1000` trap.

## 06_ida_si_callsite — IDA Pro Hex-Rays of the CALLER side (SystemInformer.exe + PDB)
The host is unprotected by design, so Hex-Rays decompiles it cleanly (PDB names applied). This is recovery
doc §2 — "find the gate: the NtOpenProcess call site and its ACCESS_MASK producer" — in readable C.

The explicit-load shim (`sip_resolve.c`) decompiles 1:1 (`SipProgateModule` + `GetProcAddress`), and the
dumper `PhUiCreateDumpFileProcess` wires the gate straight into the process open:
```c
// NULL -> the .sipm beside the exe, then verify/decrypt:
strcpy_s(v38 + 1, v70 - v38, "SystemInformer.sipm");
ProcAddress = GetProcAddress(v36, "sip_gate_init");
if (ProcAddress) ((void (__fastcall *)(char *))ProcAddress)(v37);   // sip_gate_init(path)

// THE gate: the DesiredAccess is produced by sip_access_mask, not chosen by a branch:
if (v40 && (v41 = GetProcAddress(v40, "sip_access_mask")) != 0)
    v42 = ((__int64 (__fastcall *)(_QWORD))v41)(0);                 // sip_access_mask(SIP_FEAT_DUMP)
else
    v42 = 4096;                                                     // 0x1000 trap — fail-safe fallback
v43 = PhOpenProcess((void **)v29 + 7, v42, *((void **)v29 + 2));    // PhOpenProcess(&h, v42, pid)
```
MEANS: `PhOpenProcess`'s access mask `v42` comes **directly** from `sip_access_mask` (`0x0450` licensed /
`0x1000` trap from `05`). There is no `if (licensed)` to NOP — the license state *is* the access mask. Even
the unresolved-shim path falls back to `0x1000` (trap), so it fails closed. (`PhpAboutDlgProc` — the Help→About
Activate-Pro flow — also references the `.sipm` and is in the log.)

## Status of the recovery-doc steps
- §1 unpack + snapshot — ✅ DONE (`02`), automated.
- §2 find the gate / the ACCESS_MASK producer — ✅ DONE: `sip_access_mask` is the producer; licensed it
  yields `0x0450`, unlicensed `0x1000` (`05`). (`06_ida_si_callsite` adds the Hex-Rays wiring if present.)
- §3 devirt the gate shape — ✅ shown by execution (`03`): emulated through the VM, fail-closed to trap.
- §4 the KDF wall — PARTIAL: statically proven that it rides on AES-GCM (`EVP_DecryptInit_ex`/`BCrypt` in the
  IAT, `04`) and that a successful decrypt is REQUIRED to get `0x0450` (`05`). A full instruction-level lift of
  the HKDF/AES block still wants a live trace; it is HKDF/AES-GCM, not an algebraic recurrence, so
  `prove_recurrence` does not apply — the evidence is the EVP call chain, not an algebra proof.
- Themida side (`ExtendedTools.dll`) — PENDING: `themida_unwrap.py` needs a full-memory dump of the unpacked
  plugin inside a live SI process (Task Manager → Create dump file while paused post-unpack) — a recording-time
  capture, not a static step.

## Tooling changed/added this pass
- `reaforge/core/loader.py` — generalized `_synth_exports` to catalog third-party import DLLs from their real
  on-disk export tables (not just system/CRT). This is why OpenSSL-linked targets now unpack. (General upgrade,
  benefits every future target that imports a non-system DLL.)
- `targets/system_informer/break_gate.py` — the title-specific gate driver (static break, `03`).
- `reaforge/tools/ida_sip_gate.py` — IDA Pro headless gate analyzer (`04`, `06`): exports, VMEnter bodies,
  crypto imports, Hex-Rays of the gate + its callers. General (keys off the opened file).
