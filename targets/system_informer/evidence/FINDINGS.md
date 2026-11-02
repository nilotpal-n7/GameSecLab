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

## What still needs the DYNAMIC run (recording-time, on the real process)
These are not static-break failures — they *require* a live licensed process by design:
- The licensed `sip_access_mask → 0x0450` (vs the `0x1000` shown here): needs a valid `.sipm` to decrypt and
  populate `g_state`. Capture with an x64dbg HW-exec BP on the `NtOpenProcess` stub, read RDX.
- The KDF/AES block of `sip_gate_init`: structural (it calls `EVP_*` = HKDF→AES-256-GCM). Not an algebraic
  recurrence, so `prove_recurrence` doesn't apply — the evidence is the EVP call chain, captured live.
- The Themida side (`ExtendedTools.dll`): `themida_unwrap.py` needs a full-memory dump of the unpacked
  process (Task Manager → Create dump file while paused post-unpack).

## Tooling changed this pass
- `reaforge/core/loader.py` — generalized `_synth_exports` to catalog third-party import DLLs from their real
  on-disk export tables (not just system/CRT). This is why OpenSSL-linked targets now unpack. (General upgrade,
  benefits every future target that imports a non-system DLL.)
- `targets/system_informer/break_gate.py` — the title-specific gate driver used for `03`.
