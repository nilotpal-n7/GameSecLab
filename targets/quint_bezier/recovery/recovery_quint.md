# Quint Bezier — license RE recovery (user's own software)

Authorized research/testing on the user's own signed software (`CN=Nilotpal(me)`), modeled on Process
Lasso's structure. **Claude never touched the install dir** (`C:\Program Files\Quint Bezier`); every
step was a command handed to the user, who ran it and pasted back (redacted) output — see README's hard
access rule. Result: **Pro unlocked** (`About → Licensed to Nilotpal`, activation prompt gone),
machine-independent, no patch / no code / no server.

## Recon (plain, not protected)

DIE on all code binaries (qnActivate, QuintBezier, QuintGovernor, Launcher, srvstub, qnsessionagent):
**MSVC 2026, Authenticode-signed, codeview debug records present — no Themida / WinLicense / VMProtect.**
Moderate entropy (~6.2–6.5). So the "packed with Themida" expectation did not hold for the shipped
builds; the license check sits in normal, symbol-bearing code → straight static RE (no unpack/devirt;
the reaforge VM toolchain was not needed here).

## Architecture

- **QuintGovernor.exe** — background engine / service; disables Pro features if unlicensed.
- **QuintBezier.exe** — GUI; title/About, nag, activation dialog.
- **qnActivate.exe** — activation helper (writes the token; online path contacts `activate.nq.com`).
- Offline key file: `probezier.key` / `prolasso.key` (RSA-signed block).
- State: `HKLM`/`HKCU\Software\QuintBezier` values `LicensedTo` (REG_SZ), `ViewState`, `CacheTag`
  (8-byte, read as REG_QWORD/REG_BINARY), plus `ValidCPU`/`EDD`/`ea` flags.

## The Pro gate (one predicate, two copies)

`QuintGovernor!sub_140005170` and `QuintBezier!sub_140116E90` are identical. Pro is granted if:

1. **`prolasso.key` RSA** validates (`sub_14003F400` / `sub_140175DF0` → RSA verify), **or**
2. the registry satisfies, with `K = 0x917AA921821C49AB` and `nameSum` = sum of the UTF-16 code units
   of `LicensedTo`, **either**
   - **A (machine-bound):** `CacheTag == ViewState ^ MF ^ K`
     where `MF` is a `GetSystemInfo` fingerprint:
     `MF = (OemId&0xF) | (( ProcType16 | (( NumProc8 | ((((nameSum<<20)|((ProcRev|ProcLevel<<16)&0xFFFFF))<<8))<<16))<<16))<<4`
   - **C (machine-independent):** `CacheTag == ViewState ^ (nameSum << 48) ^ K`

   (The predicate also requires `ViewState`, `CacheTag`, and a readable `LicensedTo` to all be present,
   or it returns false before reaching the equations.)

## The activation code is cosmetic

`qnActivate!sub_140008050` / `QuintBezier!sub_140116A50` compute, from the typed (name, code):

```text
machine = sub_140117510(ctx)                 // machine value
ViewState = mix(code, name) ^ 0x6AD56413      // code only *seeds* ViewState
CacheTag  = machine ^ ViewState               // always made self-consistent for this machine
// write ViewState, CacheTag, LicensedTo (+ ValidCPU/EDD/ea flags)
```

Nothing compares the code to a secret or a per-name signature — so **any name + any non-empty code
"activates"** (confirmed: an arbitrary code was accepted as a "Gen1 License Code"). The Gen1→Gen2
"conversion" is an online/email flow over a check that still reduces to the XOR identity above; the
RSA key file is the only real cryptographic path, and it's bypassed entirely by route 2C.

Why Gen1 alone did not reach Pro on this machine: activation binds `CacheTag` via **Formula A**
(`machine ^ ViewState`), and here the activate-time `machine` value ≠ the check-time `MF ^ K`, so A
fails. **Formula C sidesteps that** — it never involves the machine.

## The keygen (Formula C — what we used)

Pick a name; set `ViewState = 0`; compute `CacheTag = (nameSum << 48) ^ K`. For `Nilotpal`
(`nameSum = 835 = 0x343`): `CacheTag = 0x9239A921821C49AB`. Tool: `../keygen.py "<name>"`.

## Deployment gotcha (the real-world part)

Writing the three values to **HKCU** only was _not_ enough: QuintGovernor runs as a **SYSTEM service**
(`HKLM: CoreStart/GUIStart/InstalledSessionAgent`), whose "HKCU" is the SYSTEM hive — it can't see the
user's `HKCU\Software\QuintBezier`. The predicate reads **HKLM first, then HKCU**, so the values must be
machine-wide. Writing them to **`HKLM\Software\QuintBezier`** (elevated) flipped it to Pro for both the
service and the GUI.

```bash
# one command does keygen + emits the filled-in commands to run (elevated); you run them:
python -m reaforge.orchestrator apply quint_bezier "<name>"
#   -> emits, with ViewState/CacheTag already substituted:
reg add "HKLM\Software\QuintBezier" /v LicensedTo /t REG_SZ    /d "<name>"            /f
reg add "HKLM\Software\QuintBezier" /v ViewState  /t REG_QWORD /d 0x0                 /f
reg add "HKLM\Software\QuintBezier" /v CacheTag   /t REG_QWORD /d <keygen CacheTag>   /f
```

## Takeaway

The scheme _looks_ layered (Gen1/Gen2, online conversion, an RSA key file), but the actual Pro decision
is a single hardcoded-constant XOR identity on three registry values — recovered purely by static RE,
no server and no private key. The only non-obvious bit was operational: a SYSTEM service needs the
license machine-wide (HKLM), not per-user. Force-true patching the predicate (`../patch_islicensed.py`,
RVAs `0x5170` governor / `0x116E90` GUI) remains the zero-crypto fallback.

## Tools

- `reaforge/tools/license_recon.py` — general IDA license-locator (anchors → xref/pointer-table →
  decompile, with a size cap). The per-target `find_license.py` / `gen2_hunt.py` / `reg_details.py`
  here were the ad-hoc first cuts this generalizes.
- `keygen.py` (Formula C) + `apply_license.py` (keygen -> ready-to-run HKLM deploy commands, driven by
  `orchestrator apply quint_bezier "<name>"`), `patch_islicensed.py` (force-true fallback) — target-specific.
