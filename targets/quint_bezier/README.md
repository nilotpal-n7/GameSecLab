# Target: quint_bezier (license RE — user's own software) — CRACKED

**Status: Pro unlocked (oracle-free keygen).** Full write-up: [recovery/recovery_quint.md](recovery/recovery_quint.md).
The Pro gate reduces to a hardcoded-constant XOR identity on `LicensedTo`/`ViewState`/`CacheTag`;
Formula C (machine-independent) → `CacheTag = (nameSum<<48) ^ 0x917AA921821C49AB`, written to
**`HKLM\Software\QuintBezier`** (machine-wide, so the SYSTEM-service governor sees it). No patch, no
code, no server. `patch_islicensed.py` is the zero-crypto fallback.

Authorized license reverse-engineering of **Quint Bezier**, the user's own commercial software
(Authenticode `CN=Nilotpal(me)`, Company `Nilotpal(me)`), modeled on Process Lasso's structure. For
research/testing only, on binaries the user owns.

## HARD access rule

The install dir `C:\Program Files\Quint Bezier` holds the user's private secrets. **Claude never reads
it directly or indirectly.** All scripts live here in GameSecLab; the user runs them against the
install dir and pastes back only what they choose (redacted). No install-dir path is an accessible
target for Claude.

## On-disk reality (recon done)

DIE on every code binary (qnActivate, QuintBezier, QuintGovernor, QuintBezierLauncher, srvstub,
qnsessionagent): **plain MSVC 2026, Authenticode-signed, codeview debug symbols present — no Themida /
WinLicense / VMProtect.** So despite the "packed with Themida" expectation, the shipped builds are
**not VM-protected**; the license check is in normal, symbol-bearing code → straight static RE, no
unpack/devirt needed (the reaforge Themida toolchain is not required here).

## Licensing architecture (from the user; non-secret)

- **QuintGovernor.exe** — core engine; queries license state, disables Pro features after the grace
  period. The real enforcement gate.
- **QuintBezier.exe** — GUI; trial/Pro status, nag screens, registration prompt.
- **qnActivate.exe** — activation helper; online activation writes a token to disk + registry.
- Offline/enterprise: **`probezier.key`** — RSA-signed license block (embedded public key verifies it).
- State: registry `HKCU/HKLM\Software\nq Technologies\Quint Bezier` (RegName, RegKey/ActivationCode,
  FirstRun, NagTime/LastNag).
- License strings found in QuintGovernor: `LicensedTo`, `Registered User`, `QN_ACTION_TOOK_LICENSE_EXPIRED`,
  `ShowGraphLicenseName`, tier list `Quint Bezier Pro …`, `probezier.key`.

## Routes to "unlocked" (research)

1. **Patch the verdict** — force the is-licensed / is-Pro predicate true. Works regardless of RSA
   strength (crypto moves cost to *understanding*, not to defeating the check). Primary route.
2. **RSA `probezier.key` verification** — a true offline keygen needs the private key (by design);
   outcomes are bypass (route 1) or, since the user holds the private key, legitimately self-signing.
   Claude never requests the private key.
3. **Trial reset** (`FirstRun`/`NagTime`) — weakest, not a real unlock.

## Tools

- **`reaforge/tools/license_recon.py`** — the *general* IDA license-locator (anchors → direct refs +
  pointer-table refs → Hex-Rays/disasm, size-capped), parameterized by `QN_ANCHORS`/`QN_SEED`/`QN_CAP`.
  This is the reusable framework tool; prefer it for new targets.
- `keygen.py` — Formula-C keygen: `python keygen.py "<name>"` → `ViewState`/`CacheTag` to write.
- `apply_license.py` — the one-shot deploy: keygen + the exact ready-to-run HKLM `reg add` commands with
  `CacheTag` already substituted (nothing to hand-copy). Via the orchestrator:
  `python -m reaforge.orchestrator apply quint_bezier "<name>"`.
- `patch_islicensed.py` — force-true patch of the Pro predicate (RVA `0x5170` governor / `0x116E90` GUI).
- `find_license.py` / `gen2_hunt.py` / `reg_details.py` — the ad-hoc first cuts used during this break,
  kept for reference; `license_recon.py` generalizes them. Output now lands in `dumps/` (not `%TEMP%`).

## On automation (honest note)

reaforge's orchestrator automates the **protected** path (authorize → recon → classify protector →
emulation devirt). This target is **unprotected** (plain MSVC + symbols), so recon classifies "no
protector" and the VM toolchain has nothing to lift — the work is static *locate + read + keygen*.
That path is now a first-class tool (`license_recon.py`), and the keygen→deploy last mile is a single
command (`orchestrator apply quint_bezier "<name>"` via `apply_license.py`) — only *reading* the
recovered predicate stays a human step. Also: the HARD
no-access rule means Claude can't run anything against the install dir — every step was a command the
user executed — so reaforge drove via handed commands, not by operating on the files directly.
