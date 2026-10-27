# Target: quint_bezier (license RE — user's own software)

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

- `find_license.py` — IDA headless locator: xref the license anchor strings, Hex-Rays (or disasm) the
  referencing functions. Run via `idat64 -A -S find_license.py <copy of the target>.exe`; writes the
  decompile to `%TEMP%\qn_license_decomp.txt` (user reviews/redacts before sharing).
