# Target: system_informer (native_license category)

Our own licensed + protected fork of [winsiderss/systeminformer](https://github.com/winsiderss/systeminformer)
(System Informer, formerly Process Hacker). The user owns the fork; this is an authorized RE lab for an
educational video that contrasts plain MSVC x64 against VMProtect/Themida-protected code and forces a
crack through the entire reaforge toolchain.

## Tiers

- **Community (Free)** — standard process viewing / graphs. Left **unprotected** (the plain-MSVC contrast).
- **Enterprise (Pro)** — license-gated, exposed as a per-process **right-click → System Informer Pro**
  submenu in `plugins\ExtendedTools\main.c` (greyed in Community; each opens the target with
  `sip_access_mask(SIP_FEAT_*)` so the kernel, not a branch, enforces the gate):
  - Process Memory Dumper — full `.dmp` via `PhWriteMiniDumpProcess` (also in the host `mdump.c`)
  - DLL Injection — alloc + write + remote `LoadLibraryW`
  - live Memory Editor — `NtReadVirtualMemory` / `NtWriteVirtualMemory` behind `IDD_PRO_MEMEDIT`
  - cross-DLL plugin handshake (`SystemInformer.exe` <-> `plugins\ExtendedTools.dll`)

## Gate mechanism (why it is hard)

No naked booleans. The license state is turned into the `NtOpenProcess` ACCESS_MASK the feature actually
uses, so the **kernel** enforces the gate:

```text
m      = (ULONG)(-(LONG)(entitled & crc_ok & nodbg));   // branchless, no JZ/JNZ
access = (base & m) | (0x1000 & ~m);                     // base when entitled, trap (0x1000) otherwise
```

`base` (0x0450 dump / 0x002A inject / 0x0038 edit) is **not** a binary immediate — it is carried
AES-256-GCM-encrypted in the offline machine file, under a key from an HKDF that entangles
`HWID || issuer_pubkey || text_crc || slug`. A patched `.text` byte or a swapped `.rdata` pubkey changes
the key, so the license **fails to decrypt** rather than failing a comparable check. The whole file is
Ed25519-signed, so entitlements cannot be forged without the issuer private key. See
`src/pro_gate.cpp`, `src/si_pro_mask.h`, and `recovery/recovery_system_informer.md`.

## Layout

```text
license_signer.py   reference oracle (Ed25519 + AES-256-GCM signer; the user holds the private key)
config.py           mask bases, slug, RVAs (single source of truth)
src/
  si_pro_mask.h     branchless entangled mask (final)
  pro_gate.h        extern "C" bridge contract (final)
  sip_crypto.h      crypto/HWID seam (LicenseSeat + Windows CNG)
  sip_crypto_licenseseat.cpp  the seam backing: HWID+Ed25519 via LicenseSeat, AES-GCM+HKDF via BCrypt
  pro_gate.cpp      the Pro licensing core (VMProtect-marked)
  integration_dumper.md   how to wire the dumper feature into mdump.c (one feature, end to end)
recovery/
  recovery_system_informer.md   the IDA/x64dbg crack walkthrough
dumps/              protected binaries + snapshots (gitignored)
issuer_keys/        the issuer private key (gitignored - never commit)
licenses/           issued .sipm files (gitignored)
```

## Oracle quickstart

```bash
python license_signer.py genkey                                  # once; keep issuer_keys/ safe
python license_signer.py pubkey-c                                # paste into src/pro_gate.cpp
python license_signer.py issue  --hwid <HWID> --text-crc 0x<CRC> --subject "Name" --tier pro
python license_signer.py verify licenses/Name.sipm --hwid <HWID> --text-crc 0x<CRC>
python license_signer.py attack licenses/Name.sipm --hwid <HWID> --text-crc 0x<CRC>  # films the failures
```

`<HWID>` comes from `VMProtectGetCurrentHWID()` on the target machine; `<CRC>` is the runtime CRC-32 of
the protected on-disk image (whole file; `sip_report_tool` prints it). Both bind the license to that
machine + that exact protected build.

## Build / protect (user runs these in the fork)

See `src/integration_dumper.md` for the wiring, and `recovery/recovery_system_informer.md` for the
VMProtect/Themida pass settings and the RE walkthrough.

**CRT trap:** `demo/licenseseat/lib/licenseseat.lib` is prebuilt `/MD` (dynamic CRT) while System Informer
is `/MT` (static CRT); they cannot share one image. So the licensing core is its **own DLL**
(`sip_progate.dll`, `/MD`, linking `licenseseat.lib` + `bcrypt.lib` + `VMProtectSDK64.lib`), which SI
(`/MT`) calls across the primitives-only C ABI in `pro_gate.h` — no CRT objects cross the boundary. Build
the DLL `/Zi /DEBUG /MAP`, then run the VMProtect pass on `sip_progate.dll` itself.
