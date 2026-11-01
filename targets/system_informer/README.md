# Target: system_informer (native_license category)

Our own licensed + protected fork of [winsiderss/systeminformer](https://github.com/winsiderss/systeminformer)
(System Informer, formerly Process Hacker). The user owns the fork; this is an authorized RE lab for an
educational video that contrasts plain MSVC x64 against VMProtect/Themida-protected code and forces a
crack through the entire reaforge toolchain.

## Tiers

- **Community (Free)** — standard process viewing / graphs. Left **unprotected** (the plain-MSVC contrast).
- **Enterprise (Pro)** — license-gated:
  - Process Memory Dumper (`PhWriteMiniDumpProcess`, `misccmd.c`)
  - DLL Injection (`misccmd.c`)
  - live Memory Editor write access (`memedit.c`)
  - cross-DLL plugin handshake (`SystemInformer.exe` <-> `plugins\ExtendedTools.dll`)

## Gate mechanism (why it is hard)

No naked booleans. The license state is turned into the `NtOpenProcess` ACCESS_MASK the feature actually
uses, so the **kernel** enforces the gate:

```
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

```
license_signer.py   reference oracle (Ed25519 + AES-256-GCM signer; the user holds the private key)
config.py           mask bases, slug, RVAs (single source of truth)
src/
  si_pro_mask.h     branchless entangled mask (final)
  pro_gate.h        extern "C" bridge contract (final)
  sip_crypto.h      crypto/HWID seam (LicenseSeat-backed)
  pro_gate.cpp      the Pro licensing core (VMProtect-marked)
  integration_misccmd.md   how to wire the dumper feature into misccmd.c (one feature, end to end)
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
the protected `.text` (the build prints it under `DEMO_SOFT`). Both bind the license to that machine +
that exact protected build.

## Build / protect (user runs these in the fork)

See `src/integration_misccmd.md` for the wiring, and `recovery/recovery_system_informer.md` for the
VMProtect/Themida pass settings and the RE walkthrough. The licensing core builds into `sip_progate.lib`
with the **same CRT as System Informer** (`/MT` release, `/MTd` debug) and `/Zi /DEBUG /MAP` so the
VMProtect pass can resolve the marker symbols.
