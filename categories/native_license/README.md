# Category: native_license

VMProtect-protected **native** license-check functions (x64, Microsoft x64 ABI). The pattern this
category automates:

- a virtualized `check_license(key)` that takes a NUL-terminated key-string pointer in the first
  integer arg (RCX),
- reads a machine/volume serial through an imported API (default `GetVolumeInformationA`, out-pointer
  in R9) — which the campaign hooks to inject a controllable serial,
- returns 1 (licensed) / 0 (rejected).

`campaign.py` is the title-agnostic mechanism: unpack to a snapshot, drive the VM'd function, run the
validation battery, then recover / peel / prove the key formula symbolically. It never names a title.

## Per-title config supplies

| field | meaning |
| --- | --- |
| `packed`, `snap` | the binary + its post-unpack snapshot |
| `check_rva` | RVA of the virtualized check function |
| `expected(serial)` | the title's reference keygen — used ONLY to validate / cross-check, never to drive recovery |
| `prove(want, serial_sym)` | optional z3 all-inputs proof of the recovered formula |
| `keybuf`, `ret_sentinel`, `marker`, `serial_api` | harness addresses / the import to hook |

See `targets/license_app/config.py` for the reference title (our C0 crackme).

## Scope

x64 MS ABI today. A 32-bit (cdecl, stack args) native license check would extend `call_check`'s
argument marshalling; the symbolic engine and peeler are already arch-agnostic.
