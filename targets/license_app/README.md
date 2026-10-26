# Target: license_app (native_license category)

Our own hardware-bound Windows license check — the VMProtect 3.11 crackme we built and broke
end-to-end. x64 PE (MinGW).

- `machine_id()` = C: volume serial; `check_license()` accepts only the matching 8-hex key.
- **clean build** `src/license_app.c` — clean baseline.  **VMProtect** `src/license_app_hardened.c` — the version we packed
  with VMProtect 3.11 Ultra (`dumps/license_app.vmp.exe`, the authorized analysis target).
- The reference keygen (clean-build algorithm) lives in `config.py` as `expected_key` — used only to
  validate / cross-check recovery, never to drive it.

## Layout

- `config.py` — the **only** place license_app specifics live (RVA, keygen, Proof-B recurrence, paths).
- `src/` — our C sources (tracked).  `recovery/` — the recovery write-ups clean/OLLVM/VMProtect + recovered keygen.
- `protect_and_break.md`, `vmprotect_break_cheatsheet.md` — the protect-then-reverse walkthrough.
- `screenshots/` — x64dbg / anti-debug evidence.
- `dumps/` — binaries, snapshot, IDA dumps, logs (**gitignored**; rebuild from `src/` + VMProtect).

## Run

```bash
python -m reaforge.core license_app [serial_hex] [modes]
```

Result: the VM accepts exactly the clean-build key for every serial; the symbolic engine recovers
`want(serial)` blind, peels the 8 VMProtect nibble-hash rounds (each z3-proven over all 2^32), and
Proof B confirms the clean `0x1505^s; ((acc*33)^nibble)+7i` recurrence.
