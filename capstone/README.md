# Capstone — protect-and-break (build layer, then reverse it)

## C0 target (done): `license_app.c`
Hardware-bound Windows license check (MinGW PE64). `machine_id()` = C: volume serial;
`expected_key()` mixes it; `check_license()` accepts only the matching 8-hex key.
Build: `gcc -O2 -o license_app.exe license_app.c` and `gcc -O2 -DKEYGEN -o keygen.exe license_app.c`.
`keygen.exe` prints this machine's valid key (RE deliverable at each layer = re-derive that keygen).

## Status
- C0 baseline built + verified (LICENSED with keygen's key). Recon via REAForge (facts in reaforge/facts.json).
- Next: C1 OLLVM obfuscation -> re-reverse; C2 VMProtect -> x64dbg+ScyllaHide/Scylla/NoVmp; C3 Themida; C4 writeup.

## Tooling proven
- REAForge **bridge mode** works: recon posted an LLM request to the mailbox and Claude Code answered it
  automatically (no pasting), returning the 3-step plan. See phases/capstone_protect_and_break.md.
- Break-side tools ready: IDA Professional 9.1 (`idat.exe` headless), Ghidra, x64dbg + ScyllaHide.
