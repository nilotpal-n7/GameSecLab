# Veloren v0.18.0 — reaching Health.current (Phase 2 deliverable)

Build: `veloren-voxygen.exe` SHA256 `D9F6311A46EDFED0FB6EC0E1B6561F468C4B4B9C0C78CFCE2ED84784A8BFDC3C`

## What we know (verified)

| Item | Value |
| --- | --- |
| Field | `Health.current`, u32, stored as displayed HP x 256 |
| Offset | `+0x50` in the Health struct (`maximum` at `+0x58`) |
| Copies in single-player | two: **server** (authoritative) and **client** (display) |
| Writer instruction | `mov [rcx+50],r15d` — bytes `44 89 79 50` |
| Static address (Ghidra/objdump) | `0x140F4D9B3` inside `Health::change_by` |
| RVA | `0xF4D9B3` |
| Run where it was caught live | `7FF7E362D9B3` -> module base `7FF7E26E0000` (ASLR moved it from `0x140000000`) |

## Pointer scan: no stable path

| Attempt | Settings | Result |
| --- | --- | --- |
| Pointermap compare, run 1 vs run 2 | level 5, offset 4095 | 0 paths |
| Same, plus thread stacks as static (32 threads, 16 KB), offset 65535, level 6 | compared against run-1 map generated *without* stack options | 0 paths |

**Why:** Rust has almost no static globals; the game world is owned by a thread, and Health sits in an ECS
`VecStorage` list indexed by entity id. The only stable roots are thread stacks, and the run-1 snapshot
didn't record them, so the comparison discarded everything. Even with matching snapshots, ECS slot paths
are fragile (the slot index depends on spawn order).

## What works instead: the code, not the data

Cheat Engine's "Find out what writes to this address" caught **one** instruction writing the server health,
**23 times**: `mov [rcx+50],r15d` at `7FF7E362D9B3`. It's the same instruction found statically in Phase 0/1
(`0x140F4D9B3`): **RVA `0xF4D9B3` is stable across launches; only the module base moves.**

So the stable "address" of health in this game is: *the code location `veloren-voxygen.exe+F4D9B3`, plus
whatever `RCX` holds when it runs.* Using that is a code-hook technique — Phase 3.
