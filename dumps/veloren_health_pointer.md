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

## Full Health layout, mapped live in ReClass (server copy, god mode frozen)

| Offset | Size | Field | Evidence |
| --- | --- | --- | --- |
| `0x00` | 8 | `last_change.by` (part 1: tag / group?) | `01 00 00 00 FF FF FF FF`; not decoded yet |
| `0x08` | 8 | `last_change.by` attacker Uid (likely) | `1224` |
| `0x10` | 8 | `last_change.time` f64 | 2293.97 -> 2422.28 between snapshots (game clock, seconds) |
| `0x18` | 8 | `last_change.instance` u64 | random, new value every change |
| `0x20` | 4 | `last_change.amount` f32 | -8.95, later -0.271 (damage of the last hit) |
| `0x24` | 4 | `last_change.cause` / `precise` tags | `01 00 01 00` -> `00 22 00 00` when damage type changed |
| `0x28` | 8 | `damage_contributors` table pointer | `-> <HEAP>32076070B00` |
| `0x30` | 8 | bucket_mask | 7 (8 buckets) |
| `0x38` | 8 | growth_left | 6 |
| `0x40` | 8 | items | 1 (one contributor) |
| `0x48` | 8 | hasher seed | random |
| `0x50` | 4 | `current` u32 x256 | `0x6400` = 25600 = 100 HP (frozen) |
| `0x54` | 4 | `base_max` u32 x256 | 25600 |
| `0x58` | 4 | `maximum` u32 x256 | 25600 |
| `0x5C` | 1 | `is_dead` | 0 |
| `0x5D` | 1 | `can_have_death_protection` | 1 |
| `0x5E` | 1 | `death_protection` | 1 |
| `0x5F` | 1 | padding | 0 |

**sizeof(Health) = 0x60 (96 bytes).** Proof: at `+0x60` the pattern repeats (`01 00 00 00 FE FF FF FF`,
an attacker Uid `1496`, a time `747.73`) — that's the **next entity's Health** in the same ECS `VecStorage`.
Element *n* of the array is at `storage_base + n*0x60`, and `current` at `+ n*0x60 + 0x50`.
