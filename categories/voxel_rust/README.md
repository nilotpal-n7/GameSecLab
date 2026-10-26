# Category: voxel_rust

Rust / voxel games (Veloren and similar). These are not VM-protected — the work here is **live
memory analysis**: scanning, pointer-path discovery, server-vs-client value comparison, and runtime
hooking. The methodology is reusable for any such title; a specific title's scans live under
`targets/<title>/`.

## Contents

- `veloren_health_pointer.md` — worked pointer-path methodology (stable multi-level pointer to a
  changing value; how to find and validate it).
- `phase3_warmup_veloren.md` — Frida function-hooking warm-up (observe / modify / player-filter).

Generic DBI/hook templates (Frida) live in `reaforge/tools/frida/`. Anti-cheat defenses that follow
from each technique go in `knowledge/FIXLIST.md`.
