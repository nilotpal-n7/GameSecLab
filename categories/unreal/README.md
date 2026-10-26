# Category: unreal

Unreal Engine games (Lyra sample project and similar). Focus: UE recon, `ProcessEvent` / UFunction
hooking, and the anti-cheat lens for UE titles. Reusable across UE titles; a specific title's offsets
and dumps live under `targets/<title>/`.

## Contents

- `lyra_setup.md` — building a Shipping build of the Lyra Starter Game as a hands-on UE target.
- `anticheat_review.md` — reviewing UE anti-cheat surfaces and the defenses that follow.

Tooling (UE4SS, Dumper-7, FModel) is detected by `reaforge/tool_registry.py`.
