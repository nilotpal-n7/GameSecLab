# Phase 3 warm-up — hooking Veloren's `Health::change_by` with Frida

A gentle run-up to Phase 3 on a target you fully understand. You'll *observe* then *modify* a live
function, which is exactly what you'll do to Unreal's `ProcessEvent` later — just without the extra
Unreal machinery.

## CONCEPT — what a hook is

A **hook** diverts a running function through your code. Frida's `Interceptor.attach(addr, {onEnter})`
inserts a detour at `addr`: when the CPU reaches it, your JavaScript runs first (with full access to the
registers via `this.context`), then the original code continues. No files are patched on disk; it's all in
memory, and it's gone when the process exits.

**Why hook `change_by`?** In Phase 2 you found that *all* damage and healing funnels through
`Health::change_by`, and you verified the exact store `mov [rcx+0x50], r15d` at RVA `0xF4D9B3`. Hooking that
one spot sees every health change in the game — the same "one choke point" idea as `ProcessEvent` on Unreal.

**Why hook the store, not the function entry?** Rust doesn't use the C argument convention and inlines
heavily, so reading arguments at the entry is unreliable. At the store we *know*: `rcx` = the Health struct,
`r15` (low 32) = the new value, `[rcx+0x50]` = old value, `[rcx+0x58]` = maximum. Addresses move every launch
(ASLR), but **RVA `0xF4D9B3` is constant**, so Frida finds it via `module base + RVA`.

## SETUP (once)

`pip install frida-tools` — already done (frida 17.x). We drive it from Python so PATH doesn't matter.
Close Cheat Engine / ReClass first (their breakpoints/handles can clash). Start Veloren singleplayer.

## STEP 1 — observe (read-only)

```bash
cd C:\Tools\GameSecLab\scripts\frida
python run_hook.py change_by_logger.js
```

Take a hit, heal, stand in a fire. Each health change prints: entity address, old -> new HP, delta, max.
**Watch for this:** you'll see lines for hits you *didn't* take — NPCs fighting elsewhere. That proves the
function is shared across all entities (ECS). Press Enter to detach.

Paste a few log lines back.

## STEP 2 — modify (register edit)

```bash
python run_hook.py change_by_block_damage.js
```

Now when a write would *lower* health, the script overwrites `r15` with the old value first, so no damage
lands. Try to take a hit — you won't lose HP.

**The lesson in the pain:** this also makes **enemies invincible**, because the hook fires for everyone.
A real player-only cheat must **filter** to the player's Health pointer. The script has an `ONLY_ENTITY`
constant — set it to your player's Health address (the `...000` base from Phase 2, found fresh this run) to
affect only you. Finding "which entity is the player" automatically is the heart of Phase 3 proper.

Restart the game to clear the hook.

## ANTI-CHEAT LENS

- **Inline hook detection:** `Interceptor` overwrites the first bytes of the target with a jump. Anti-cheat
  can hash/compare `.text` against a known-good copy and spot the changed prologue (function-prologue
  integrity). Veloren does none of this; a protected game would.
- **Where this goes on Unreal:** the same `Interceptor.attach` pattern, but the universal choke point is
  `UObject::ProcessEvent`, and you read `UFunction*` + params instead of raw registers. That's Phase 3.

## FILES

- `scripts/frida/change_by_logger.js` — observe every health change
- `scripts/frida/change_by_block_damage.js` — block damage (all entities, or one via `ONLY_ENTITY`)
- `scripts/frida/run_hook.py` — attach + load driver
