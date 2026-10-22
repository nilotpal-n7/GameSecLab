# Phase 2 — Memory editing (target: Veloren v0.18.0, single-player)

You arrive here with something most cheaters never get: the **exact struct layout**, recovered in Phase 0/1
from debug symbols + open source + a disassembly check. We verified it against the binary:

```text
Health (component), &mut self in RCX inside Health::change_by @ 0x140f4c940:
  +0x00  last_change (HealthChange)      <- copied here by the movdqu stores at the end of change_by
  ...    damage_contributors (HashMap)
  +0x50  current   u32   (value x256)    <- VERIFIED: mov %r15d, 0x50(%rcx)
  +0x54  base_max  u32   (value x256)
  +0x58  maximum   u32   (value x256)    <- VERIFIED: clamp source, mov 0x58(%rcx),%eax
  +0x5C  is_dead / can_have_death_protection / death_protection (bool)

Energy (component), compact 16 bytes:
  +0x00  current    u32  (value x256)
  +0x04  base_max   u32  (value x256)
  +0x08  maximum    u32  (value x256)
  +0x0C  regen_rate f32  (raw float, NOT scaled)
```

**The ×256 rule:** memory stores `displayed_value * 256`. HUD shows **100 HP** -> memory holds **25600**
(`0x6400`), a **4-byte integer**. This is the single most important fact for your first scan. (Why 256:
it lets the game do fractional health with fast integer math — an *accidental* obfuscation, see the lens.)

---

## 1. CONCEPT — addresses, pointers, ASLR, pointer paths

- **Address:** a location in the process's memory, e.g. `0x2A0F4C10`. Where a value *is right now*.
- **ASLR** (confirmed on in Phase 0): the game loads at a random base **every launch**, and ECS storages
  are heap-allocated, so the address of your health **changes every run**. An address you find today is
  useless tomorrow. This is the problem the rest of the phase solves.
- **Pointer:** a value that *is* an address — memory pointing at other memory.
- **Pointer path:** a chain `[[[base + o1] + o2] + o3]` that starts somewhere **stable** (a fixed location
  in the module, same offset every run) and hops through pointers to reach your health. Stable base +
  fixed offsets = survives relaunch and ASLR. Building one is the real deliverable of this phase.
- **ECS shape (from Phase 1):** there is no "Player" object. Health lives in a `VecStorage<Health>` — a
  contiguous array indexed by entity id. So your pointer path ends at *array_base + entity_slot * stride*,
  and the slot can move if entities despawn. We'll handle that.

---

## 2. YOUR STEPS

### Step 2.0 — Cheat Engine (already installed: 7.7, `C:\Program Files\Cheat Engine`)

1. Start it with `Cheat Engine.exe` — a small launcher that opens the right build
   (`cheatengine-x86_64-SSE4-AVX2.exe` on your CPU). Veloren is 64-bit, so you need the x86_64 build anyway.
2. **Optional warm-up (30–60 min, recommended):** run `Tutorial-x86_64.exe` from the same folder. Steps 2–8
   drill exactly this phase on a safe target: exact scan, unknown-value scan, float, code finder,
   **pointers (step 6)** and **multilevel pointers (step 8)**. `gtutorial-x86_64.exe` is a tiny graphical
   game version. If you finish step 8, steps 2.5 below will feel familiar.
3. Lab hygiene: we only ever attach to **single-player** Veloren. Never with a public server connected.

### Step 2.1 — Launch Veloren single-player and note your HP

1. Start `veloren-voxygen.exe`, create/enter a **singleplayer** world, spawn in.
2. Read your HUD health number, call it `H` (e.g. 100). Keep a weak enemy nearby to take a hit later.

### Step 2.2 — First scan: the scaled integer

1. Cheat Engine -> click the computer icon -> pick `veloren-voxygen.exe`.
2. Value Type: **4 Bytes**. Scan Type: **Exact Value**. Value: **`H * 256`** (100 -> `25600`).
3. First Scan. You'll likely get many hits (lots of things equal that number).
4. **Narrow it:** take a hit so HP changes to `H2`. New scan, Exact Value `H2 * 256`. Repeat 2–3 times.
   - If exact-value is stubborn, use **Unknown initial value -> Decreased value** (after damage) /
     **Increased value** (after regen). This is the general trick when you don't know the encoding.
5. You want to end with a small set (1–5) of addresses that track `displayed * 256`.

> Reality check: in single-player there are **two** Health components in the process — the embedded
> **server's** (authoritative) and the **client's** (for the HUD). You may find both. The one that, when
> frozen, actually stops you dying is the **server** copy. Finding which is which is the lesson in 2.4.

### Step 2.3 — Confirm you found health (and prove the ×256)

1. Add a candidate to the table. Right-click -> change the value to `50 * 256 = 12800`; watch the HUD snap
   to 50. That confirms both the address **and** the scaling.
2. Note it's `displayed * 256`. Set it to `(H_max) * 256` for a top-up.

### Step 2.4 — Freeze, and find who wins

1. Tick the **Freeze** box (the "Active"/frozen checkbox) on your health address. Take hits.
2. Two outcomes teach the whole phase:
   - **HP won't drop** -> you froze the **authoritative (server)** copy. That's god mode in single-player.
   - **HP still drops, snaps back, or flickers** -> you froze the **client/HUD** copy; the server keeps
     computing real damage and re-syncs. This is **server authority** demonstrated in one process.
3. Write down which copy behaved how. (In multiplayer, only the *server* copy exists on the server machine,
   which you can't reach — so this freeze would be pure client-side and purely cosmetic.)

### Step 2.5 — Pointer scan to a stable path (beat ASLR)

**Use the pointermap method.** A plain pointer scan writes *every* candidate path — Cheat Engine warns
"billions of useless results and giga/terabytes" — so answer **No** to that warning. Instead snapshot
memory in one run and compare against a second run, keeping only paths valid in both:

**Run 1**
1. Right-click the **server** health address -> **Pointer scan for this address**.
2. Select **Generate pointermap** -> OK -> save `dumps\veloren_run1.scandata`. Note the run-1 address.

**Relaunch** — 3. Close Veloren fully, relaunch, load the same singleplayer world. Old address is now wrong (ASLR).

**Run 2**
4. Find health again (2.2) and identify the server copy (2.4 — the copy whose edit does *not* move the HUD).
5. Right-click it -> **Pointer scan for this address** -> tick **Compare results with other saved
   pointermap(s)** -> add `veloren_run1.scandata` with its run-1 address.
6. Max level **5**, Maximum offset **4095**, Max different offsets per node **3** -> OK ->
   save `dumps\veloren_health.PTR`. Results = paths that worked in **both** runs.
7. Relaunch once more and use **Rescan memory** in the pointer-scan window with the new address to shrink to a
   handful of reliable paths. Record the final `module+offset -> ... -> +offset` path in
   `dumps\veloren_health_pointer.md`.

Dialog notes: leave **Pointers must end with specific offsets** off — with ECS storage the last offset is
`slot*sizeof(Health) + 0x50`, not plain `0x50`. If you get 0 results, raise Maximum offset to `65535`.

> Expect the ECS to make this interesting: the last hop should land on a `VecStorage` buffer and the final
> `+0x50` is our verified `Health.current`. If paths are unstable across relaunch, the slot index is
> changing — note it; a robust cheat would scan for the storage base + resolve the player entity id, which
> is exactly the kind of logic Phase 3/4 hooks reveal.

### Step 2.6 — Scripts (I'll hand these to you; keep in `scripts\cheatengine\`)

- `veloren_health_scaled.CT` notes + a Lua helper that reads/writes using the ×256 rule.
- An **Auto-Assembler** snippet that, once you have a stable base, injects a tiny "health = maximum each
  tick" or "freeze current" routine, to contrast *data edits* (this phase) with *code edits* (Phase 3).

### Step 2.7 — ReClass.NET: rebuild the struct

1. **Install:** download `ReClass.NET.rar` (v1.2) from <https://github.com/ReClassNET/ReClass.NET/releases>,
   extract to `C:\Tools\ReClass.NET` (Windows 11 Explorer can extract `.rar`; otherwise 7-Zip). Run
   `x64\ReClass.NET.exe` — Veloren is 64-bit. (Needs .NET Framework 4.7+, already on Windows 11.)
2. **Attach:** Process menu -> *Attach to Process* -> `veloren-voxygen.exe`.
3. **Point a class at Health:** the struct starts **0x50 before** `current`. Server health
   `...8050` -> struct base `...8000`. Click the address in the class header and type the base.
4. **Make room:** right-click a row -> *Add Bytes* -> *Add 64 Bytes* until the class is at least `0x70` long.
5. **Type the known fields** (select row -> right-click -> *Change Type*), then double-click names to rename:
   `+0x50 current UInt32`, `+0x54 base_max UInt32`, `+0x58 maximum UInt32`,
   `+0x5C is_dead Bool`, `+0x5D can_have_death_protection Bool`, `+0x5E death_protection Bool`.
   Rename the class `Health`. Displayed HP = value / 256.
6. **Watch it live:** take a hit — `current` changes in the window. Double-click a value to edit it, just like CE.
7. **Explore the unknown part (the real ReClass skill):** `+0x00` holds `last_change` (`HealthChange`).
   Change the first rows to **Float** and take a hit: look for a float equal to the damage you just took
   (negative = damage). Try **Double** for a steadily increasing value (game time).
8. **Save + export:** File -> Save As -> `scripts\reclass\veloren_health.rcnet`; Project -> *Generate C++ Code*
   -> save as `scripts\reclass\Health.h`. That header is the hand-made version of what Dumper-7 generates for Unreal.

### Step 2.8 — Write it up

Fill `dumps\veloren_health_pointer.md` (path + which copy is authoritative) and add a NOTES.md entry.

---

## 3. ANTI-CHEAT LENS (add defenses to FIXLIST.md)

| What you exploited | Why it worked | Defense |
| --- | --- | --- |
| Scanned for `displayed*256` | Value is a plain integer with a *fixed, guessable* transform | **Real obfuscation:** store `value XOR key` + a checksum, key rotated per session; recompute on read. Fixed-point ×256 only slows a beginner. |
| Froze current health | Nothing checks that `current` moves plausibly | **Sanity checks:** `current <= maximum` (Veloren already clamps this in `change_by`!), no health gain without a heal event, rate limits. |
| Edited the client copy | Client holds a writable copy of state | **Server authority:** the only real fix. Veloren already recomputes on the server; the client edit is cosmetic online. |
| Found a stable pointer path | Stable base + fixed offsets survive ASLR | You can't remove pointer paths, but you can **detect** scanning tools and **move**/encrypt critical values behind indirection + integrity checks (raises cost, never absolute). |
| `DerefFlaggedStorage` dirty bit | Taking `&mut` flags the component to sync | Not a defense by itself — but it's *why* a server-side edit propagates and a client-side one gets overwritten. Good model for your own netcode: authoritative mutation on the server, replicate down. |

**One-line takeaway:** every defense in this table except *server authority* only raises the attacker's
cost. Design your own game so the client can lie about its health all day and it changes nothing real.

---

## 4. HOW THIS TRANSFERS TO AAA / Unreal (Khazan-like)

- Same workflow (scan -> confirm -> freeze -> pointer scan -> ReClass), but values are usually **float**
  or **double** HP, often behind `GWorld -> PlayerController -> Pawn -> AttributeSet -> Health`.
- Phase 1 (Dumper-7) gives you those offsets up front, so you *start* at step 2.5 with a known path.
- Commercial anti-cheat (EAC/BattlEye/Vanguard) may block CE from opening the process at all — that's a
  Phase 5 topic. We practise the mechanics here, where nothing is watching.

---

## 5. DELIVERABLE

`dumps\veloren_health_pointer.md`: your verified stable pointer path to `Health.current (+0x50)`, a note on
which copy (server vs client) was authoritative when frozen, and the ReClass layout screenshot in
`screenshots\`. Phase 2 is done when you can relaunch the game and re-reach your health **via the saved
path without a fresh scan**.
