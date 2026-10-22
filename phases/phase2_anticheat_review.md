# Phase 2 — anti-cheat review (what we did, how a defender sees it)

Phase 2 covered: scanning memory, writing/freezing a value, pointer scanning, "what writes to this
address", and rebuilding a struct in ReClass. For each, here is **the signal a defender can see** and
**the defense**, split into *client-side* (raises attacker cost, always defeatable) vs *server-side*
(the only thing that actually protects the game).

---

## 1. Opening the process (Cheat Engine / ReClass attach)

**What happened:** both tools called `OpenProcess` on `veloren-voxygen.exe` to read/write its memory.

**Defender's view:**

- A handle to the game process with `PROCESS_VM_READ`/`PROCESS_VM_WRITE`/`PROCESS_VM_OPERATION` is opened
  by *another* process. Anti-cheat can enumerate who holds a handle to it (e.g. via `NtQuerySystemInformation`).
- Known-tool fingerprints: window class names, driver names (`CEDRIVER`, DBK), the CE/ReClass process names.

**Defense (mostly client-side, i.e. detection, not prevention):**

- Enumerate open handles to self; flag foreign ones with write access.
- Scan loaded drivers / running processes for known tool signatures.
- Strip your own process ACL so non-admin tools can't open a handle (kernel anti-cheat goes further).
- **Reality:** all defeatable (rename tools, kernel-mode read, DBVM). Detection just raises cost.

## 2. The value scan (`displayed * 256`)

**What happened:** found health because it's a plain integer with a fixed, guessable transform (×256).

**Defense:**

- *Client-side:* don't store the plain value. Keep `current XOR session_key` plus a checksum; decode on
  read, re-encode on write, rotate the key each session. (Veloren's ×256 is only accidental obfuscation.)
- *Server-side (real):* the number in the client is just a display cache; the server holds the truth.

## 3. Writing / freezing the value

**What happened:** set `current` to 25600 and froze it (CE rewrites ~every 100 ms).

**Defender's view & defense:**

- *Client-side sanity checks* — the kind you can also see Veloren already doing in `change_by`:
  `current <= maximum`, no increase without a heal event, rate-limit changes, flag impossible jumps.
- *Integrity:* periodically hash the stat block and compare to a shadow copy held elsewhere; a direct
  write (which skips the setter) fails the check. **Note:** hash the *fields*, not raw bytes — padding
  byte `0x27`/`0x5F` holds junk and would cause false mismatches (see GLOSSARY: padding bytes).
- *Server-side (real):* we proved it live — freezing the **client** copy was cosmetic; the **server** copy
  is authoritative. Online, that copy is on a machine the attacker can't touch. **This is the whole game.**

## 4. Pointer scan (failed) + "what writes to this address"

**What happened:** no stable pointer path (Rust: no globals, ECS `VecStorage` slot). The reliable anchor
was the code that writes health — a hardware breakpoint caught `mov [rcx+50],r15d` once per write.

**Defender's view & defense:**

- A **hardware breakpoint** sets the CPU debug registers (DR0–DR3, DR7). A process can read its own
  `CONTEXT` and see them set -> a classic anti-debug check (Phase 4 covers this both ways).
- Code-anchored cheats depend on the instruction staying put. Shipping stripped + ASLR (both already true
  for us as *attacker friction*) and, for high-value functions, virtualization (VMProtect/Themida) make
  that instruction hard to find and hook. Phase 3/5 territory.

## 5. ReClass struct rebuild

**What happened:** reconstructed the 96-byte `Health` from debug symbols + source + live watching.

**Defense:** this is the Phase 0 lesson cashed in — **ship stripped**. No symbols, no shipped source,
no public offsets => the attacker must do all of Section 4/5's work from scratch for every patch.

---

## The one-paragraph takeaway

Everything in Phase 2 that a cheater does to the client, a developer can only *slow down* on the client:
obfuscation, checksums, tool/handle/breakpoint detection, stripping, virtualization — each raises cost,
none is a wall. We demonstrated the single exception directly: when we froze the **server's** health copy
it worked, and when we froze the **client's** it was overwritten on the next sync. **Authoritative state on
a server you control is the only defense in this phase that cannot be beaten from the client.** Design the
client so it may lie about its own health freely and nothing real changes.
