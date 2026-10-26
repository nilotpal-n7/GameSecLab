# GLOSSARY

Plain-words definitions. Add a term the first time you meet it.

## Binaries & files

- **PE (Portable Executable)** — the file format of Windows `.exe`/`.dll`. Has headers, then
  *sections* (`.text` = code, `.rdata` = read-only data/strings, `.data` = globals, `.rsrc` = icons/version info).
- **Import table** — the list of DLL functions a PE needs. Tells you a lot about what a program does.
- **PDB** — debug-symbol file produced by the MSVC linker: function names, types, line numbers.
  Shipping one with a game hands attackers a map. The exe's *debug directory* stores the PDB path.
- **Authenticode / code signing** — a certificate signature on a PE proving who published it and
  that it was not modified after signing.
- **DWARF** — the debug-info format used by GNU toolchains (gcc/MinGW, Rust's `windows-gnu`
  target). Stored *inside* the exe as `.debug_*` sections instead of a separate PDB.
- **Symbol table / name mangling** — function names stored in the binary. Rust and C++ encode
  ("mangle") them, e.g. `_ZN7veloren...`; tools can demangle them back to readable names.
- **Toolchain** — the compiler + linker + runtime libraries used to build a program. MSVC ships
  `vcruntime*.dll`; MinGW ships `libgcc_s_seh-1.dll` / `libstdc++-6.dll` / `libwinpthread-1.dll`.
- **Static vs dynamic analysis** — static = study files without running them (undetectable);
  dynamic = observe/modify the running process (detectable by anti-cheat).
- **Entropy** — how random the bytes look (0–8). Normal code ~6; compressed/encrypted data ~7.9+.
  A code section with very high entropy hints at packing or encryption.

- **Overlay** — bytes appended after the last PE section. Installers, packers and self-extractors
  hide payloads there; in MinGW builds it's often just the COFF symbol table.
- **COFF symbol table** — the classic in-file list of symbol names + addresses (`objdump -t`).
- **Demangling** — turning `_ZN14veloren_common...` back into `veloren_common::comp::health::...` (`c++filt`).
- **`.pdata` / `.xdata`** — x64 exception/unwind tables. Dense address arrays -> high entropy that is *not* encryption.
- **ASLR** — Address Space Layout Randomization: the exe/DLLs load at a different address every run,
  so hard-coded addresses break. NX/DEP = data pages can't be executed.
- **XREF (cross-reference)** — in Ghidra/IDA, "who uses this string/function?". Find a string -> follow its XREFs -> land in the code.
- **False positive (heuristic)** — a detector flagging something that isn't there (DIE's "Packer: Generic" on Veloren).
  Anti-cheat faces the same problem: a false ban is worse than a missed cheat.

## Protection

- **Packer** — wraps an exe in a compressed/encrypted stub that unpacks at runtime (e.g. UPX).
- **Protector / virtualizer** — packers that also hide code by translating it into a custom
  bytecode run by an embedded VM (VMProtect, Themida). Makes static analysis much harder.
- **DRM** — copy protection (e.g. Denuvo, Steam DRM). Not the same as anti-cheat.
- **Anti-cheat** — software that detects/prevents tampering with a running game (EAC, BattlEye, Vanguard).
- **Mutation vs Virtualization vs Ultra** (VMProtect compilation types) — *Mutation* rewrites code into
  equivalent-but-messy **native** x86 (fast, weakest); *Virtualization* converts it to **bytecode for an embedded
  VM** (slow, strong); *Ultra* = mutate then virtualize (strongest).
- **VM dispatcher / handler / bytecode** — a virtualized function becomes an array of bytecode and a loop (the
  *dispatcher*) that reads each opcode and jumps to a small *handler* that performs it. Recovering the function =
  identifying the handlers and replaying the bytecode (**devirtualization**).
- **Packer stub / OEP** — a packer replaces the real entry with a *stub* that decrypts the image in memory, then
  jumps to the **OEP (Original Entry Point)** = where the real program starts. Static tools see only the stub.
- **Memory Protection (integrity CRC)** — the protector hashes its own code at runtime; any **byte patch** = CRC
  mismatch = it bails. Defeat by editing a **register/flag at runtime** (no bytes change) instead of patching.
- **Import Protection / IAT** — the Import Address Table is the list of DLL functions a PE uses. Protectors hide
  it and resolve imports in the stub, so the on-disk IAT is tiny; **Scylla** rebuilds it from a running process.
- **Watermark (demo)** — a nag messagebox/banner a trial protector injects (VMProtect Demo). Cosmetic, not a
  protection layer.

## Dynamic analysis / debugging / unpacking

- **Debugger (x64dbg)** — run a process one instruction at a time, set breakpoints, read/edit registers + memory.
  User-mode; our target's "Kernel" detection is about kernel debuggers, not x64dbg itself.
- **Anti-debug checks** — ways a program notices a debugger: **PEB `BeingDebugged`** and **`NtGlobalFlag`** (cheap
  flags), **`NtQueryInformationProcess`** (ProcessDebugPort/Flags), **`NtSetInformationThread` (HideFromDebugger)**,
  **`NtQuerySystemInformation` (KdDebuggerEnabled)** (kernel). Timing (`rdtsc`) is another.
- **ScyllaHide** — an x64dbg plugin that hooks those APIs so the checks read "no debugger". Needed before a
  protected binary will even run under the debugger.
- **Scylla** — dumps a running (unpacked) process image to disk and rebuilds its IAT (**IAT Autosearch → Get
  Imports → Dump → Fix Dump**), turning an in-memory unpacked program back into a static-analyzable `.exe`.
- **ZF (Zero Flag) / register edit** — flipping a CPU flag or register value live in the debugger to change a
  branch outcome, **without** modifying bytes (so integrity CRCs don't trip). The core C2 bypass move.
- **NoVmp / VTIL** — an (abandoned, 2021) automatic VMProtect **devirtualizer** for VMProtect x64 **3.0–3.5**
  (fork NoVmpy ≤3.6), needs an **unpacked** input. Does **not** handle modern versions (our target is 3.11).

## Unreal Engine

- **.pak / .utoc / .ucas** — UE asset containers. `.pak` is the classic format; `.utoc`/`.ucas`
  is IoStore (UE4.26+/UE5). Can be AES-encrypted and/or signed.
- **Shipping build** — UE's release configuration: no console, optimized, minimal logging.
  Development builds keep the console and lots of debug info.

## Game data

- **Data-driven design** — gameplay values (health, damage) live in data files, not code.
  Easy to balance; also easy to read and tamper with if shipped as plain text.
- **RON (Rusty Object Notation)** — the plain-text data format Veloren uses for its assets.

## Memory layout

- **Fixed-point** — storing a fractional number as an integer times a constant (Veloren: value ×256).
  100.0 HP is stored as `25600`. Fast integer math; also an accidental speed bump for memory scanners.
- **`#[repr(Rust)]`** — the default Rust struct layout: the compiler **reorders fields** to cut padding,
  so source order ≠ memory order. You must read offsets from the binary, not assume declaration order.
- **line-tables-only DWARF (`debug=1`)** — ships function names + source line mappings (for backtraces)
  but not struct field layouts. `gdb ptype` can't dump offsets; you recover them from source + disassembly.
- **Calling convention (Win64):** first arg in **RCX**. In a method, RCX = `&self`/`&mut self`, so
  `mov [rcx+0x50],...` is writing a field at offset 0x50 of the object.

- **Enum tag + payload** — a Rust/C++ tagged union is stored as a small *tag* (which variant) followed by
  that variant's data. `DamageSource::Buff(Bleeding)` = tag `0`, payload `0x22`. Rust's *niche optimisation*
  reuses impossible tag values to mean `None`, so `Option<T>` often costs no extra bytes.
- **Padding bytes** — gaps the compiler inserts for alignment. Their contents are leftover junk (Veloren
  byte `0x27` flips 00/40), so hashing or comparing whole structs byte-for-byte gives false mismatches.

## Game architecture

- **ECS (Entity-Component-System)** — entities are just IDs; data lives in per-type *component storages*
  (all `Health` values together, all `Position` values together); *systems* loop over them each tick.
  Veloren uses the `specs` library. Memory-hacking impact: no "Player object" to walk — you find the
  storage array and your entity's slot.
- **Event-driven damage** — attacks don't subtract health directly; they emit an event
  (`HealthChangeEvent`) that one system applies later. One choke point = one hook to catch all damage.

## Networking

- **Embedded / listen server** — the game server running inside the player's own process (Veloren
  single-player). Whoever runs the server is the authority, so offline, the player is.
- **Server authority** — the server owns the true game state; clients only send inputs/requests.
  The only defense that cannot be defeated by editing your own client.
- **TLS interception (MITM)** — a middlebox (e.g. corporate firewall) that decrypts HTTPS by
  presenting its own certificate. Certificate validation is what exposes it.
