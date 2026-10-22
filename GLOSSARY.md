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

## Protection

- **Packer** — wraps an exe in a compressed/encrypted stub that unpacks at runtime (e.g. UPX).
- **Protector / virtualizer** — packers that also hide code by translating it into a custom
  bytecode run by an embedded VM (VMProtect, Themida). Makes static analysis much harder.
- **DRM** — copy protection (e.g. Denuvo, Steam DRM). Not the same as anti-cheat.
- **Anti-cheat** — software that detects/prevents tampering with a running game (EAC, BattlEye, Vanguard).

## Unreal Engine

- **.pak / .utoc / .ucas** — UE asset containers. `.pak` is the classic format; `.utoc`/`.ucas`
  is IoStore (UE4.26+/UE5). Can be AES-encrypted and/or signed.
- **Shipping build** — UE's release configuration: no console, optimized, minimal logging.
  Development builds keep the console and lots of debug info.

## Game data

- **Data-driven design** — gameplay values (health, damage) live in data files, not code.
  Easy to balance; also easy to read and tamper with if shipped as plain text.
- **RON (Rusty Object Notation)** — the plain-text data format Veloren uses for its assets.

## Networking

- **Server authority** — the server owns the true game state; clients only send inputs/requests.
  The only defense that cannot be defeated by editing your own client.
- **TLS interception (MITM)** — a middlebox (e.g. corporate firewall) that decrypts HTTPS by
  presenting its own certificate. Certificate validation is what exposes it.
