# Benchmarking VMProtect 3.11 on Commercial & Open-Source Game Binaries: Target Selection, Dead Cells (GOG) Architecture, and Evaluation Methodology

**Document Version:** 2.0 (October 2026 — Analyzed & Expanded Edition)  
**Focus:** Ground-Truth Game Selection (VMProtect 3.8–3.11), *Dead Cells* (Haxe / HashLink JIT vs. HL/C) Binary Architecture, VMProtect 3.11 Maximum-Complexity Configuration, and Pre/Post-Protection Verification Protocols

---

> ## ⚠️ Scope & Authorization (GameSecLab hard rules — read first)
>
> This benchmark is **only** valid, and **only** performed in this lab, as a *controlled ground-truth* exercise:
>
> * **✅ Authorized targets:** binaries you wrote yourself, open-source binaries you build from source (DevilutionX, OpenMW, Veloren, a HashLink/C build of your own Haxe project), and **DRM-free** commercial binaries **you own** — each protected by **applying VMProtect 3.11 yourself**, then analyzed. This is the same pattern as the `license_app` capstone: you own both the clean and the protected binary, so you have ground truth.
> * **🚫 Out of scope — never:** defeating, unpacking, or circumventing the **shipping protection / DRM / anti-cheat of a third-party commercial product**. The live titles in §1.2 (Genshin, ZZZ, Hi-Fi RUSH, MapleStory/BlackCipher, Arknights/ACE, Witcher 3, etc.) are listed as **architectural context only** — to understand how VMProtect is deployed in the wild — **not** as things to attack. Attacking their protection or anti-cheat is prohibited regardless of framing.
> * **🔒 Dead Cells file-access rule:** the installed game lives in a restricted folder. Only `ModTools\` and `lang\` are accessible to the assistant. Any operation on `deadcells.exe`, `libhl.dll`, `res.pak`, saves or logs is delivered to **you** as a command to run in your own terminal — the assistant never reads or scans those files.
> * **Legitimacy note:** Dead Cells ships **official mod tools** (`ModTools\`, Steam Workshop `--workshop-test`) and is DRM-free on GOG, so *self-applying VMProtect to your own copy for local RE practice* carries no DRM-circumvention. Do not redistribute any protected build.

## 1. Target Selection Methodology: Wild Commercial Games vs. Controlled DRM-Free Benchmarks

When evaluating binary analysis frameworks (`Pushan`, `VMPredator`, `VMSpec`, and `vmp-lazy-unpack`) against **VMProtect 3.8 through 3.11**, researchers must avoid targets wrapped in multi-layered enterprise DRM (such as Denuvo Anti-Tamper) so that observed anti-analysis mechanics originate strictly from VMProtect.

### 1.1 VMProtect Version Timeline & Compilation Cutoffs

To confirm whether an existing commercial game executable uses VMProtect 3.8+ rather than legacy 2.x or early 3.x builds, cross-reference the PE header `TimeDateStamp` and packer signatures against the official VMProtect release schedule:

* **VMProtect 3.8.x:** Mid-2023 – July 2024 (`3.8.6` Dec 2023; `3.8.9` July 2024)
* **VMProtect 3.9.x:** August 2024 – June 2025 (`3.9.0` Aug 2024; `3.9.6` June 2025)
* **VMProtect 3.10.x:** September 2025 – June 2026 (`3.10.0` Sept 2025; `3.10.6` June 2026)
* **VMProtect 3.11:** reported October 2026 by the installed Ultimate demo (build 2835) used in this lab. **Verification caveat:** the latest version publicly confirmable at research time (2026-10-26) is **3.10.3 (Dec 11, 2025)** — `vmpsoft.com/news` is unreachable through the lab proxy (TLS-inspection cert), so the specific 3.11 feature list below (SSE `ORPD`/`ORPS` fixes, ARM64 `LDAPR*`, Rust SDK, whole-function symbol markers) is **unverified** and should be confirmed against the vendor changelog before being cited in a paper. Treat the version timeline dates as approximate.

### 1.2 Wild Commercial Games Protected by VMProtect 3.8–3.10.x (Zero Denuvo)

> **🚫 Context only — not authorized targets (see Scope banner).** This table documents *how VMProtect appears in the wild*; these are live third-party products and several carry kernel anti-cheat (MapleStory → BlackCipher, Arknights → ACE). **Do not** unpack, devirtualize, or otherwise attack their protection in this lab. **Also: the "VMProtect version window" claims below are unverified** — specific titles' use of VMProtect (e.g. Genshin, ZZZ) is community lore, not confirmed from primary sources; cite only after independent verification. Benchmarking happens exclusively on the controlled ground-truth targets in §1.3.

| Game Title | Genre | Engine / Architecture | VMProtect Version Window | Architectural Notes |
| :--- | :--- | :--- | :--- | :--- |
| **Zenless Zone Zero** *(HoYoverse — Steam Release June 2026 / Patch 2.5+)* | Action RPG | Unity IL2CPP (`ZenlessZoneZero.exe` / `UnityPlayer.dll` / `UserAssembly.dll`) | **VMP 3.9.x – 3.10.6+** | **No Denuvo.** Recompiled on a 6-week patch cadence. Virtualizes initialization, string/metadata decryption (`GetStringLiteralFromIndex`), and packet cryptography. |
| **Hi-Fi RUSH** *(Tango Gameworks / Krafton — Post-Dec 4, 2025 Patch 10)* | Rhythm Action Platformer | Unreal Engine 4 (Native x64 C++) | **VMP 3.9.x – 3.10.x** | **Denuvo removed in Patch 10 (Dec 4, 2025).** Retains VMProtect + SteamStub as its ceiling binary protection on current PC builds. |
| **Genshin Impact** *(5.x/6.x)* & **Honkai: Star Rail** *(3.x)* | Open-World / Turn-Based RPG | Unity IL2CPP (Native x64 C++ assemblies) | **VMP 3.9.x – 3.10.6+** | **No Denuvo.** Continuous live-service builds updated with modern VMProtect 3.x virtualization and custom IL2CPP metadata encryption. |
| **Arknights: Endfield** *(Hypergryph / Gryphline — 2026 Client)* | 3D Action RPG | Unity IL2CPP + ACE Modules | **VMP 3.10.x** | **No Denuvo.** Core security and anti-tamper modules compiled and packed with 2025–2026 VMProtect 3.10.x builds. |
| **MapleStory Worlds / MapleStory N** *(Nexon — 2025–2026 Clients)* | 2D Side-Scrolling MMORPG / Metroidvania-style | Native x64 Client + BlackCipher | **VMP 3.9.x – 3.10.x** | **No Denuvo.** Uses modern VMProtect 3.x virtualization across client protection modules. |

*(Note: Legacy RPGs such as **Dark Souls: Prepare to Die Edition** [2012] or **Tales of Symphonia** [2016] use older VMProtect 2.x/early 3.x builds and lack 3.8–3.11's MBA handler mutations and inline self-checksumming.)*

---

### 1.3 Controlled Ground-Truth Targets (DRM-Free Games + Self-Applied VMProtect 3.11)

Wild binaries lack un-obfuscated ground-truth executables and `.pdb` symbol files. Academic benchmarks (such as *Pushan* and *VMPredator*) therefore pair wild case studies with **controlled ground-truth binaries**: taking a 100% DRM-free game executable and protecting it directly with the **VMProtect Ultimate 3.11 Demo** (`08.10.2026` build).

#### Tier A: Open-Source Native RPGs (Full Source + `.pdb` Symbol Ground Truth)

1. **DevilutionX** *(Diablo 1 & Hellfire Source Port — 2D Isometric Action RPG)*:  
   * **Architecture:** Native x64 C++ (`devilutionx.exe` + `devilutionx.pdb`).  
   * **Research Advantage:** Fast compilation in Visual Studio 2022; allows direct insertion of `VMProtectBeginUltra` markers or `.pdb` whole-function selection on combat math, RNG seed propagation, and dungeon generation loops.
2. **OpenMW** *(The Elder Scrolls III: Morrowind Reimplementation — 3D Open-World RPG)*:  
   * **Architecture:** Native x64 C++20 (`openmw.exe` + `openmw.pdb`).  
   * **Research Advantage:** Heavy SSE/AVX floating-point physics and complex C++ vtable hierarchies ideal for benchmarking VMProtect 3.11's `ORPD`/`ORPS` SSE fixes and `.pdata` exception directories.
3. **Veloren** *(3D Voxel Action RPG)*:  
   * **Architecture:** Native x64 **Rust**.  
   * **Research Advantage:** Directly tests VMProtect 3.11's newly introduced **Rust SDK** and Rust symbol demangling.

#### Tier B: Commercial DRM-Free GOG Games (Pre-Compiled Native Binaries)

* **2D / 2.5D Metroidvanias:** *Dead Cells* (`deadcells.exe` + `libhl.dll`), *Bloodstained: Ritual of the Night* (`BloodstainedRotN-Win64-Shipping.exe`, Unreal Engine 4 x64 C++), *Ender Lilies: Quietus of the Knights* (Unreal Engine 4 x64 C++), and *Blasphemous 1 & 2* (Unity IL2CPP `GameAssembly.dll`).
* **3D Action RPGs & 3D Metroidvanias:** *Control: Ultimate Edition* (`Control_DX12.exe`, Remedy Northlight C++ Engine), *Ys VIII: Lacrimosa of DANA* / *Ys IX: Monstrum Nox* (`ys8.exe` / `ys9.exe`, custom C++ engine), and *The Witcher 3: Wild Hunt* (`witcher3.exe`, REDengine 3).

---

## 2. Deep-Dive Case Study: *Dead Cells* (GOG v35 Build) Architecture

### 2.1 What Is a "GOG Build" and Is the *Medley of Pain Bundle (v35)* DRM-Free?

**GOG (`gog.com`, formerly Good Old Games)** is a digital distribution storefront operated by CD Projekt with a strict **100% DRM-Free** mandate.

* Every official GOG release—including the **Dead Cells: Medley of Pain Bundle (Update v35 "The End is Near" + 5 DLCs)**—ships without SteamStub, without `steam_api64.dll` license callbacks, and without online activation checks.
* **Why GOG Installers Matter for Binary Research:** The GOG Offline Backup Installer extracts an unmodified Portable Executable (`.exe`) and Dynamic Link Library (`.dll`) layout directly from the studio's build pipeline. This provides an uncorrupted baseline Import Address Table (IAT), `.text` section, and `.pdata` unwind table prior to applying VMProtect 3.11.
* **Risk of Unofficial Third-Party Mirrors:** Downloading files from unofficial third-party mirrors or scene/warez sites risks introducing modified executables (e.g., Steam builds patched with custom API emulators, inline hooks, or malware injectors). Any prior tampering alters the IAT and section hashes, invalidating quantitative deobfuscation metrics.

### 2.2 Internal Engine Architecture of *Dead Cells* (HashLink JIT vs. HashLink/C)

Motion Twin developed *Dead Cells* in the **Haxe** programming language using the **Heaps.io** 2D/3D game engine targeting the **HashLink (`hl`)** virtual machine runtime.

Understanding how the retail *Dead Cells* installation directory is partitioned is critical before loading files into VMProtect 3.11:

| File Name | Typical Size | Binary Role & Internal Mechanics |
| :--- | :--- | :--- |
| **`deadcells.exe`** / **`deadcells_gl.exe`** | ~300 KB – 500 KB | **Native x64 Bootstrap Launcher:** Parses command-line arguments, initializes the OS window/context, loads `libhl.dll`, maps `hlboot.dat` into memory, and invokes the HashLink JIT entry point. |
| **`libhl.dll`** | ~400 KB – 800 KB | **HashLink Virtual Machine & x86_64 JIT Compiler (Native C):** Exports C runtime primitives (`hl_jit_init`, `hl_jit_function`, `hl_module_init`, garbage collector `hl_gc_*`, and type system handlers). At startup, `libhl.dll` compiles the Haxe bytecode in `hlboot.dat` into native x86_64 machine code inside dynamically allocated `RWX`/`RX` memory pages. |
| **`hlboot.dat`** | ~15 MB – 25 MB | **Compiled HashLink Bytecode Module:** Contains all high-level Haxe game classes, combat damage formulas, mob AI state machines, and level generation rules in HashLink intermediate bytecode format. |
| **`res.pak`** | ~1.5 GB+ | **Packed Asset Archive:** Sprites, audio, biome templates, and serialized entity data. |
| **`fmt.hdll`, `sdl.hdll`, `openal.hdll`** | ~100 KB – 1 MB each | **Native HashLink Plugins (DLLs):** Native C/C++ bindings for SDL2 windowing/input, OpenAL audio, and image/compression codecs (`png`, `ogg`, `zip`). |

> **⚠️ Correction for the actual installed build (from the user's own `ls`, 20-08-2024 build).** This build does **not** match the generic "300 KB bootstrap + separate `hlboot.dat`" layout above:
>
> | File | Actual size | Reality |
> | :--- | :--- | :--- |
> | `deadcells.exe` / `deadcells_gl.exe` | **~18 MB each** (18,080,256 / 18,074,112 B) | **Both thin launcher AND fat file:** the native code is only **~71 KB** (`.text` vsize `0x118B4`); the bulk is **`.rsrc` ~18 MB** (vsize `0x1128134`) holding the **embedded HashLink bytecode as a PE resource** (entropy 6.57 = stored unencrypted). The `_gl` variant is the OpenGL backend. |
> | `hlboot.dat` | **absent** | No standalone bytecode file in this build — consistent with embedded bytecode. |
> | `libhl.dll` | ~300 KB (300,544 B) | HashLink VM/JIT, as described. |
> | `res.pak` | **~2.07 GB** (2,071,694,886 B) | Packed assets (openable with the official `ModTools\PAKTool.exe`). |
> | `*.hdll` | `chroma, directx, discord, fmt, openal, sdl, ssl, ui, uv` | Native plugins present (incl. `ssl.hdll`, `discord.hdll`). |
>
> **Benchmark implication:** "Strategy 1 — protect `deadcells.exe`" no longer virtualizes only a 300 KB loader; it wraps an 18 MB binary that is *native launcher + embedded bytecode blob* (the bytecode is data, executed by `libhl.dll`'s JIT at runtime, so VMProtect virtualizes the **native** launcher/entry, not the Haxe game logic). For *deep game-function* devirtualization benchmarking, **Strategy 3 (HashLink/C → native `.exe`+`.pdb`)** remains the only route that puts `Player_takeDamage`-style logic into native x64 that VMProtect can virtualize by symbol — this mirrors the `license_app` capstone exactly. To confirm the embedded-bytecode claim without the assistant touching the file, **you** can run the header check in §7.4.

### 2.3 Three Benchmarking Strategies for *Dead Cells* in VMProtect 3.11

Because the retail build of *Dead Cells* uses **HashLink/JIT** (`deadcells.exe` + `libhl.dll` + `hlboot.dat`), protecting only `deadcells.exe` only virtualizes the 300 KB bootstrap loader. To benchmark both **Full-Binary Unpacking** and **Deep Function Devirtualization**, use one of the following three configurations:

1. **Strategy 1 — Dual-Binary Retail Protection (`deadcells.exe` + `libhl.dll`):**
   * Pack and virtualize `deadcells.exe` (to evaluate PE unpacking, `EntryPoint` virtualization, and IAT reconstruction).
   * Simultaneously protect `libhl.dll` in VMProtect 3.11 by applying **Ultra (Mutation + Virtualization)** to core exported C functions inside the JIT compiler and evaluator (such as `hl_jit_function`, `hl_hash`, `hl_rnd_next`, and memory allocator routines) plus packing `libhl.dll`.
2. **Strategy 2 — Native `.hdll` Plugin Math Virtualization (`fmt.hdll` / `sdl.hdll`):**
   * Protect specific cryptographic, hashing, compression, or math routines exported by `.hdll` native plugins (`fmt.hdll`), which are pure C/x64 DLLs with clean export tables (`EAT`).
3. **Strategy 3 — Monolithic Native Compilation via HashLink/C (`hl/c` + `.pdb`):**
   * HashLink natively supports transpiling Haxe bytecode into pure C source code (`haxe -hl out/main.c`). Compiling a Haxe/Heaps project via **HashLink/C** in Visual Studio 2022 (`Release` with `/Zi` PDB generation) eliminates `hlboot.dat` and the JIT altogether, producing a **single monolithic native x64 `.exe` and `.pdb` symbol file** where every game function (`Player_takeDamage`, `Level_generate`) is native x86_64 machine code selectable by name in VMProtect 3.11.

---

## 3. Configuring VMProtect 3.11 for a Maximum-Complexity Benchmark

To stress-test academic deobfuscation pipelines across all defense layers simultaneously, configure the target binary in **VMProtect Ultimate 3.11** (`GUI` or `VMProtect_Con.exe`) using the two-layer profile below.

### 3.1 Layer A: Deep Function Virtualization (`Ultra` Mode)

1. **Load Binary & Symbols:** Place the target `.exe`/`.dll` and its `.pdb` or `.map` file in the same folder so VMProtect 3.11 automatically resolves symbol names, or select exported/internal subroutines via VMProtect's built-in disassembler.
2. **Select Benchmark Functions (`Functions for Protection`):**
   * **`EntryPoint`:** Always add `EntryPoint` to the protected functions list. When `EntryPoint` is virtualized alongside file packing, the unpacking stub in `.vmp1` never executes a clean tail-jump (`JMP OEP`) back to `.text`; instead, it transitions directly from the unpacking VM context into the virtualized `EntryPoint` bytecode stream inside `.vmp0`.
   * **Branch-Dense Functions (CFG & Opaque Predicate Stress Test):** Select 3–5 functions with nested switches, loops, and conditional state transitions to test VPC-sensitive CFG recovery (`Pushan`).
   * **Arithmetic/Bitwise-Dense Functions (MBA & SSE Stress Test):** Select 3–5 functions performing hash mixing, PRNG updates, CRC checks, or SIMD vector math (`ORPS`/`ORPD`/`ADDPS`) to trigger `vNAND`/`vNOR` reduction and Mixed Boolean-Arithmetic (MBA) expansion.
3. **Set Compilation Type to `Ultra (Mutation + Virtualization)`:**
   * `Mutation` alone only obfuscates native x64 instructions in place.
   * `Virtualization` alone lifts clean native x64 instructions directly to VM bytecode.
   * **`Ultra`** runs the architectural mutation pass *first* (injecting junk instructions, dead branches, and polynomial/semi-linear MBA rewrites) and then compiles that mutated stream into threaded VM bytecode with rolling decryption keys.
   * Leave **Lock to Key** set to `No` unless explicitly testing VMProtect's RSA licensing engine.

### 3.2 Layer B: Full-Binary Packing, IAT Stripping & Anti-Analysis Options

| Option Category | Parameter | Benchmark Setting | Low-Level Architectural Effect in VMProtect 3.11 |
| :--- | :--- | :--- | :--- |
| **File** | `Memory Protection` | **Yes** | Protects non-writable PE sections (`.text`, `.rdata`, `.vmp0`) against runtime modification. Interleaves memory-read handlers into the virtual bytecode stream that fold 4/8-byte code chunks directly into the **Rolling Key Register** (`Key_{i+1} = Key_i ^ CRC(Chunk)`). |
| **File** | `Import Protection` | **Yes** | Strips the original Import Address Table (IAT) and replaces `CALL [IAT]` / `JMP [IAT]` sites with obfuscated trampolines entering `.vmp0`/`.vmp1` that resolve exports dynamically without plaintext DLL/API strings. |
| **File** | `Resource Protection` | **Yes** | Encrypts non-mandatory PE resources (preserving only OS shell icons and manifests) and decrypts them in memory during initialization. |
| **File** | `Pack the Output File` | **Yes** | Compresses and encrypts the original PE sections, replacing the initial loader sequence with a virtualized unpacking stub that maps a fresh view of `\KnownDlls\ntdll.dll` via `NtOpenSection`/`NtMapViewOfSection` to execute direct kernel syscalls. |
| **Detection** | `Debugger` | **User-mode + Kernel-mode** | Enables direct reads of `KUSER_SHARED_DATA` (`0x7FFE02D4`), direct syscalls (`NtQueryInformationProcess` for `ProcessDebugPort`/`ProcessDebugObjectHandle`, `NtQuerySystemInformation` for `SystemKernelDebuggerInformation`, `NtSetInformationThread` with `ThreadHideFromDebugger`), and deliberate `CloseHandle`/`NtClose` exceptions to scrub `DR0–DR7` in SEH/unwind handlers. |
| **Detection** | `Virtualization Tools` | **Yes** | Inserts virtualized `CPUID` (Leaf `0x1` Hypervisor Present bit and Leaf `0x40000000`) and `RDTSC` time-delta profiling across handler chains to detect VMware, VirtualBox, QEMU, and Sandboxie. |
| **Additional** | `Strip Debug Information` | **Yes** | Strips `IMAGE_DIRECTORY_ENTRY_DEBUG` and symbol strings from the packed output binary. |
| **Additional** | `Strip Relocations` | **No** *(for ASLR x64 PEs)* | Keep relocations intact on modern `.dll` and ASLR `.exe` targets so Windows can relocate the image without loading errors. |

### 3.3 Reproducible `.vmp` Project Configuration Template (XML)

For automated batch benchmarking with `VMProtect_Con.exe`, save the following project schema as `deadcells_benchmark.vmp` alongside your target binary:

~~~xml
<?xml version="1.0" encoding="UTF-8" ?>
<Document Version="2">
    <Protection InputFileName="deadcells.exe" Options="926328" VMCodeSectionName=".vmp">
        <Messages/>
        <Folders/>
        <Procedures>
            <!-- Virtualize EntryPoint with Ultra (CompilationType="2") -->
            <Procedure CompilationType="2" MapAddress="EntryPoint" Options="1"/>
            <!-- Add target internal/exported functions by symbol name or RVA -->
            <Procedure CompilationType="2" MapAddress="hl_hash" Options="1"/>
            <Procedure CompilationType="2" MapAddress="hl_rnd_next" Options="1"/>
        </Procedures>
        <Objects/>
    </Protection>
    <DLLBox/>
    <Script/>
    <LicenseManager/>
</Document>
~~~

Run via command line:

~~~bash
VMProtect_Con.exe deadcells.exe deadcells_vmp311.exe -pf deadcells_benchmark.vmp
~~~

---

## 4. Verification Protocol: How to Verify If a Binary Is DRM-Free (Pre-Test) & Properly Protected (Post-Test)

Before running a downloaded game binary in your research environment—and after packing it with VMProtect 3.11—use this 4-step verification workflow.

### Step 1: Public Database Verification (`PCGamingWiki`)

1. Search the target title on **PCGamingWiki**.
2. Inspect the **Availability** table: confirm whether the GOG / Steam / Epic build lists **DRM-free: Yes** or flags third-party layers (`SteamStub`, `Denuvo`, `VMProtect`, `EOS`).

### Step 2: Static Signature & Entropy Analysis (`Detect It Easy` / `DIE v3.10+`)

Drag and drop `deadcells.exe` and `libhl.dll` into **Detect It Easy (DIE)**:

* **Clean DRM-Free Baseline:**
  * **Compiler Detection:** Displays standard compiler toolchains (`Microsoft Visual C/C++ (2019/2022)` or `MinGW/GCC`) and standard linker versions.
  * **Section Table:** Shows standard PE sections (`.text`, `.rdata`, `.data`, `.pdata`, `.rsrc`, `.reloc`) with normal code entropy (`~6.0 – 6.6` bits/byte in `.text`).
  * **Import Table (`Imports`):** Clearly lists plaintext Win32/CRT imports (`KERNEL32.dll`, `USER32.dll`, `VCRUNTIME140.dll`, `libhl.dll`).
* **If Third-Party DRM Is Present:**
  * **SteamStub:** Flags `Packer: Steam Stub` or contains a `.bind` section alongside `steam_api64.dll` imports.
  * **VMProtect 3.8–3.11 (Post-Protection Verification):** Flags `Protector: VMProtect (3.8-3.10+)[new 14 jmp 4]`, shows newly appended `.vmp0` and `.vmp1` sections with high packed entropy (`> 7.8` bits/byte), and shows a stripped/minimal IAT.

### Step 3: Command-Line PE Header & Import Inspection (`dumpbin`)

Run Visual Studio's `dumpbin` utility to record ground-truth structural metrics before and after applying VMProtect 3.11:

~~~bash
# Record ground-truth section layout, entry point RVA, and imports
dumpbin /headers /imports deadcells_clean.exe > baseline_pe_metrics.txt

# Compare against VMProtect 3.11 output
dumpbin /headers /imports deadcells_vmp311.exe > protected_pe_metrics.txt
~~~

### Step 4: Air-Gapped Runtime Execution Check

1. Disconnect the test VM or host machine from all network interfaces.
2. Execute `deadcells.exe` directly from the installation directory (without GOG Galaxy, Steam, or Epic running in the background).
3. A genuine DRM-free build initializes `libhl.dll`, parses `hlboot.dat`, and enters the main menu with zero network socket attempts or launcher IPC calls.

---

## 5. Quantitative Academic Evaluation Metrics for Your Research Paper

Because you possess both `deadcells_clean.exe` (or `libhl_clean.dll`) and `deadcells_vmp311.exe`, you can compute four rigorous benchmarks in your paper:

1. **Unpacking & IAT Reconstruction Fidelity (`vmp-lazy-unpack` Benchmark):**
   * Compare the reconstructed Import Address Table against `baseline_pe_metrics.txt`:
     `IAT_Recall = (Correctly Resolved Thunks) / (Total Ground-Truth Imports)`
2. **CFG Node & Edge Recovery Accuracy (`Pushan` Benchmark):**
   * For each Ultra-virtualized function `f`, compare the lifted Control Flow Graph `G_lifted = (V_l, E_l)` against the ground-truth native CFG `G_true = (V_t, E_t)` extracted from the clean binary / `.pdb`:
     `Edge_Precision = |E_l intersect E_t| / |E_l|`, `Edge_Recall = |E_l intersect E_t| / |E_t|`
3. **Trace / Instruction Length Reduction Ratio (`VMPredator` Benchmark):**
   * Measure the reduction from raw dynamic/symbolic VM instruction count `N_vm` to extracted semantic IR instructions `N_lifted` relative to original native instructions `N_native`:
     `Reduction_Ratio = 1 - (N_lifted / N_vm)`
4. **Formal Bit-Vector Semantic Equivalence (`Z3` / `Simplifier` / `ProMBA` Verification):**
   * For each basic block, assert `Phi_lifted(X) != Phi_ground_truth(X)` in Z3 over 64-bit bit-vectors (`BitVec(64)`). An `unsat` result mathematically proves 100% soundness of the deobfuscated block.

---

## 6. Verified Links & Research Resources

### Official Game & Engine Sources

* **Dead Cells Official Store Page on GOG (100% DRM-Free):**  
  [https://www.gog.com/en/game/dead_cells](https://www.gog.com/en/game/dead_cells)
* **Dead Cells: Medley of Pain Bundle on GOG (v35 + 5 DLCs, DRM-Free):**  
  [https://www.gog.com/en/game/dead_cells_medley_of_pain_bundle](https://www.gog.com/en/game/dead_cells_medley_of_pain_bundle)
* **Dead Cells Technical & DRM Entry on PCGamingWiki:**  
  [https://www.pcgamingwiki.com/wiki/Dead_Cells](https://www.pcgamingwiki.com/wiki/Dead_Cells)
* **HashLink Virtual Machine & `hl/c` Compiler Repository (Haxe Foundation):**  
  [https://github.com/HaxeFoundation/hashlink](https://github.com/HaxeFoundation/hashlink)
* **Heaps.io Game Engine Repository (Used by *Dead Cells*):**  
  [https://github.com/HeapsIO/heaps](https://github.com/HeapsIO/heaps)

### Open-Source Ground-Truth RPG Repositories (For `.pdb` Symbol Benchmarking)

* **DevilutionX (Diablo 1 & Hellfire Native C++ Source Port):**  
  [https://github.com/diasurgical/DevilutionX](https://github.com/diasurgical/DevilutionX)
* **OpenMW (Morrowind Native C++20 Engine):**  
  [https://github.com/OpenMW/openmw](https://github.com/OpenMW/openmw)
* **Veloren (3D Action RPG in Native Rust — Tests VMP 3.11 Rust SDK):**  
  [https://github.com/veloren/veloren](https://github.com/veloren/veloren)

### Binary Inspection, Unpacking & Protection Tools

* **Detect It Easy (DIE — Packer, Compiler & `.vmp` Signature Scanner):**  
  [https://github.com/horsicq/Detect-It-Easy](https://github.com/horsicq/Detect-It-Easy)
* **VMProtect 3.11 Official Changelog & Demo Downloads (`08.10.2026`):**  
  [https://vmpsoft.com/news/](https://vmpsoft.com/news/)  
  [https://vmpsoft.com/products/matrix/](https://vmpsoft.com/products/matrix/)
* **`vmp-lazy-unpack` (Unicorn Emulation Unpacker & IAT Reconstructor for VMP 3.11):**  
  [https://github.com/x86rc/vmp-lazy-unpack](https://github.com/x86rc/vmp-lazy-unpack)
* **PCGamingWiki DRM-Free Games Master Database:**  
  [https://www.pcgamingwiki.com/wiki/The_big_list_of_DRM-free_games_on_GOG.com](https://www.pcgamingwiki.com/wiki/The_big_list_of_DRM-free_games_on_GOG.com)

---

## 7. GameSecLab Integration — what we can actually run, and how (2026-10-26)

### 7.1 Mapping §5's metrics onto the tooling we already built

The abstract metrics in §5 are not hypothetical for us — the `license_app` capstone already produced each one; this benchmark just scales them to larger targets:

| §5 metric | Our existing implementation | Status |
| :--- | :--- | :--- |
| IAT reconstruction fidelity | `vmp-lazy-unpack` env + `reaforge/devirt/devirt_oep.py` (reaches OEP, 122-entry IAT recovered on `license_app_c2`) | working |
| CFG node/edge recovery | per-function VM emulation trace (Capstone) in `devirt_oep.py` | working (single-function) |
| Trace→IR reduction ratio | symbolic taint engine `devirt_formula.py` (206k VM instrs → 63-node `want`) | working |
| **Formal bit-vector equivalence** | `reaforge/devirt/demba_rounds.py` — per-round z3 proofs + all-inputs Proof B; `demba_gamba.py` cross-check | working (the §5.4 `unsat` test, done for all 2³² inputs) |

So the honest benchmark contribution we can make: run this pipeline on a **larger, self-protected ground-truth** binary and report the four numbers against real `.pdb` ground truth.

### 7.2 Baseline pre-protection scan (confirmed, user-run 2026-10-26)

PE section/entropy scan of the installed build (user ran it; assistant did not touch the files): **CLEAN — no packer/DRM.** `deadcells.exe` → 5 standard sections (`.text` entropy 6.35 / EntryPoint in `.text`; `.rsrc` ~18 MB @ 6.57 = embedded HL bytecode, unencrypted), no `.vmp*`. `libhl.dll` → 6 standard sections, `.text` 6.53, EntryPoint in `.text`. No section entropy near the >7.8 packing threshold. **This is the valid ground-truth baseline** to protect and then analyze.

### 7.3 Repos pulled & link status

* **Cloned OK** → `C:\Tools\_downloads\research\game-bench\`: `HaxeFoundation/hashlink` (VM/JIT + the HL/C backend for Strategy 3), `diasurgical/DevilutionX` (lightest clean C++ ground truth — recommended first scaled target).
* **Already present** → `C:\Tools\_downloads\research\vmp-lazy-unpack`, and the MBA simplifiers under `C:\Tools\_downloads\research\mba-tools\` (GAMBA/SiMBA/Simplifier/ProMBA/MSiMBA/msynth) for the §5.4 equivalence layer.
* **Verify-before-citing:** `vmpsoft.com/news` (unreachable via lab proxy — TLS inspection), the GOG store/bundle pages, and PCGamingWiki were **not** machine-verified here; confirm manually. OpenMW/Veloren/Heaps/DIE not cloned (large / GUI release binaries) — pull on demand.

### 7.4 Commands for **you** to run on the restricted Dead Cells files

Per the access rule, the assistant will not read `deadcells.exe` / `libhl.dll` / `res.pak`. Run these yourself from the Dead Cells directory and paste back only what you're comfortable sharing (redact anything sensitive):

Confirm the HashLink bytecode is embedded in the exe (looks for the `HLB` module magic):

```bash
powershell -NoProfile -Command "$b=[IO.File]::ReadAllBytes('deadcells.exe'); $m=[Text.Encoding]::ASCII.GetBytes('HLB'); for($i=0;$i -lt $b.Length-3;$i++){ if($b[$i]-eq$m[0]-and$b[$i+1]-eq$m[1]-and$b[$i+2]-eq$m[2]){ 'HLB magic at offset 0x{0:X}' -f $i; break } }"
```

Static DRM / packer / compiler check (needs Detect It Easy — `diec` CLI from horsicq/Detect-It-Easy):

```bash
diec deadcells.exe
diec libhl.dll
```

Ground-truth PE metrics before any VMProtect pass (needs VS `dumpbin`):

```bash
dumpbin /headers /imports libhl.dll > C:\Tools\GameSecLab\capstone\deadcells_libhl_baseline.txt
```

Unpack assets with the **official** tool (sanctioned modding, not DRM circumvention):

```bash
ModTools\PAKTool.exe
```

### 7.5 CHOSEN target & proceed path (Dead Cells)

Baseline confirmed clean (§7.2). The chosen benchmark target is **`libhl.dll` → `hl_hash_utf8`**, because we have its **exact C source as ground truth** from the cloned `HaxeFoundation/hashlink` (`src/std/obj.c:90`):

```c
HL_PRIM int hl_hash_utf8( const char *name ) {   // exported (HL_API) from libhl.dll
    int h = 0;
    while( *name ) { h = 223 * h + (unsigned)*name; name++; }   // 32-bit wrap
    h %= 0x1FFFFF7B;                                            // signed mod by 536870779
    return h;
}
```

This is a self-contained arithmetic hash (multiply-accumulate by 223 + a non-power-of-2 modulo) — the same shape as the `license_app` capstone, but inside a real shipping game library. The multiply and the `% 0x1FFFFF7B` will generate rich VMProtect MBA, exercising the full de-MBA pipeline, and equivalence is checkable against the source above. (`hl_hash_gen` is the same core plus a cache lookup — messier; `hl_hash_utf8` is the clean pure-arithmetic variant. Confirm the constants match your Aug-2024 build, though this hash has been stable for years.)

**Packing step (your VMProtect 3.11 GUI — lab division of labor):**

* Load `libhl.dll` (+ `.map`/exports auto-resolve).
* `Functions for Protection`: add exports **`hl_hash_utf8`** (primary) and optionally `hl_hash_gen`, `hl_hash`.
* Compilation type **Ultra (Mutation + Virtualization)**; **Lock to Key = No**.
* File options: Pack output, Memory Protection, Import Protection, Resource Protection = Yes; Detection: Debugger = User+Kernel, Virtualization Tools = Yes; Strip Debug Info = Yes; Strip Relocations = No (DLL).
* Output `libhl_vmp311.dll`; keep the clean `libhl.dll` as ground truth.

**Then (assistant):** run `vmp-lazy-unpack` + `reaforge/devirt/devirt_oep.py` to reach/execute the protected export, `devirt_formula.py` + `demba_rounds.py` to recover `hl_hash_utf8`'s formula and SMT-prove it against the source, and report the four §5 metrics. Optional secondary pass: pack `deadcells.exe` itself to benchmark PE unpacking / IAT reconstruction / `.rsrc`-bytecode handling.

### 7.6 Execution RESULT — devirtualizer validated on the real shipping DLL ✅

The user packed `libhl.dll` → `libhl.vmp.dll` (VMProtect 3.11 Ultra + pack; confirmed: `.vmp0/.vmp1/.vmp2`, entry in `.vmp2`, `.vmp2` entropy 7.90, `.text` raw stripped). Driver `reaforge/devirt/devirt_dll32.py` (built on `vmp-lazy-unpack`, 32-bit) reaches the unpacked state and cold-calls the virtualized `hl_hash_utf8`:

```text
== devirtualizer validation battery (virtualized hl_hash_utf8 vs HashLink source) ==
  b''              VM=0x00000000  src=0x00000000  PASS
  b'a'             VM=0x00000061  src=0x00000061  PASS
  b'Player'        VM=0x0C4D6110  src=0x0C4D6110  PASS
  b'takeDamage'    VM=0xF1BDAB0C  src=0xF1BDAB0C  PASS
  b'__string'      VM=0xF95F92E7  src=0xF95F92E7  PASS
  b'value'         VM=0x11B87FF6  src=0x11B87FF6  PASS
  b'Dead Cells'    VM=0xF9DF2D90  src=0xF9DF2D90  PASS
  b'BiomeLevelGen' VM=0xECA8738C  src=0xECA8738C  PASS
ALL PASS -- the VM reproduces hl_hash_utf8 exactly on a real shipping VMProtect 3.11 game DLL.
```

**32-bit port obstacles solved** (the x64 `license_app` pipeline was x64-only):

1. **Api-set imports** — `libhl` imports `api-ms-win-crt-*` / `-core-*` API-set DLLs absent from the catalog; VMProtect's Import Protection re-resolves the full set during unpack, so dropping them faults. Fix: synthesize each module's real export-name pool from `ucrtbase`/`kernelbase`/`kernel32` in `SysWOW64` (a superset).
2. **DllMain entry** — a DLL needs the 32-bit `DllMain(hinst, DLL_PROCESS_ATTACH, 0)` `stdcall` frame or the unpacker returns into garbage.
3. **`VirtualQuery`** — not in the kit's handler table (it has `NtQueryVirtualMemory`); added one built on the kit's `memory_basic_information`.
4. **`RtlUnwind` — the key blocker** — DllMain/CRT init stalls on it, leaving a VM-context table slot uninitialized (the VM then dereferenced a near-NULL `0x1C`; proven to be VM-context, not arg-passing, via a shotgun test). Stubbing it let the unpacker reach `emulation_reached_unpacked_entry` (451 pages of `.vmp0` restored) and the VM-context table fully populate.
5. **Iteration speed** — a post-unpack memory snapshot (`FAST=1`) reloads in seconds instead of re-running ~200M emulated instructions.

**Benchmark meaning:** this is §5-metric *functional/semantic fidelity* — our devirtualizer faithfully executes a VMProtect 3.11-virtualized function inside a real commercial game's runtime and matches the independent source ground truth on every input. The **all-inputs formal proof** (§5.4) is the open extension: it needs the taint-symbolic engine (`devirt_formula.py`/`demba_rounds.py`) ported from x64 to x86-32 — the same engine that proved the `license_app` formula for all 2³² inputs.

Run: `cd C:\Tools\_downloads\research\vmp-lazy-unpack && python reaforge\devirt\devirt_dll32.py C:\Tools\GameSecLab\capstone\libhl.vmp.dll` (first run unpacks + snapshots; add `FAST=1` after).

### 7.7 Phase 2 — all-inputs formal proof (x86-32 taint-symbolic engine) ✅ PROVEN

`reaforge/devirt/devirt_formula32.py` ports the x64 taint-symbolic engine to x86-32 (32-bit register aliasing, 4-byte `push`/`pop`, 1-operand `mul`/`imul` → `EDX:EAX`, full symbolic EFLAGS). Reusing the FAST post-unpack snapshot, it symbolizes an N-byte input, propagates claripy expressions through the VMProtect VM along the single concrete path, reads the symbolic output `h_out(b0..b_{N-1})`, and SMT-proves it against the closed form:

```text
probe b'Play'              h_out=0x15335A99  ref=0x15335A99  ok
probe b'\x01\x02\x03\x04'  h_out=0x00AABDC2  ref=0x00AABDC2  ok
probe b'\xff\xff\xff\xff'  h_out=0xFF560640  ref=0xFF560640  ok
probe b'\x01\x00\x00\x00'  h_out=0x00A9369F  ref=0x00A9369F  ok
[Proof] h_out == fold for ALL 2^32 inputs?
  >>> UNSAT  ==>  PROVEN: virtualized hl_hash_utf8 == h=0; for c in bytes[:4]: h=223*h+c; h %= 0x1FFFFF7B
```

This is §5-metric **formal bit-vector equivalence (§5.4)** achieved on the real shipping VMProtect 3.11 function — the concrete 8/8 validation is now a *universal* guarantee for 4-byte inputs (z3 UNSAT over all 2³²). The per-byte round is uniform, so the recurrence generalizes to any length (raise `N` to extend the proof; the div/mod makes larger `N` progressively harder for z3).

**Semantics the symbolic recovery corrected:** `(unsigned)*name` **sign-extends** the signed `char` before the unsigned cast, so byte `0xFF` contributes `0xFFFFFFFF` (not `0xFF`) — invisible to ASCII-only testing; and the final `h %= 0x1FFFFF7B` is a **signed/truncated** modulo (`z3.SRem`). The devirtualizer recovered the true semantics, not the naive source reading. (This mirrors the x64 `license_app` campaign, whose formula was likewise recovered + proved; see `reaforge/devirt/README.md`.)

Run: `cd C:\Tools\_downloads\research\vmp-lazy-unpack && FAST=1 python reaforge\devirt\devirt_formula32.py C:\Tools\GameSecLab\capstone\libhl.vmp.dll 4`
