# Architectural Analysis & Academic Deobfuscation of VMProtect 3.11 (2026)

**Document Version:** 1.0 (October 2026)  
**Focus:** Virtualization Architecture, Anti-Tampering, Anti-Debugging, and State-of-the-Art Deobfuscation Methodologies (`Pushan`, `VMPredator`, `VMSpec`)

---

## 1. Executive Summary & Version Context

**VMProtect 3.11** (released October 8, 2026) represents the current iteration of commercial stack-machine virtualization and binary protection. Building upon the 3.10.x architectural branch, VMProtect 3.11 introduces:

* **Intel x86/x86_64 Fixes:** Corrected virtualization semantics for SSE packed floating-point bitwise instructions (`ORPD` and `ORPS`).
* **ARM64 Virtualization Expansion:** Native virtualization support for acquire-release atomic loads (`LDAPR`, `LDAPRB`, `LDAPRH`, `LDAPUR`, `LDAPURB`, `LDAPURH`), complementing 3.10.x's Pointer Authentication (`PACI*`, `AUTI*`, `RETA*`) and atomic memory operations (`LDADD*`, `SWP*`).
* **Whole-Function Symbol Markers (3.10.6+ / 3.11):** Support for whole-function protection markers (`VMProtectFunction`, `VMProtectFunctionVirtualization`, `VMProtectFunctionMutation`, `VMProtectFunctionUltra`, `VMProtectFunctionVirtualizationLockByKey`, and `VMProtectFunctionUltraLockByKey`) driven via PDB, DWARF, and MAP debug symbol parsing.
* **Platform & Runtime Updates:** Added Rust SDK bindings, improved .NET WPF and `Span` protection, and added macOS 27 ("Golden Gate") Mach-O `LC_ROUTINES` / `LC_ROUTINES64` support.

---

## 2. Core Virtualization & Stream Architecture

VMProtect 3.11 translates native x86/x64/ARM64 instructions into a proprietary, polymorphic, stack-based RISC bytecode executed by an embedded virtual machine.

### 2.1 Threaded Dispatch & Elimination of the Central Loop

Unlike classical virtual machines (and early VMProtect 1.x/2.x builds) that rely on a centralized `Decode -> Dispatch -> Execute` loop node, VMProtect 3.11 uses **direct threaded dispatch**:

* Every virtual instruction handler concludes with its own inline decryption logic that computes the next handler's entry address and transfers control via an indirect branch (`JMP REG` or `RET`).
* Handlers are heavily duplicated, mutated, and inlined across `.vmp0` and `.vmp1`, eliminating high-in-degree dispatcher nodes in the Control Flow Graph (CFG).

### 2.2 Execution-Dependent Rolling Decryption Keys

The Virtual Program Counter (`VPC`, mapped dynamically to a native general-purpose register such as `RSI`, `RDI`, or `RBP`) fetches encrypted bytecode tokens of variable width (1, 2, 4, or 8 bytes).

* A dedicated **Rolling Key Register** ($K$) is updated upon every bytecode fetch using non-linear bit-vector transformations:
  $$K_{i+1} = f(K_i, \text{RawBytecode}_i)$$
  where $f$ composes unary and binary mutations (`XOR`, `ADD`, `SUB`, `NEG`, `NOT`, `ROR`/`ROL`, `BSWAP`).
* The decoded operand or handler index $O_i$ is derived as:
  $$O_i = g(\text{RawBytecode}_i, K_i)$$
* **Analytical Consequence:** Because $K_{i+1}$ is strictly history-dependent across all prior fetches in the basic block, static disassembly at an arbitrary bytecode offset is infeasible without executing or symbolically emulating the exact predecessor path.

### 2.3 Virtual Context & Dynamic `VREGISTERS` Relocation

* VMProtect maintains a Virtual Stack Pointer (`VSP`) and a scratch area of Virtual Registers (`VREGISTERS[0..N]`) allocated within the native stack frame.
* **Dynamic Context Relocation:** When `VSP` pushes approach within a fixed safety threshold (typically `0x140` bytes) of the `VREGISTERS` array base, the VM executes an internal relocation handler that copies the entire virtual register bank to a lower stack address. This invalidates static memory-offset assumptions and naive hardware read/write watchpoints.

### 2.4 Universal `vNAND`/`vNOR` Reduction & Mixed Boolean-Arithmetic (MBA)

* Standard arithmetic and bitwise instructions (`ADD`, `SUB`, `XOR`, `AND`, `OR`) are synthesized from functionally complete primitives (`vNAND` or `vNOR`).
* When compiled with **Ultra (Mutation + Virtualization)** protection, handlers interleave **polynomial and linear Mixed Boolean-Arithmetic (MBA)** identities—for example, expanding bitwise addition into:
  $$x + y \equiv (x \oplus y) + 2 \cdot (x \land y) \equiv (x \lor y) + (x \land y)$$
  This inflates the Abstract Syntax Tree (AST) depth of symbolic expressions and degrades off-the-shelf SMT solver performance.

---

## 3. Anti-Tampering & User-Mode Evasion Mechanics

| Mechanism | Architectural Implementation in VMProtect 3.11 | Analytical Impact |
| :--- | :--- | :--- |
| **Clean `ntdll.dll` Mapping & Direct Syscalls** | Uses `NtOpenSection` (`\KnownDlls\ntdll.dll`) or `NtOpenFile` (`\SystemRoot\System32\ntdll.dll`) + `NtMapViewOfSection` to map an unhooked view of `ntdll.dll`. Parses the Export Address Table (EAT) to extract System Service Numbers (SSNs) and executes raw `syscall` instructions directly from `.vmp` sections. | Bypasses user-mode API hooks placed by sandboxes, EDRs, or dynamic analysis frameworks in the default loaded `ntdll.dll` / `kernelbase.dll`. |
| **`VirtualProtect` & Prologue Validation** | Inspects the entry prologues of `kernelbase!VirtualProtect` and `ntdll!NtProtectVirtualMemory` for inline trampoline patches (`0xE9`, `0xFF 0x25`) or software breakpoints (`0xCC`). | Detects user-mode hooking frameworks (e.g., MinHook, Detours, Frida) attempting to intercept memory permission transitions. |
| **Interleaved Bytecode Self-Checksumming** | Rather than spawning an easily suspended background CRC thread, VMP weaves memory-read handlers directly into the virtualized instruction stream. These handlers read 4- to 8-byte chunks of `.text`, `.vmp0`, and `.vmp1` and fold the raw bytes into the **Rolling Key Register** ($K_{i+1} = K_i \oplus \text{CRC}(\text{Chunk})$). | Any inline patch or `0xCC` software breakpoint silently corrupts the rolling decryption key, causing an indirect jump to an invalid address hundreds of instructions later (delayed crash without an explicit error string). |
| **Section Permission Auditing** | Invokes `NtQueryVirtualMemory` (`MemoryBasicInformation`) via direct syscall to verify that code sections retain expected page permissions (e.g., `PAGE_EXECUTE_READ` rather than `PAGE_EXECUTE_READWRITE`). | Detects naive dumpers or unpackers that globally mark sections `RWX`. |

---

## 4. Anti-Debugging & Environmental Profiling

1. **`KUSER_SHARED_DATA` Direct Memory Reads:**
   * Bypasses `IsDebuggerPresent()` and `PEB->BeingDebugged` by using virtualized memory-read handlers to directly inspect the fixed user-mode kernel page at `0x7FFE0000` (specifically `0x7FFE02D4` for `KdDebuggerEnabled`).
2. **Exception-Driven Hardware Debug Register (`DR0–DR7`) Scrubbing:**
   * Triggers deliberate exceptions—such as invoking `NtClose` / `CloseHandle` on an invalid handle when handle tracing is enabled, or executing trapping instructions—and catches them via custom Structured/Vectored Exception Handlers (SEH/VEH) or x64 unwind routines (`.pdata`).
   * The handler inspects and zeroes `CONTEXT->Dr0` through `Dr7` before resuming execution via `NtContinue`, blinding hardware breakpoints without calling `GetThreadContext`.
3. **Virtualized `RDTSC` / `CPUID` Timing & Hypervisor Profiling:**
   * Pairs virtualized `RDTSC` instructions across handler chains to measure execution time deltas ($\Delta t$) and checks `CPUID` leaves (`0x1` Hypervisor Present bit 31 in `ECX`, and `0x40000000` hypervisor vendor signatures).
4. **Direct Kernel Queries (`NtQuerySystemInformation` / `NtSetInformationThread`):**
   * Executes direct syscalls for `ProcessDebugPort` (`0x7`), `ProcessDebugObjectHandle` (`0x1E`), `ProcessDebugFlags` (`0x1F`), `SystemKernelDebuggerInformation` (`0x23`), and `SystemCodeIntegrityInformation` (`0x67`).
   * Detaches the thread from any attached user-mode debugger by invoking `NtSetInformationThread` with `ThreadHideFromDebugger` (`0x11`).

---

## 5. 2026 Academic Deobfuscation Frameworks & Mathematical Extensions

### 5.1 Pushan: Trace-Free VPC-Sensitive Symbolic Emulation

* **Reference:** Ashwin Sudhir et al., *"Pushan: Trace-Free Deobfuscation of Virtualization-Obfuscated Binaries"*, `arXiv:2603.18355` (March 2026).
* **Core Architecture:**
  * Traditional Dynamic Symbolic Execution (DSE) suffers from path explosion in VM loops because it forks state and accumulates path constraints ($\Pi = \bigwedge c_i$).
  * Pushan treats CFG recovery as an **abstract interpretation / structural fixed-point problem** rather than a path-feasibility problem:
    1. **VPC-Sensitive Memoization:** Basic blocks are indexed by $(\text{NativeAddr}, \text{VPC})$.
    2. **Abstract State Merging ($\sqcup$):** When control-flow paths converge, differing concrete register/memory values are widened to an unconstrained abstract symbol $\top$ (`TOP`).
    3. **Constraint-Free SMT Enumeration:** Indirect jump targets (`JMP RAX`) and opaque predicates are resolved by querying the SMT solver on the isolated target expression *without* historical path constraints.
* **Proposed Mathematical Extension (Selective Key Preservation at Join Points):**
  * *Problem in VMP 3.11:* If two converging branches carry distinct concrete rolling keys $K^{(1)} \neq K^{(2)}$ that are compensated by branch-specific key-adjusting handlers prior to merge, naive widening ($K^{(1)} \sqcup K^{(2)} = \top$) destroys the concrete key state, rendering the post-merge dispatch expression $\text{Table}[\text{Mem}[\text{VPC}] \oplus \top]$ unresolvable.
  * *Formal Solution:* Partition the abstract state domain $\Sigma$ into the Key/Dispatcher Sub-state $\Sigma_K = \{\text{VPC}, K, \text{VSP}\}$ and Data Sub-state $\Sigma_D$. Define a **Key-Preserving Join Operator** $\sqcup_K$:
    $$\Sigma^{(1)} \sqcup_K \Sigma^{(2)} = \left( \Sigma_K^{(1)} \cup_{\text{bounded}} \Sigma_K^{(2)},\; \Sigma_D^{(1)} \sqcup_{\top} \Sigma_D^{(2)} \right)$$
    By maintaining a bounded disjunctive set of concrete values for $\Sigma_K$ while widening $\Sigma_D$ to $\top$, the analyzer prevents state explosion on program data while preserving exact rolling-key decidability across loop headers.

### 5.2 VMPredator: Core-Structure Semantic Anchor Mapping

* **Reference:** Wanju Kim et al., *"A Core-Structure-Based Automated Analysis Tool for Commercial Virtualization Obfuscation Deobfuscation"*, `arXiv:2605.30902` (May 2026).
* **Core Architecture:**
  * Avoids brittle dispatcher-loop pattern matching by anchoring analysis on three universal **Semantic Anchor Points**: `VM Entry` (native context push), `Handlers` (state mutation), and `VM Exit` (native context pop).
  * Separates each handler's internal instructions into **(1) Operand Decoding**, **(2) Core Semantic Execution**, and **(3) Next-Handler Dispatch** using **AST Depth Heuristics**, achieving an ~85% reduction in instruction length.
* **Proposed Mathematical Extension (Bivariate Taint Partitioning):**
  * *Problem in VMP 3.11 Ultra Mode:* When MBA obfuscation is applied to the core semantic logic, its AST depth matches or exceeds the AST depth of rolling-key operand decoding, causing AST-depth thresholds to misclassify program logic as dispatcher overhead.
  * *Formal Solution:* Introduce two orthogonal taint labels at `VM Entry`:
    * $\tau_{\text{VM}}$: Applied to the initial bytecode pointer (`VPC`), Rolling Key ($K_0$), and `.vmp` bytecode memory pages.
    * $\tau_{\text{Arch}}$: Applied to the pushed native architectural registers (`RAX..R15`, `EFLAGS`) and non-VM stack/heap memory.
  * For any symbolic expression $e$ evaluated inside a handler, let $T(e) \subseteq \{\tau_{\text{VM}}, \tau_{\text{Arch}}\}$ denote its propagated taint set:
    * **Pure Decoding / Dispatch Overhead:** $T(e) = \{\tau_{\text{VM}}\}$ (strip from lifted IR).
    * **Immediate Constant Loading:** $T(e) = \{\tau_{\text{VM}}\}$, but $e$ is written to a virtual register later consumed by an expression with $\tau_{\text{Arch}}$ (fold to constant via concrete evaluation).
    * **Core Semantic Mutation:** $\tau_{\text{Arch}} \in T(e)$ (preserve and pass to MBA simplification).

### 5.3 VMSpec: Decompiler-Based Virtual Machine Analysis

* **Reference:** Fabian Kilger, Leonard Auer, Manuel Andreas et al., *"VMSpec: A Decompiler-based Approach against Virtual Machine Obfuscation"*, `arXiv:2610.29566` (October 21, 2026).
* **Relevance:** Addresses the limitation of incomplete handler synthesis in dynamic trace approaches by leveraging decompiler-driven structural analysis to recover complete handler specifications across multi-branch virtualized constructs.

---

## 6. Research Tooling & Hybrid Pipeline Benchmarks

### 6.1 Unpacking & Import Resolution (`vmp-lazy-unpack`)

* **Architecture:** Developed by `x86rc` (updated October 2026 for VMProtect 3.11 and 32-bit/64-bit PE support). Uses **Unicorn Engine**, **Capstone**, and `pefile` alongside a pinned catalog of Windows DLL exports to emulate the packed binary from its entry point in a simulated Windows environment without attaching a live debugger.
* **Capabilities:** Intercepts direct syscalls and emulated API calls, handles `CloseHandle` anti-debug exceptions via shared emulation handlers, tracks memory writes until execution enters restored code (OEP), reconstructs the Import Address Table (IAT), patches obfuscated import stubs, repairs x64 `.pdata` exception directories, and dumps the unpacked image.
* **Scope Boundary:** Resolves packing, anti-debug checks during initialization, and IAT obfuscation, providing a clean binary input for static/symbolic devirtualizers (`Pushan`, `VMPredator`, `VMSpec`), though it does not devirtualize `.vmp` bytecode functions by itself.

### 6.2 Memory Protection Monitoring (`vmp-virtualprotect-bypass` & Ring-3 Callbacks)

* **Architecture:** Conceptual frameworks such as `vmp-virtualprotect-bypass` focus on neutralizing `VirtualProtect` / `NtProtectVirtualMemory` checks during dynamic inspection.
* **Architectural Evolution for VMP 3.11:** Because VMP 3.11 invokes direct syscalls via a manually mapped `ntdll.dll` view, defensive monitoring environments increasingly rely on **`ProcessInstrumentationCallback`** (Nirvana callbacks via `NtSetInformationProcess`) to observe Ring-0 to Ring-3 syscall returns uniformly, or hypervisor **Extended Page Tables (EPT)** split-TLB views to preserve unmodified read views for inline self-checksumming handlers.

---

## 7. Verified Academic & Technical References

### 2026 Core Academic Literature

1. **Pushan (March 2026):** Ashwin Sudhir, Zion Leonahenahe Basque, Wil Gibbs, et al., *"Pushan: Trace-Free Deobfuscation of Virtualization-Obfuscated Binaries"*, arXiv:2603.18355 [cs.CR].  
   * **Abstract:** <https://arxiv.org/abs/2603.18355>  
   * **PDF:** <https://arxiv.org/pdf/2603.18355>  
   * **HTML:** <https://arxiv.org/html/2603.18355v1>  
   * **DOI:** <https://doi.org/10.48550/arXiv.2603.18355>

2. **VMPredator (May 2026):** Wanju Kim, Seoksu Lee, et al., *"A Core-Structure-Based Automated Analysis Tool for Commercial Virtualization Obfuscation Deobfuscation"*, arXiv:2605.30902 [cs.CR].  
   * **Abstract:** <https://arxiv.org/abs/2605.30902>  
   * **PDF:** <https://arxiv.org/pdf/2605.30902>  
   * **HTML:** <https://arxiv.org/html/2605.30902v1>  
   * **DOI:** <https://doi.org/10.48550/arXiv.2605.30902>

3. **VMSpec (October 2026):** Fabian Kilger, Leonard Auer, Manuel Andreas, et al., *"VMSpec: A Decompiler-based Approach against Virtual Machine Obfuscation"*, arXiv:2610.29566 [cs.CR].  
   * **Abstract:** <https://arxiv.org/abs/2610.29566>  
   * **PDF:** <https://arxiv.org/pdf/2610.29566>  
   * **HTML:** <https://arxiv.org/html/2610.29566v1>

### Foundational Deobfuscation & MBA Simplification Literature

1. **Syntia (USENIX Security 2017):** Tim Blazytko et al., *"Syntia: Synthesizing the Semantics of Obfuscated Code"*.  
   * **Link:** <https://www.usenix.org/conference/usenixsecurity17/technical-sessions/presentation/blazytko>
2. **QSynth (IEEE S&P 2020):** Robin David et al., *"QSynth: A Program Synthesis based Approach for Binary Code Deobfuscation"*.
3. **VMHunt (ACM CCS 2018):** Dongpeng Xu et al., *"VMHunt: A Verifiable Approach to Partially-Virtualized Binary Code Simplification"*.  
   * **DOI:** <https://doi.org/10.1145/3243734.3243827>

### Vendor Documentation & Open-Source Analysis Repositories

1. **VMProtect 3.11 Official Changelog (October 8, 2026):**  
   * **Link:** <https://vmpsoft.com/news/>
2. **`vmp-lazy-unpack` (Unicorn-Based Emulation Unpacker & Import Resolver):**  
   * **Link:** <https://github.com/x86rc/vmp-lazy-unpack>
3. **Unicorn Engine (CPU Emulator Framework):**  
   * **Link:** <https://www.unicorn-engine.org/>
