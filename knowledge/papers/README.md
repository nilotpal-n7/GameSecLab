# docs/ — research library

Papers and references for the capstone (anti-analysis, virtualization obfuscation, DBI, devirtualization).
Collected for study of software **we own or are authorized to test**. Add the source URL + why it matters.

## Current papers

| File | Source | Why it matters here |
| --- | --- | --- |
| `Bypassing_Anti-Analysis_of_Commercial_Protector_Methods_Using_DBI_Tools.pdf` | IEEE Access 2021, Y.B. Lee et al. | **The C2 key.** Analyzes anti-VM + anti-DBI of VMProtect/Themida/Enigma/Obsidium. VMProtect anti-DBI = **single-step (trap-flag) exception**; shows the DBI bypass (re-raise the exception). Explains exactly why our ScyllaHide run failed. |
| `Rolles_Unpacking_Virtualization_Obfuscators_WOOT2009.pdf` | USENIX WOOT '09, Rolf Rolles — <https://static.usenix.org/events/woot09/tech/full_papers/rolles.pdf> | Foundational **devirtualization** paper. How a VM obfuscator (VMProtect-style) works and how to recover the logic: find the VM dispatcher, decode the bytecode, lift handlers to IR. The theory behind manual VM recovery. |
| `DElia_SoK_DBI_for_Security_AsiaCCS2019.pdf` | ACM AsiaCCS 2019, D'Elia et al. — <https://kclpure.kcl.ac.uk/ws/files/108301045/main.pdf> | **SoK on DBI for security** and how DBI (Pin) gets detected/evaded. Attack surface + a library of detection patterns + mitigations — for building a *stealthy* Pin tool. |
| `DBI_Evasion_and_Countermeasures_Survey.pdf` | Univ. Zaragoza — <https://zaguan.unizar.es/record/126489/files/texto_completo.pdf> | Survey of **DBI evasion techniques vs Intel Pin** and which have countermeasures. Practical anti-anti-DBI for our Pin work. |

## VMProtect 3.11 architecture + 2026 devirtualization (added 2026-10-26)

| File | Why it matters here |
| --- | --- |
| `Architectural_Analysis_&_Academic_Deobfuscation_of_VMProtect_3.11_(2026).md` | Maps 3.11's VM/anti-tamper/anti-debug internals — explains why x64dbg, Pin, and our single-step bypass all failed (it's RDTSC timing + direct syscalls + checksumming, not the old single-step). |
| `vmp311_analysis_and_pipeline.md` | **My analysis + the new break pipeline:** emulation-unpack (vmp-lazy-unpack) → devirtualize (Pushan). Ties every failed attempt to a root cause. |
| `Pushan…2603.18355.pdf` | **Verified** (ASU+CISPA, Mar 2026) trace-free VM deobfuscator → C pseudocode; vs VMProtect/Themida/Tigress. |
| `VMPredator…2605.30902.pdf` | Core-structure semantic-anchor devirtualization (May 2026). |
| `VMSpec…2610.29566.pdf` | Decompiler-based VM analysis (Oct 2026). |
| `VMHunt…1811.04036.pdf` | CCS'18 — partially-virtualized code simplification (foundational). |

Tools cloned to `C:\Tools\_downloads\research\` (outside the repo — external code): `vmp-lazy-unpack`
(Unicorn unpacker, VMP 3.4–3.11), `arancino`, `sok-dbi-security`.

## To collect next (ongoing)

- VMProtect/Themida-specific devirtualization write-ups (NoVmp/VTIL design, VMHunt CCS'18, Syntia USENIX'17).
- Symbolic/concolic deobfuscation (Triton, angr; Salwan/Bardin "Symbolic deobfuscation").
- Program synthesis for handler recovery (Syntia, Xyntia).
- Modern VMProtect 3.x internals / anti-debug write-ups.

> Practice: when a doc proves useful for research/analysis, download the PDF here and add a row above with
> the source URL and a one-line "why it matters".
