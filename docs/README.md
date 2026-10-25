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

## To collect next (ongoing)

- VMProtect/Themida-specific devirtualization write-ups (NoVmp/VTIL design, VMHunt CCS'18, Syntia USENIX'17).
- Symbolic/concolic deobfuscation (Triton, angr; Salwan/Bardin "Symbolic deobfuscation").
- Program synthesis for handler recovery (Syntia, Xyntia).
- Modern VMProtect 3.x internals / anti-debug write-ups.

> Practice: when a doc proves useful for research/analysis, download the PDF here and add a row above with
> the source URL and a one-line "why it matters".
