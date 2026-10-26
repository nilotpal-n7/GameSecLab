# screenshots/ — key evidence for verification & presentation

Milestone screenshots kept for the write-up / portfolio. Naming: `<layer>_<nn>_<what>.png`.

## C2 — VMProtect virtualization break

| File | Shows |
| --- | --- |
| `c2_01_x64dbg_vmprotect_entry_stub.png` | `license_app_c2.vmp.exe` loaded in x64dbg, paused at the VMProtect packer **entry stub** (obfuscated `push/jmp`, junk `???` bytes). |
| `c2_02_antidebug_detected_default_scyllahide.png` | VMProtect **anti-debug fired** with the default ScyllaHide "VMProtect" profile: *"A debugger has been found running in your system."* |
| `c2_03_antidebug_detected_maxed_scyllahide.png` | Same detection **after maxing the ScyllaHide profile** (36+ hooks). Proves usermode anti-anti-debug can't beat VMProtect 3.11's **single-step** anti-debug — the root cause the DBI paper explains. |

> Practice: save the screenshot behind each milestone/result here (you capture the GUI, I copy it in with a
> descriptive name), so the final write-up has verifiable evidence.
