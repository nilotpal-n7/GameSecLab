# Devirtualization tooling availability for VMProtect 3.11 (checked 2026-10-26)

Goal: devirtualize `check_license` (the lone VM-bytecode function left in our unpacked dump).
Reality: **no publicly released tool devirtualizes VMProtect 3.11.**

| Tool | Basis | VMProtect support | Code public? |
| --- | --- | --- | --- |
| **Pushan** (arXiv:2603.18355) | angr (VEX/AIL), constraint-free symbolic emulation | 3.11 (evaluated) | **No** — paper only; authors release just their CFGED eval tooling, not Pushan |
| **VMPredator** (arXiv:2605.30902) | semantic-anchor mapping | 3.11 | No public repo found |
| **VMSpec** (arXiv:2610.29566) | decompiler-based | modern | No public repo found |
| **Titan** (github.com/archercreat/titan) | Triton + LLVM lifting | **< 3.8** ("less than ideal output") | Yes (Triton+LLVM build) |
| **NoVmp / NoVmpy** | VTIL | 3.0–3.5 / ≤3.6, needs unpacked input | Yes (abandoned 2021) |

**Conclusion:** the tools that *can* do 3.11 are unreleased research prototypes; the released tools (Titan,
NoVmp) target old VMProtect (<3.8) and would give poor/no output on 3.11. Off-the-shelf automated
devirtualization of our 3.11 function is not currently possible.

## Realistic ways to still recover `check_license`

1. **Manual VM devirtualization** — the dump is unpacked, so the VM entry/dispatcher/handlers in `.G#b` are
   statically visible. For one tiny function this is tractable and is the core RE skill (ref: Rolles WOOT'09,
   `docs/Rolles_…WOOT2009.pdf`). Hard but tool-independent.
2. **Dynamic I/O recovery** — emulate/trace the VM executing `check_license` on known inputs and recover the
   input→output relation (we control the env via Unicorn, like vmp-lazy-unpack).
3. **Already known** — we recovered the exact algorithm at **C0** (`expected_key`, key `75685AB2`); the C2 break
   (strip protection + recover `main` + isolate the VM function) is complete regardless.
