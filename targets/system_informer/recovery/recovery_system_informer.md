# Recovery walkthrough — System Informer Pro

How a cracker would break the Pro gate, and why each step forces a different part of the reaforge
toolchain. This is the RE companion to the build; live RVAs/addresses are marked `TODO(build)` and get
filled from the protected binary's `/MAP` + an IDA pass. Everything analysed here is the user's own fork.

The headline: the gate is **not** a boolean. A valid license and a cracked attempt are produced
side-by-side with `license_signer.py` (the oracle, issuer private key held by the user). A shallow crack
(NOP a branch, flip a flag, swap-and-sign the pubkey) does not work; a real break has to walk the whole
chain below.

---

## 0. Recon — classify the two protectors

```bash
python -m reaforge.orchestrator recon <SystemInformer.vmp.exe>   # DIE: VMProtect 3.11
python -m reaforge.orchestrator recon <ExtendedTools.themida.dll> # DIE: Themida / WinLicense
```

- `SystemInformer.exe` → **VMProtect Ultra** on the cold gate (`sip_gate_init`, `sip_access_mask`,
  `sip_xdll_respond`), Mutation on the reachability stubs. Routes to `reaforge/core` devirt.
- `plugins\ExtendedTools.dll` → **Themida/WinLicense**. Routes to `reaforge/tools/themida_unwrap.py` +
  `pe_reconstruct.py` (the orchestrator refuses to run the VMProtect devirt engine on a Themida binary —
  it points at the plan instead).

## 1. Unpack + rebuild the IAT (both binaries)

- VMProtect: reach the OEP/post-unpack state via the emulation loader (`reaforge/core/loader.py`,
  VmpLoader) and snapshot it to `dumps/system_informer_postoep.snap`.
- Themida: `themida_unwrap.py` to strip the Falcon/WinLicense layers, then `pe_reconstruct.py` to rebuild
  a loadable image and repair the IAT (Themida redirects imports through its own thunks). Without a
  rebuilt IAT the later static/symbolic passes see garbage call targets.

`TODO(build)`: OEP RVA, IAT RVA/size, which imports are wrapped.

## 2. Find the gate — VMEnter, not a compare

There is no `cmp/jz` to search for. Instead look for the `NtOpenProcess` call sites the Pro features use
and trace **backwards** to where the ACCESS_MASK (RDX, the 2nd arg via `ObjectAttributes`/desired-access)
is produced. That producer is `sip_access_mask`, and it is a VMProtect VMEnter.

- In IDA: xref `NtOpenProcess` / `PhOpenProcess`; the dumper path is in `misccmd.c`-derived code.
- The RDX value is not an immediate — it comes out of the VM. Set an x64dbg hardware-exec BP on the
  `NtOpenProcess` stub and read RDX: `0x0450` when licensed, `0x1000` when not. `TODO(build)`: addresses.

## 3. Devirtualise the gate (VMProtect)

```bash
python -m reaforge.core system_informer dump recover peel prove
```

`reaforge/tools/vm_lift.py` lifts `sip_access_mask` and `sip_gate_init`. The oracle-free VM-lifter
(Unicorn concrete + SymEngine shadow) recovers the branchless selection:

```
m      = -(entitled & crc_ok & nodbg)
access = (base & m) | (0x1000 & ~m)
```

Recovering `base` is the point: it is **not** in the lifted code as a constant — it is a value loaded
from `g_state.mask_base[]`, which was written by `sip_gate_init` only after a successful AES-GCM decrypt.
So devirt tells you the *shape* of the gate but hands you a data dependency on the KDF. `cross-check`:
`config.expected_key("dump")` == `0x0450` — the value a correct lift must predict for the entitled state.

## 4. Lift the KDF and prove it (the real wall)

`sip_gate_init` is the deep VMEnter. Lift it to recover the key schedule:

```
ikm = HWID || issuer_pubkey(32) || text_crc(LE u32) || "enterprise-forensics"
K   = HKDF-SHA256(ikm, salt, info="SIP-offline-v1")        # 32-byte AES key
pt  = AES-256-GCM-decrypt(K, nonce, ciphertext)            # entitlements (incl. the mask bases)
```

Prove the relationship with `reaforge/core/peel.prove_recurrence` (the same z3 machinery that proved the
license_app and dead_cells recurrences). What the proof must establish, and why each defeats a shallow
crack:

| input to the KDF        | shallow crack it kills                                    |
|-------------------------|-----------------------------------------------------------|
| `text_crc` (runtime)    | patch 1 byte of `.text` -> CRC changes -> K changes -> GCM auth fails. No compare to NOP. |
| `issuer_pubkey` bytes   | swap `.rdata` pubkey -> K changes; even self-signing, you must re-encrypt under the new K AND still produce the right mask bases. |
| `HWID`                  | machine binding; a lifted K on one box does not transfer. |
| Ed25519 signature       | edit decrypted entitlements + re-encrypt -> signature no longer verifies (no private key). |

The lesson filmed here: you cannot "find the check". You must reconstruct the KDF, which is exactly what
`prove_recurrence` is for. `TODO(build)`: the lifted HKDF/AES block, the proof transcript.

## 5. Recover the mask bases from the decrypted payload

Only after the KDF is proven can you decrypt a captured `.sipm` (on the legit machine) and read
`mask_dump/inject/edit`. These are the bases the devirt in §3 needed. Alternatively, dump `g_state` from
memory at runtime after a successful init (x64dbg), which is the quick dynamic shortcut for the video —
note it still requires a valid license to have decrypted, i.e. it does not forge anything.

## 6. Forge + sign (what actually unlocks it)

A working forge needs the issuer private key — which the user holds, so the honest demonstration is: show
the oracle issuing a valid license, and show that without the private key the best an attacker can do is
a *dynamic* bypass, not a forged file:

```bash
python license_signer.py issue  --hwid <HWID> --text-crc 0x<CRC> --subject "Reviewer" --tier pro
python license_signer.py verify licenses/Reviewer.sipm --hwid <HWID> --text-crc 0x<CRC>   # PASS
python license_signer.py attack licenses/Reviewer.sipm --hwid <HWID> --text-crc 0x<CRC>   # all cracks FAIL
```

Dynamic bypass (the realistic attacker move, like `bypass` mode on license_app): after devirt, patch the
*runtime* `g_state` (or force `sip_access_mask` to return the base) so the handle opens with `0x0450`.
This works but is unstable and defeated by the CRC-into-KDF on the next clean run, and it does not survive
`VMProtectIsValidImageCRC`. Contrast this with the oracle's clean, portable license on camera.

## 7. Cross-DLL handshake

`ExtendedTools.dll` (Themida, `et_xdll.c`) challenges `sip_progate.dll` (VMProtect); the response is
`HKDF(xdll_seed || challenge, salt=HWID, info="SIP-xdll-v1")`, where `xdll_seed` comes from the decrypted
license, so a module that never decrypted a valid license cannot answer. The coupling is **response-as-key**:
the `.sipm` carries an `XDLB` section (challenge + an AES-256-GCM unlock blob keyed by that response), and
ExtendedTools decrypts the blob with the response to obtain its Pro feature flags — there is no boolean to
NOP across the DLL seam. Breaking this requires having broken §4 in *both* protector families — the Themida
unwrap/reconstruct path and the VMProtect devirt path — which is the point of running one binary through each.

---

## Dual-protector contrast (for the video)

- Same gate logic, two protectors: VMProtect VM vs Themida Falcon VM + WinLicense wrapping.
- Show DIE classification, then the two different reaforge entry points, then the identical recovered
  algorithm — i.e. the protection is interchangeable but the *scheme* is what matters.

## Build-provided addresses (filled 2026-11-02)

Gate functions in `sip_progate.dll` (image base `0x180000000`). The unpacked `/MAP` RVA is where the C
compiler put each function; after the VMProtect pass that code is virtualized, so in the shipped (packed)
DLL the live entry point is the **export RVA** — that is where an RE actually lands and must devirt from.

| function               | unpacked `.map` RVA | packed export RVA | role                              |
|------------------------|---------------------|-------------------|-----------------------------------|
| `sip_access_mask`      | `0x3540`            | `0x1249`          | the mask materialiser (choke pt)  |
| `sip_gate_init`        | `0x35D0`            | `0x1320`          | verify / entangled-KDF choke pt   |
| `sip_xdll_respond`     | `0x3DC0`            | `0x16F4`          | cross-DLL handshake responder     |
| `sip_is_pro`           | `0x3D90`            | `0x1DF2`          | UI predicate (not the gate)       |
| `sip_image_text_crc32` | `0x6130`            | — (internal)      | whole-image CRC feeding the KDF   |
| `sip_nodbg`            | `0x33A0`            | — (internal)      | anti-debug predicate              |

- `config.py` `check_rva` = `0x1249` (packed `sip_access_mask` export).
- Themida side: in `plugins\ExtendedTools.dll` the handshake challenger `EtXdllUnlock` is the virtualized
  macro at RVA `0x7C8AB-0x7CB4E` (from the Themida protection log; Demo => FALCON64-Tiny VM). Packed plugin
  MD5 `5bc7854cf650a0f1f4fbe6dabceee1cb`.

## Open items (produced by the recovery RUN, not the build)

- `TODO(run)`: post-OEP snapshot + the Themida-unwrapped image (outputs of `themida_unwrap.py` + `pe_reconstruct.py`).
- `TODO(run)`: the live `NtOpenProcess` RDX trace (licensed `0x0450` vs unlicensed `0x1000`).
- `TODO(run)`: the lifted KDF/AES block + the `prove_recurrence` transcript.
