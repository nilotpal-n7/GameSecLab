#!/usr/bin/env python3
r"""Title config: system_informer - our own licensed+protected fork of winsiderss/systeminformer.

The ONE place this target's specifics live. Unlike license_app (a serial->key crackme), System Informer
Pro gates features by an offline MACHINE FILE: the reference oracle is targets/system_informer/
license_signer.py (the user holds the Ed25519 private key), not a pure serial function. So `expected`
here is the known-good ACCESS_MASK a recovery must reproduce for a feature, and the deep break is proving
the entangled KDF (HKDF over HWID||pubkey||text_crc||slug) with reaforge/core/peel.prove_recurrence, then
forging + signing with the oracle. See recovery/recovery_system_informer.md.

Protected path exercised end to end:
    recon (DIE) -> classify protector (VMProtect Ultra; one binary also Themida/WinLicense)
    -> reaforge/tools/vm_lift.py (devirt sip_gate_init / sip_access_mask)
    -> reaforge/tools/themida_unwrap.py + pe_reconstruct.py (the Themida binary)
    -> reaforge/core/peel.prove_recurrence (the KDF)
    -> license_signer.py forge/sign.

Run via:   python -m reaforge.core system_informer [feature] [modes]
"""
from __future__ import annotations

from pathlib import Path

from categories.native_license import campaign

HERE = Path(__file__).resolve().parent
DUMPS = HERE / "dumps"

# -- Pro entitlement model (single source of truth; license_signer.py mirrors these) --------------
SLUG = "enterprise-forensics"

# NtOpenProcess ACCESS_MASK bases the branchless gate selects between (si_pro_mask.h / pro_gate.cpp).
# These are carried ENCRYPTED in the license payload - they are not immediates in the protected binary;
# a correct recovery must pull them out of the decrypted entitlements, not read them from .rdata.
MASK = {
    "dump":   0x00000450,  # Process Memory Dumper (PhWriteMiniDumpProcess / misccmd.c)
    "inject": 0x0000002A,  # DLL Injection (misccmd.c)
    "edit":   0x00000038,  # live Memory Editor write access (memedit.c)
}
MASK_TRAP = 0x00001000     # unlicensed trap (PROCESS_SUSPEND_RESUME): handle opens, Pro op denies

# Feature index order must match SipFeature in si_pro_mask.h.
FEATURES = ("dump", "inject", "edit")


def expected_key(feature) -> int:
    """Known-good ACCESS_MASK for a feature - what a devirt of sip_access_mask must reproduce when the
    cached state is (entitled & crc_ok & nodbg) == 1. Cross-check oracle only."""
    if isinstance(feature, int):
        feature = FEATURES[feature] if 0 <= feature < len(FEATURES) else "dump"
    return MASK.get(feature, MASK_TRAP)


CONFIG = campaign.Config(
    name="system_informer Pro gate",
    # TODO: drop the protected build in dumps/ and `orchestrator authorize` it. The VMProtect binary is
    # SystemInformer.exe; the Themida pass (optional) targets plugins\ExtendedTools.dll.
    packed=str(DUMPS / "SystemInformer.vmp.exe"),
    snap=str(DUMPS / "system_informer_postoep.snap"),
    # TODO: RVA of sip_access_mask (the mask materialiser) once the build MAP is in hand; sip_gate_init
    # is the verify/KDF choke point. Fill from the /MAP file the protected build emits.
    check_rva=0x1000,
    expected=expected_key,
    protector="vmprotect",
)


def run(packed=None, arg=None, modes=("validate", "recover", "peel", "prove")):
    """`arg` selects the feature to analyse (dump/inject/edit); defaults to the memory dumper."""
    feat = arg if arg in FEATURES else "dump"
    cfg = campaign.Config(**{**CONFIG.__dict__, "name": f"system_informer Pro gate [{feat}]"})
    campaign.run(cfg, packed, modes)
