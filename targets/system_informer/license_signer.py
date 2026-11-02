#!/usr/bin/env python3
r"""System Informer Pro — offline machine-file SIGNER (clean reference oracle).

This is the keygen-equivalent for the system_informer target: the user holds the Ed25519 PRIVATE key
and issues valid offline licenses with it, exactly the way keygen.py is the oracle for quint_bezier.
It exists so a *valid* license and a *cracked attempt* can be produced + filmed side by side, and so the
C++ verifier in src/pro_gate.cpp can be checked against a known-correct Python implementation of the
identical byte format.

WHY THIS IS HARD TO CRACK (the format is the whole point)
---------------------------------------------------------
The license is NOT "a flag you flip". The entitlement payload (tier + the four ACCESS_MASK bases that the
branchless kernel gate ANDs together) is AES-256-GCM encrypted under a key derived by an HKDF that
*entangles* four inputs:

    ikm = HWID || ed25519_pubkey(32) || text_crc(LE u32) || entitlement_slug
    K   = HKDF-SHA256(ikm, salt=salt, info=b"SIP-offline-v1", len=32)

and the whole file is then Ed25519-signed with the user's private key. Consequences, by attack:

  * patch one byte of the protected image -> text_crc changes -> K changes -> AES-GCM auth FAILS.
        The license does not "return false"; it fails to DECRYPT. There is no compare to NOP.
        ("text_crc" is the field name. The verifier's sip_image_text_crc32() CRCs the whole on-disk
        module file -- pre-pack that is dominated by .text; once VMProtect packs the output, .text's raw
        data is zeroed into packed sections, so a whole-file CRC is what stays reproducible and binds the
        license to the exact packed build, incl. the VM bytecode the cracker actually edits.)
  * swap the embedded .rdata pubkey for the attacker's own (classic forge) -> pubkey bytes in ikm change
        -> K changes. The attacker can still self-sign + self-encrypt under their pubkey-derived K, so the
        sig check alone would pass — but the DECRYPTED payload must then also carry the EXACT mask bases
        (0x0450 / 0x002A / 0x0038 / 0x1000). Those live VMProtectDecryptStringA-encrypted inside the VM'd
        region, so a forger who has not devirtualised the gate does not know them; a wrong base makes
        NtOpenProcess return STATUS_ACCESS_DENIED and the Pro feature dies downstream of any check.
  * wrong machine (wrong HWID) -> K changes -> fails to decrypt. Normal machine binding.
  * edit the decrypted entitlements and re-encrypt under the (derivable) K -> Ed25519 signature no longer
        matches, because the attacker does not hold the private key.

So a full crack must: unpack -> rebuild IAT -> devirt the gate to recover the mask bases -> prove the KDF
(peel.prove_recurrence over the HKDF/AES relationship) -> forge AND sign a self-consistent file. That is
the entire lab toolchain, which is the design goal. See recovery/recovery_system_informer.md.

FILE FORMAT  (little-endian; call it "SIPM" = System Informer Pro Machine-file)
-------------------------------------------------------------------------------
    offset  field
    0       magic        4   b"SIPM"
    4       version      1   = 1
    5       flags        1   bit0 = DEMO_SOFT permitted
    6       reserved     2   = 0
    8       salt        16   random per issue (HKDF salt)
    24      nonce       12   AES-256-GCM nonce
    36      ct_len       4   u32 length of ciphertext (includes the trailing 16-byte GCM tag)
    40      ciphertext  ct_len
    ...     signature   64   Ed25519 over bytes [0 .. 40+ct_len)  (everything above the signature)

ENTITLEMENT PAYLOAD  (plaintext, before AES-GCM; little-endian)
---------------------------------------------------------------
    magic        4   b"ENTL"
    license_id  16   uuid4 bytes
    issued       8   u64 unix seconds
    expires      8   u64 unix seconds (0 = perpetual)
    tier         4   u32  (0 = Free/Community, 1 = Pro/Enterprise)
    subject          len-prefixed utf-8 (u16 len)   "Licensed To"
    slug             len-prefixed utf-8 (u16 len)    entitlement slug ("enterprise-forensics")
    mask_dump    4   u32  NtOpenProcess ACCESS_MASK base for Process Memory Dumper   (0x00000450)
    mask_inject  4   u32  ...                              for DLL Injection          (0x0000002A)
    mask_edit    4   u32  ...                              for live Memory Editor     (0x00000038)
    mask_trap    4   u32  unlicensed trap mask (granted when NOT entitled)            (0x00001000)
    xdll_seed   32   rolling-key seed for the SI.exe <-> ExtendedTools.dll handshake

USAGE
-----
    python license_signer.py genkey                       # create issuer keypair (keep the private key!)
    python license_signer.py pubkey-c                     # emit the pubkey as a C array for embedding
    python license_signer.py issue  --hwid <hex> --text-crc 0x<crc> --subject "Name" [--tier pro]
    python license_signer.py verify <file.sipm> --hwid <hex> --text-crc 0x<crc>
    python license_signer.py attack <file.sipm> --hwid <hex> --text-crc 0x<crc>  # demo why cracks fail

The mask bases and slug match targets/system_informer/config.py (the single source of truth for them).
"""
from __future__ import annotations

import argparse
import os
import struct
import sys
import time
import uuid
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

HERE = Path(__file__).resolve().parent
KEYDIR = HERE / "issuer_keys"               # gitignored; holds the private key the user controls
PRIV_PEM = KEYDIR / "sip_issuer_ed25519.pem"
PUB_RAW = KEYDIR / "sip_issuer_ed25519.pub"

MAGIC = b"SIPM"
ENT_MAGIC = b"ENTL"
VERSION = 1
HKDF_INFO = b"SIP-offline-v1"
SLUG_DEFAULT = "enterprise-forensics"

# Cross-DLL handshake (ExtendedTools.dll <- sip_progate.dll). An "XDLB" section carrying a per-license
# unlock blob is appended to the outer file AFTER the ciphertext and BEFORE the Ed25519 signature, so it
# is covered by the signature yet readable without the main KDF. ExtendedTools gets the handshake response
# from sip_progate (HKDF below) and uses it as the AES-256-GCM key to open the blob; a wrong/absent response
# fails GCM auth -> the plugin stays in Community mode. Response-as-key: no naked boolean crosses the seam.
# sip_gate_init() is untouched by this: it takes sig = last 64 bytes, verifies everything before (so the
# XDLB bytes are signed), and reads ct by its length at offset 40 (so the trailing section is ignored).
XDLL_INFO = b"SIP-xdll-v1"       # == info in pro_gate.cpp sip_xdll_respond (salt = HWID, ikm = seed||challenge)
XDLL_SECTION_MAGIC = b"XDLB"     # outer-file section tag
XUNLOCK_MAGIC = b"XUNL"          # plaintext magic inside the unlock blob (followed by u32 feature flags)

# The four ACCESS_MASK bases the branchless gate selects between. Single source of truth = config.py;
# duplicated here as defaults so the signer runs stand-alone for filming. Keep them in sync.
MASK_DUMP = 0x00000450
MASK_INJECT = 0x0000002A
MASK_EDIT = 0x00000038
MASK_TRAP = 0x00001000

TIER_FREE, TIER_PRO = 0, 1


# ── low-level serialization helpers ──────────────────────────────────────────────────────────────
def _lp(s: str) -> bytes:
    """Length-prefixed (u16) utf-8."""
    b = s.encode("utf-8")
    if len(b) > 0xFFFF:
        raise ValueError("string too long")
    return struct.pack("<H", len(b)) + b


def _read_lp(buf: bytes, off: int) -> tuple[str, int]:
    (n,) = struct.unpack_from("<H", buf, off)
    off += 2
    return buf[off:off + n].decode("utf-8"), off + n


def pack_entitlements(*, subject: str, slug: str, tier: int, issued: int, expires: int,
                      license_id: bytes, xdll_seed: bytes,
                      mask_dump: int, mask_inject: int, mask_edit: int, mask_trap: int) -> bytes:
    out = bytearray(ENT_MAGIC)
    out += license_id
    out += struct.pack("<QQI", issued, expires, tier)
    out += _lp(subject)
    out += _lp(slug)
    out += struct.pack("<IIII", mask_dump, mask_inject, mask_edit, mask_trap)
    out += xdll_seed
    return bytes(out)


def unpack_entitlements(buf: bytes) -> dict:
    if buf[:4] != ENT_MAGIC:
        raise ValueError("bad entitlement magic")
    off = 4
    license_id = buf[off:off + 16]; off += 16
    issued, expires, tier = struct.unpack_from("<QQI", buf, off); off += 20
    subject, off = _read_lp(buf, off)
    slug, off = _read_lp(buf, off)
    mask_dump, mask_inject, mask_edit, mask_trap = struct.unpack_from("<IIII", buf, off); off += 16
    xdll_seed = buf[off:off + 32]; off += 32
    return dict(license_id=license_id, issued=issued, expires=expires, tier=tier, subject=subject,
                slug=slug, mask_dump=mask_dump, mask_inject=mask_inject, mask_edit=mask_edit,
                mask_trap=mask_trap, xdll_seed=xdll_seed)


# ── the entangled KDF (must match src/pro_gate.cpp byte for byte) ─────────────────────────────────
def normalize_hwid(hwid: str) -> bytes:
    """Canonical HWID bytes fed to the KDF = the exact device-id STRING bytes.

    This must match pro_gate.cpp byte for byte: sip_hwid() returns LicenseSeat device::generate_device_id()
    verbatim (e.g. the 32-char hex string "c30e12..."), and the gate hashes those ASCII bytes directly. So
    we hash the string's UTF-8 bytes too — we do NOT hex-decode it (that would feed 16 bytes vs the gate's
    32, and the AES-GCM auth would always fail).
    """
    return hwid.strip().encode("utf-8")


def derive_key(hwid_bytes: bytes, pubkey_raw: bytes, text_crc: int, slug: str, salt: bytes) -> bytes:
    ikm = hwid_bytes + pubkey_raw + struct.pack("<I", text_crc & 0xFFFFFFFF) + slug.encode("utf-8")
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=HKDF_INFO).derive(ikm)


def derive_xdll_key(xdll_seed: bytes, challenge: bytes, hwid_bytes: bytes) -> bytes:
    """The cross-DLL handshake response == the key that unlocks the ExtendedTools blob. Must match
    pro_gate.cpp sip_xdll_respond byte for byte: HKDF(ikm = seed||challenge, salt = HWID, info = "SIP-xdll-v1")."""
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=hwid_bytes,
                info=XDLL_INFO).derive(xdll_seed + challenge)


def build_xdll_section(xdll_seed: bytes, hwid_bytes: bytes) -> bytes:
    """XDLB | challenge(32) | nonce(12) | u16 len | AES-256-GCM(unlock-blob). The blob plaintext is
    XUNLOCK_MAGIC + u32 feature-flags; a genuine handshake response decrypts it, nothing else does."""
    challenge = os.urandom(32)
    xnonce = os.urandom(12)
    xkey = derive_xdll_key(xdll_seed, challenge, hwid_bytes)
    pt = XUNLOCK_MAGIC + struct.pack("<I", 1)        # feature flags = 1 (Pro)
    xct = AESGCM(xkey).encrypt(xnonce, pt, None)     # 16-byte tag appended
    return XDLL_SECTION_MAGIC + challenge + xnonce + struct.pack("<H", len(xct)) + xct


# ── key management ────────────────────────────────────────────────────────────────────────────────
def load_private() -> Ed25519PrivateKey:
    if not PRIV_PEM.exists():
        sys.exit(f"no issuer key at {PRIV_PEM}. Run `license_signer.py genkey` first (then keep it safe).")
    return serialization.load_pem_private_key(PRIV_PEM.read_bytes(), password=None)


def pubkey_raw_from_priv(priv: Ed25519PrivateKey) -> bytes:
    return priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def cmd_genkey(_args) -> None:
    KEYDIR.mkdir(exist_ok=True)
    if PRIV_PEM.exists():
        sys.exit(f"refusing to overwrite existing key {PRIV_PEM} (delete it by hand if you really mean to)")
    priv = Ed25519PrivateKey.generate()
    PRIV_PEM.write_bytes(priv.private_bytes(serialization.Encoding.PEM,
                                            serialization.PrivateFormat.PKCS8,
                                            serialization.NoEncryption()))
    pub = pubkey_raw_from_priv(priv)
    PUB_RAW.write_bytes(pub)
    print(f"issuer keypair written:\n  private: {PRIV_PEM}  (KEEP SECRET — this is the whole security root)")
    print(f"  public : {PUB_RAW}  ({pub.hex()})")
    print("\nEmbed the public key in the binary with `license_signer.py pubkey-c`.")


def cmd_pubkey_c(_args) -> None:
    priv = load_private()
    pub = pubkey_raw_from_priv(priv)
    body = ", ".join(f"0x{b:02X}" for b in pub)
    print("/* System Informer Pro issuer public key (Ed25519, raw 32 bytes).")
    print("   Embed in .rdata; feed these exact bytes into the KDF (see pro_gate.cpp). */")
    print(f"static const unsigned char kSipIssuerPubKey[32] = {{ {body} }};")


# ── issue / verify ────────────────────────────────────────────────────────────────────────────────
def build_file(priv: Ed25519PrivateKey, hwid_bytes: bytes, text_crc: int, payload: bytes,
               slug: str, demo_soft: bool, xdll_seed: bytes) -> bytes:
    pub = pubkey_raw_from_priv(priv)
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = derive_key(hwid_bytes, pub, text_crc, slug, salt)
    ct = AESGCM(key).encrypt(nonce, payload, None)  # tag appended
    flags = 0x01 if demo_soft else 0x00
    header = MAGIC + struct.pack("<BBH", VERSION, flags, 0) + salt + nonce + struct.pack("<I", len(ct)) + ct
    header += build_xdll_section(xdll_seed, hwid_bytes)   # signed region, after ct, before sig (see note above)
    sig = priv.sign(header)
    return header + sig


def cmd_issue(args) -> None:
    priv = load_private()
    hwid_bytes = normalize_hwid(args.hwid)
    tier = TIER_PRO if args.tier == "pro" else TIER_FREE
    expires = 0 if args.expires in (None, "never") else int(time.time()) + int(args.expires) * 86400
    xdll_seed = os.urandom(32)   # one seed: feeds both the ENTL payload (sip_progate) and the XDLB unlock (ExtendedTools)
    payload = pack_entitlements(
        subject=args.subject, slug=args.slug, tier=tier, issued=int(time.time()), expires=expires,
        license_id=uuid.uuid4().bytes, xdll_seed=xdll_seed,
        mask_dump=args.mask_dump, mask_inject=args.mask_inject, mask_edit=args.mask_edit,
        mask_trap=args.mask_trap)
    blob = build_file(priv, hwid_bytes, args.text_crc, payload, args.slug, args.demo_soft, xdll_seed)
    out = Path(args.out) if args.out else HERE / "licenses" / f"{args.subject.replace(' ', '_')}.sipm"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(blob)
    print(f"issued {['FREE', 'PRO'][tier]} license -> {out}  ({len(blob)} bytes)")
    print(f"  subject   : {args.subject!r}")
    print(f"  slug      : {args.slug!r}")
    print(f"  hwid      : {args.hwid}")
    print(f"  text_crc  : 0x{args.text_crc & 0xFFFFFFFF:08X}")
    print(f"  expires   : {'perpetual' if expires == 0 else time.strftime('%Y-%m-%d', time.gmtime(expires))}")


def verify_file(blob: bytes, hwid_bytes: bytes, text_crc: int, pubkey_raw: bytes,
                slug: str) -> tuple[bool, str, dict | None]:
    """The reference verifier — mirrors exactly what src/pro_gate.cpp must do.

    Returns (ok, reason, entitlements). ok=False with a reason string on any failure; this is what a
    cracker sees go wrong, and the *stage* at which it fails is the lesson.
    """
    if len(blob) < 40 + 64 or blob[:4] != MAGIC:
        return False, "bad magic / truncated", None
    sig = blob[-64:]
    signed = blob[:-64]
    # 1) authenticity: did the issuer's private key sign these exact bytes?
    try:
        Ed25519PublicKey.from_public_bytes(pubkey_raw).verify(sig, signed)
    except Exception:
        return False, "Ed25519 signature invalid (payload forged or tampered; no private key)", None
    version, _flags, _res = struct.unpack_from("<BBH", blob, 4)
    if version != VERSION:
        return False, f"unsupported version {version}", None
    salt = blob[8:24]
    nonce = blob[24:36]
    (ct_len,) = struct.unpack_from("<I", blob, 36)
    ct = blob[40:40 + ct_len]
    # 2) the entangled KDF: wrong HWID / patched .text / swapped pubkey all land here as a decrypt failure
    key = derive_key(hwid_bytes, pubkey_raw, text_crc, slug, salt)
    try:
        payload = AESGCM(key).decrypt(nonce, ct, None)
    except Exception:
        return False, "AES-GCM auth failed — KDF mismatch (wrong HWID, patched .text, or swapped pubkey)", None
    ent = unpack_entitlements(payload)
    now = int(time.time())
    if ent["expires"] and now > ent["expires"]:
        return False, "license expired", ent
    if ent["slug"] != slug:
        return False, f"entitlement slug mismatch ({ent['slug']!r} != {slug!r})", ent
    # cross-DLL handshake self-check: locate the XDLB section (after ct, before sig) and confirm the unlock
    # blob opens under the recomputed handshake key. This is exactly what ExtendedTools does at runtime,
    # minus getting the response from sip_progate — here we recompute it from the decrypted seed.
    ent["xdll_ok"] = None
    xoff = 40 + ct_len
    if signed[xoff:xoff + 4] == XDLL_SECTION_MAGIC:
        challenge = signed[xoff + 4:xoff + 36]
        xnonce = signed[xoff + 36:xoff + 48]
        (xlen,) = struct.unpack_from("<H", signed, xoff + 48)
        xct = signed[xoff + 50:xoff + 50 + xlen]
        try:
            xpt = AESGCM(derive_xdll_key(ent["xdll_seed"], challenge, hwid_bytes)).decrypt(xnonce, xct, None)
            ent["xdll_ok"] = xpt[:4] == XUNLOCK_MAGIC
        except Exception:
            ent["xdll_ok"] = False
    return True, "ok", ent


def cmd_verify(args) -> None:
    priv = load_private()  # oracle verifies with the matching pubkey
    pub = pubkey_raw_from_priv(priv)
    ok, reason, ent = verify_file(Path(args.file).read_bytes(), normalize_hwid(args.hwid),
                                  args.text_crc, pub, args.slug)
    print(f"verify: {'PASS' if ok else 'FAIL'} — {reason}")
    if ent:
        print(f"  tier   : {['FREE', 'PRO'][ent['tier']]}")
        print(f"  subject: {ent['subject']!r}")
        print(f"  masks  : dump=0x{ent['mask_dump']:04X} inject=0x{ent['mask_inject']:04X} "
              f"edit=0x{ent['mask_edit']:04X} trap=0x{ent['mask_trap']:04X}")
        xdll = ent.get("xdll_ok")
        print(f"  xdll   : {'unlock blob OK (ExtendedTools will unlock)' if xdll else 'MISSING/BAD' if xdll is not None else 'no XDLB section (old license)'}")
    sys.exit(0 if ok else 1)


def cmd_attack(args) -> None:
    """Film reel: run the four shallow cracks against a real license and show each one failing, and
    at which stage. This is the 'cracked attempt' side of the side-by-side."""
    priv = load_private()
    pub = pubkey_raw_from_priv(priv)
    blob = Path(args.file).read_bytes()
    hwid = normalize_hwid(args.hwid)
    crc = args.text_crc

    def show(label, **kw):
        ok, reason, _ = verify_file(**{"blob": blob, "hwid_bytes": hwid, "text_crc": crc,
                                       "pubkey_raw": pub, "slug": args.slug, **kw})
        print(f"  {label:38s}: {'PASS' if ok else 'FAIL'} — {reason}")

    print("baseline (legit machine, unpatched binary, real pubkey):")
    show("as issued")
    print("\nshallow cracks a naive cracker tries:")
    show("[patch 1 byte of .text]", text_crc=crc ^ 0x1)
    show("[run on a different machine]", hwid_bytes=b"\xde\xad\xbe\xef" * 4)
    swapped = Ed25519PrivateKey.generate()
    swap_pub = pubkey_raw_from_priv(swapped)
    show("[swap embedded pubkey in .rdata]", pubkey_raw=swap_pub)
    # flip the tier byte in the ciphertext (no key) -> GCM tag / signature breaks
    tampered = bytearray(blob)
    if len(tampered) > 60:
        tampered[55] ^= 0x01
    ok, reason, _ = verify_file(bytes(tampered), hwid, crc, pub, args.slug)
    print(f"  {'[flip a ciphertext byte]':38s}: {'PASS' if ok else 'FAIL'} — {reason}")
    print("\nEvery shallow crack fails before reaching a comparable boolean. A working forge needs the"
          "\nprivate key (signature) AND the VM-recovered mask bases (or NtOpenProcess denies access).")


def _crc_arg(s: str) -> int:
    return int(s, 0) & 0xFFFFFFFF


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="System Informer Pro offline license signer (reference oracle).")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("genkey").set_defaults(func=cmd_genkey)
    sub.add_parser("pubkey-c").set_defaults(func=cmd_pubkey_c)

    def add_common(sp):
        sp.add_argument("--hwid", required=True, help="target HWID (hex or raw; VMProtectGetCurrentHWID)")
        sp.add_argument("--text-crc", dest="text_crc", type=_crc_arg, required=True,
                        help="CRC-32 of the protected on-disk image the verifier computes at runtime "
                             "(sip_report_tool prints it; e.g. 0xA1B2C3D4)")
        sp.add_argument("--slug", default=SLUG_DEFAULT)

    i = sub.add_parser("issue"); add_common(i)
    i.add_argument("--subject", required=True)
    i.add_argument("--tier", choices=("free", "pro"), default="pro")
    i.add_argument("--expires", default="never", help="days until expiry, or 'never'")
    i.add_argument("--out")
    i.add_argument("--demo-soft", action="store_true", help="set the DEMO_SOFT-permitted flag bit")
    i.add_argument("--mask-dump", type=_crc_arg, default=MASK_DUMP)
    i.add_argument("--mask-inject", type=_crc_arg, default=MASK_INJECT)
    i.add_argument("--mask-edit", type=_crc_arg, default=MASK_EDIT)
    i.add_argument("--mask-trap", type=_crc_arg, default=MASK_TRAP)
    i.set_defaults(func=cmd_issue)

    v = sub.add_parser("verify"); add_common(v)
    v.add_argument("file")
    v.set_defaults(func=cmd_verify)

    a = sub.add_parser("attack"); add_common(a)
    a.add_argument("file")
    a.set_defaults(func=cmd_attack)
    return p


def main(argv=None) -> None:
    args = build_parser().parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
