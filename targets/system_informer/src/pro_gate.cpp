/* pro_gate.cpp — System Informer Pro licensing core (C++), exposed to SI's C code via pro_gate.h.
 *
 * Builds as a small static lib (sip_progate.lib) with the SAME CRT as System Informer (/MT release,
 * /MTd debug). Compile with /Zi /DEBUG /MAP so the VMProtect pass can resolve the marker symbols; the
 * .vmp pass then strips debug info and enables memory protection. VMProtect settings:
 *   - Ultra (virtualize) on the COLD choke points: sip_gate_init (verify/KDF), sip_access_mask (mask
 *     materialisation), sip_xdll_respond (plugin handshake). NEVER on hot loops.
 *   - Mutation on the reachability stubs (sip_is_pro, sip_nodbg).
 *   - VMProtectDecryptStringA on the entitlement slug and the offline-key material; the issuer pubkey is
 *     loaded inside the virtualised region so it is not a plaintext .rdata blob.
 *
 * STRICT VMProtect/MSVC rules honoured throughout (violating these yields "External jump into protected
 * block" at the .vmp pass or CRT-unwind corruption at runtime):
 *   - __declspec(noinline) on every function that carries a marker.
 *   - NO return/break/goto/throw between VMProtectBegin...()/VMProtectEnd(): compute into a local, fall
 *     through to VMProtectEnd(), then return after it. Error paths are guarded `if (rc==SIP_OK){...}`.
 *   - NO non-trivial-destructor C++ objects (std::string/std::vector/licenseseat::Result) inside a
 *     marker. All crypto/HWID go through the extern "C" sip_crypto.h seam (primitives, raw buffers), so
 *     nothing with a destructor ever lives across a marker boundary. Any LicenseSeat C++ object is built
 *     and destroyed OUTSIDE the markers, and only raw bytes are carried in.
 */
#include "pro_gate.h"
#include "si_pro_mask.h"
#include "sip_crypto.h"

#include <string.h>
#include <stdint.h>

/* Make the file buildable for local testing even without the VMProtect SDK on the include path; the
 * real protected build #includes the genuine header and the markers become VM entry/exit points. */
#if defined(__has_include)
#  if __has_include(<VMProtectSDK.h>)
#    include <VMProtectSDK.h>
#    define SIP_HAVE_VMP 1
#  endif
#endif
#ifndef SIP_HAVE_VMP
#  define VMProtectBeginUltra(n)        ((void)0)
#  define VMProtectBeginMutation(n)     ((void)0)
#  define VMProtectBegin(n)             ((void)0)
#  define VMProtectEnd()                ((void)0)
#  define VMProtectDecryptStringA(s)    (s)
#  define VMProtectIsDebuggerPresent(k) (0)
#  define VMProtectIsValidImageCRC()    (1)
#endif

/* --- DEMO_SOFT: filmable (detect+log, keep running) vs real (detect+corrupt). ---------------------- */
#ifdef DEMO_SOFT
#  define SIP_ON_TAMPER(state) /* detect-and-log: leave state as computed, surface the code */
#else
#  define SIP_ON_TAMPER(state) do { (state).tier = TIER_FREE; } while (0) /* detect-and-corrupt */
#endif

namespace {

constexpr uint8_t  kFileMagic[4] = { 'S', 'I', 'P', 'M' };
constexpr uint8_t  kEntMagic[4]  = { 'E', 'N', 'T', 'L' };
constexpr uint8_t  kVersion      = 1;
enum { TIER_FREE = 0, TIER_PRO = 1 };

/* Cached, post-verify Pro state. Plain-old-data (no destructors) so it is safe to touch from VM'd code. */
struct GateState {
    int      ok;            /* 1 iff a valid Pro license verified on this machine with this image      */
    uint32_t tier;
    uint32_t mask_base[SIP_FEAT__COUNT]; /* decrypted ACCESS_MASK bases (dump/inject/edit)             */
    uint32_t crc_ok;        /* 0/1: runtime .text CRC matched the value folded into the decrypt key    */
    uint32_t nodbg;         /* 0/1: no debugger observed                                                */
    uint8_t  xdll_seed[32]; /* cross-DLL rolling-key seed from the entitlements                         */
};
GateState g_state; /* zero-initialised */

/* Read a little-endian unsigned from a buffer (no alignment assumptions). */
inline uint32_t rd_u32(const uint8_t *p) { return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24); }
inline uint64_t rd_u64(const uint8_t *p) { uint64_t v = 0; for (int i = 0; i < 8; ++i) v |= (uint64_t)p[i] << (8 * i); return v; }
inline uint16_t rd_u16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }

/* Issuer Ed25519 public key (raw 32 bytes). In the protected build this array is referenced only from
 * inside the virtualised sip_gate_init, so it is not an addressable plaintext .rdata constant. Replace
 * with the bytes from `license_signer.py pubkey-c`. */
const uint8_t kIssuerPubKey[32] = {
    0x50, 0x7C, 0x40, 0x96, 0x9C, 0x1E, 0xBF, 0x49, 0x7C, 0xAE, 0x51, 0xF1, 0xB5, 0x47, 0x78, 0xF4,
    0x89, 0x84, 0xF9, 0x4E, 0x68, 0x59, 0x04, 0x12, 0x1A, 0xB9, 0x70, 0x81, 0x25, 0x60, 0xEB, 0xD8
};

/* Read the whole machine file into `buf` (<= cap). Returns length, or 0. Kept OUTSIDE every marker:
 * file I/O uses CRT handles we do not want unwinding through VM'd frames. */
size_t read_machine_file(const char *path, uint8_t *buf, size_t cap)
{
    const char *p = path ? path : "SystemInformer.sipm";
    FILE *f = nullptr;
    if (fopen_s(&f, p, "rb") != 0 || !f) return 0;
    size_t n = fread(buf, 1, cap, f);
    fclose(f);
    return n;
}

/* Layered anti-debug -> 0/1 (1 == clean). Mutation-protected; cheap enough for the cold path. */
__declspec(noinline) uint32_t sip_nodbg(void)
{
    uint32_t clean = 1;
    VMProtectBeginMutation("sip_nodbg");
    /* user+kernel via VMProtect */
    if (VMProtectIsDebuggerPresent(1 /*check kernel debugger too*/)) clean = 0;
    /* PEB BeingDebugged (x64) */
#if defined(_M_X64)
    {
        const uint8_t *peb = (const uint8_t *)__readgsqword(0x60);
        if (peb && peb[2]) clean = 0;                 /* BeingDebugged  */
        uint32_t ntg = *(const uint32_t *)(peb + 0xBC); /* NtGlobalFlag */
        if (ntg & 0x70) clean = 0;                    /* heap flags set by a debugger */
    }
    /* hardware breakpoints: any DR0-DR3 set, or DR7 enable bits */
    {
        CONTEXT ctx; memset(&ctx, 0, sizeof(ctx));
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (GetThreadContext(GetCurrentThread(), &ctx)) {
            if (ctx.Dr0 | ctx.Dr1 | ctx.Dr2 | ctx.Dr3 || (ctx.Dr7 & 0xFF)) clean = 0;
        }
    }
    /* timing: rdtsc delta across a cheap op; a single-stepping debugger inflates it */
    {
        unsigned long long t0 = __rdtsc();
        volatile uint32_t spin = 0; for (int i = 0; i < 64; ++i) spin += i;
        unsigned long long dt = __rdtsc() - t0;
        if (dt > 500000ULL) clean = 0;
    }
#endif
    VMProtectEnd();
    return clean;
}

} /* anonymous namespace */

/* ---- exported, extern "C" via pro_gate.h ---------------------------------------------------------- */

extern "C" SipInitResult sip_gate_init(const char *machine_file_path)
{
    /* All C++-with-destructor work (none here, but e.g. a LicenseSeat object) would go HERE, outside the
     * marker. We only read bytes into POD buffers before entering the VM region. */
    uint8_t file[4096];
    size_t  flen = read_machine_file(machine_file_path, file, sizeof(file));

    uint8_t hwid[256]; size_t hwid_len = sizeof(hwid);
    if (!sip_hwid(hwid, &hwid_len)) hwid_len = 0;
    uint32_t text_crc = sip_image_text_crc32();
    uint32_t nodbg    = sip_nodbg();

    SipInitResult rc = SIP_OK;

    VMProtectBeginUltra("sip_gate_init");
    GateState st; memset(&st, 0, sizeof(st));

    /* 0) structural checks (fall-through; no early return inside the marker) */
    if (flen < 40 + 64 || memcmp(file, kFileMagic, 4) != 0) rc = SIP_BAD_FORMAT;
    if (rc == SIP_OK && file[4] != kVersion)                rc = SIP_BAD_FORMAT;
    if (rc == SIP_OK && flen == 0)                          rc = SIP_NO_LICENSE;

    const uint8_t *sig    = file + (flen - 64);
    const uint8_t *signed_ = file;
    size_t signed_len     = flen - 64;

    /* 1) authenticity: issuer signature over everything but the trailing 64-byte sig */
    if (rc == SIP_OK && !sip_ed25519_verify(kIssuerPubKey, signed_, signed_len, sig))
        rc = SIP_SIG_INVALID;

    /* field offsets */
    const uint8_t *salt  = file + 8;      /* 16 */
    const uint8_t *nonce = file + 24;     /* 12 */
    uint32_t ct_len      = (rc == SIP_OK) ? rd_u32(file + 36) : 0;
    const uint8_t *ct    = file + 40;
    if (rc == SIP_OK && (40 + (size_t)ct_len + 64 > flen)) rc = SIP_BAD_FORMAT;

    /* 2) entangled KDF: ikm = hwid || pubkey(32) || text_crc(LE u32) || slug */
    uint8_t ikm[256 + 32 + 4 + 64];
    size_t  off = 0;
    if (rc == SIP_OK) {
        const char *slug = VMProtectDecryptStringA("enterprise-forensics");
        size_t slug_len  = strlen(slug);
        memcpy(ikm + off, hwid, hwid_len);                off += hwid_len;
        memcpy(ikm + off, kIssuerPubKey, 32);             off += 32;
        ikm[off++] = (uint8_t)(text_crc      );
        ikm[off++] = (uint8_t)(text_crc >> 8 );
        ikm[off++] = (uint8_t)(text_crc >> 16);
        ikm[off++] = (uint8_t)(text_crc >> 24);
        memcpy(ikm + off, slug, slug_len);                off += slug_len;
    }

    uint8_t key[32];
    if (rc == SIP_OK)
        sip_hkdf_sha256(ikm, off, salt, 16,
                        (const uint8_t *)VMProtectDecryptStringA("SIP-offline-v1"), 14, key);

    /* 3) decrypt: wrong HWID / patched .text / swapped pubkey all land here as auth failure */
    uint8_t pt[1024];
    if (rc == SIP_OK && (ct_len < 16 || ct_len - 16 > sizeof(pt) ||
                         !sip_aesgcm_decrypt(key, nonce, ct, ct_len, pt)))
        rc = SIP_KDF_MISMATCH;

    /* 4) parse entitlements (POD only) */
    if (rc == SIP_OK) {
        const uint8_t *p = pt;
        if (memcmp(p, kEntMagic, 4) != 0) rc = SIP_BAD_FORMAT;
        if (rc == SIP_OK) {
            p += 4;
            p += 16;                       /* license_id   */
            uint64_t issued  = rd_u64(p);  p += 8; (void)issued;
            uint64_t expires = rd_u64(p);  p += 8;
            st.tier          = rd_u32(p);  p += 4;
            uint16_t sn = rd_u16(p); p += 2; p += sn;              /* subject (skip) */
            uint16_t gl = rd_u16(p); p += 2;                       /* slug len       */
            const char *want = VMProtectDecryptStringA("enterprise-forensics");
            if (gl != strlen(want) || memcmp(p, want, gl) != 0) rc = SIP_SLUG_MISMATCH;
            p += gl;
            st.mask_base[SIP_FEAT_DUMP]   = rd_u32(p); p += 4;
            st.mask_base[SIP_FEAT_INJECT] = rd_u32(p); p += 4;
            st.mask_base[SIP_FEAT_EDIT]   = rd_u32(p); p += 4;
            /*   mask_trap */                           p += 4;
            memcpy(st.xdll_seed, p, 32);
            /* 5) time + integrity + debugger -> the entangled predicates */
            if (rc == SIP_OK && expires != 0) {
                /* time check without pulling <chrono> into the marker */
                uint64_t now = (uint64_t)_time64(nullptr);
                if (now > expires) rc = SIP_EXPIRED;
            }
            st.crc_ok = (uint32_t)(VMProtectIsValidImageCRC() ? 1u : 0u);
            st.nodbg  = nodbg;
            if (!st.nodbg) { SIP_ON_TAMPER(st); }
            st.ok = (rc == SIP_OK && st.tier == TIER_PRO && st.crc_ok && st.nodbg) ? 1 : 0;
        }
    }
    if (rc == SIP_OK && nodbg == 0) rc = SIP_DEBUGGER;

    g_state = st; /* publish */
    VMProtectEnd();
    return rc;
}

extern "C" int sip_is_pro(void)
{
    int v;
    VMProtectBeginMutation("sip_is_pro");
    v = g_state.ok;
    VMProtectEnd();
    return v;
}

extern "C" ACCESS_MASK sip_access_mask(int feature)
{
    ACCESS_MASK access;
    VMProtectBeginUltra("sip_access_mask");
    uint32_t idx  = (feature >= 0 && feature < SIP_FEAT__COUNT) ? (uint32_t)feature : 0;
    uint32_t base = g_state.mask_base[idx];
    /* entitled = licensed AND this is a Pro tier; crc_ok and nodbg from cached verify.
     * The mask is materialised HERE, inside the VM, so there is no plaintext mask->syscall seam. */
    uint32_t entitled = (g_state.ok && g_state.tier == TIER_PRO) ? 1u : 0u;
    access = sip_select_mask(base, SIP_TRAP_MASK, entitled, g_state.crc_ok, g_state.nodbg);
    VMProtectEnd();
    return access;
}

extern "C" int sip_xdll_respond(const unsigned char challenge[32], unsigned char response_out[32])
{
    int ok = 0;
    VMProtectBeginUltra("sip_xdll_respond");
    /* rolling response = HKDF(seed || challenge, salt=hwid, info="SIP-xdll-v1").
     * Both modules derive the same seed from the verified license, so only a genuinely Pro-verified pair
     * can complete the handshake; patched-but-unlicensed cannot produce a matching response. */
    if (g_state.ok && g_state.tier == TIER_PRO) {
        uint8_t hwid[256]; size_t hl = sizeof(hwid);
        if (sip_hwid(hwid, &hl)) {
            uint8_t ikm[64];
            memcpy(ikm, g_state.xdll_seed, 32);
            memcpy(ikm + 32, challenge, 32);
            sip_hkdf_sha256(ikm, 64, hwid, hl,
                            (const uint8_t *)VMProtectDecryptStringA("SIP-xdll-v1"), 11, response_out);
            ok = 1;
        }
    }
    VMProtectEnd();
    return ok;
}
