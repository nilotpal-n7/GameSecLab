#!/usr/bin/env python3
r"""Crypto-API call tracer (Frida) — lift a program's key schedule by watching the crypto primitives it
calls, without touching protected/virtualized code. Spawns the target suspended, hooks the standard crypto
exports (Windows CNG bcrypt + OpenSSL libcrypto EVP + legacy advapi CryptoAPI) plus GetProcAddress (to catch
primitives resolved dynamically), resumes, and prints the call sequence. Protectors like VMProtect virtualize
the *caller*, but the real APIs still run in the crypto DLLs — so this reads the HKDF/AES/HMAC block the way a
dynamic analyst would. For software you own / are authorized to analyse.

  python -m reaforge.tools.crypto_trace <exe> [args...] [--cwd DIR] [--secs N]

Notes: needs frida (pip). Uses the Frida 17 Module API (Process.getModuleByName(m).getExportByName(n)).
"""

from __future__ import annotations

import sys
import time

# Default crypto exports to watch, by module. Extend per target as needed.
DEFAULT_HOOKS = {
    "bcrypt.dll": [
        "BCryptOpenAlgorithmProvider",
        "BCryptCreateHash",
        "BCryptHashData",
        "BCryptFinishHash",
        "BCryptGenerateSymmetricKey",
        "BCryptDeriveKey",
        "BCryptKeyDerivation",
        "BCryptDecrypt",
        "BCryptEncrypt",
        "BCryptSetProperty",
    ],
    "libcrypto-1_1-x64.dll": ["EVP_DecryptInit_ex", "EVP_DecryptUpdate", "EVP_DecryptFinal_ex", "EVP_CIPHER_CTX_ctrl", "EVP_aes_256_gcm", "EVP_sha256", "HKDF", "HMAC"],
    "advapi32.dll": ["CryptDecrypt", "CryptDeriveKey", "CryptHashData", "CryptCreateHash"],
}
# GetProcAddress names containing any of these are reported (primitives resolved dynamically).
CRYPTO_HINTS = ("evp_", "bcrypt", "hkdf", "sha", "aes", "hmac", "pkey", "cipher", "digest", "crypt", "kdf")

_JS = r"""
var HOOKS = %s;
var HINTS = %s;
var HOOKED = {};
function expOf(mod, name) {
  try { var m = Process.findModuleByName(mod); if (!m) return null; return m.getExportByName(name); }
  catch (e) { return null; }
}
function installAll() {
  Object.keys(HOOKS).forEach(function (mod) {
    HOOKS[mod].forEach(function (name) {
      var key = mod + '!' + name;
      if (HOOKED[key]) return;
      var a = expOf(mod, name);
      if (!a) return;
      Interceptor.attach(a, { onEnter: function () { send({t:'call', n:name, m:mod}); } });
      HOOKED[key] = true;
      send({t:'hooked', n:name, m:mod});
    });
  });
}
installAll();
var ldr = expOf('ntdll.dll', 'LdrLoadDll');
if (ldr) Interceptor.attach(ldr, { onLeave: function () { installAll(); } });
var intv = setInterval(installAll, 3);
setTimeout(function(){ clearInterval(intv); }, 5000);
var gpa = expOf('kernel32.dll', 'GetProcAddress');
if (gpa) Interceptor.attach(gpa, { onEnter: function (args) {
  var pn = args[1];
  if (!pn.isNull() && pn.toInt32() > 0x10000) {
    try { var s = pn.readCString();
      if (s) { var l = s.toLowerCase(); for (var i=0;i<HINTS.length;i++) if (l.indexOf(HINTS[i])>=0) { send({t:'gpa', n:s}); break; } }
    } catch (e) {}
  }
}});
send({t:'ready'});
"""


def trace(exe, args=(), cwd=None, secs=6, hooks=None, hints=CRYPTO_HINTS, show=print):
    """Spawn `exe args` under Frida, trace crypto exports for `secs` seconds, return the call sequence."""
    import json

    import frida

    hooks = hooks or DEFAULT_HOOKS
    seq, dynamic = [], []
    pid = frida.spawn([exe, *args], cwd=cwd)
    session = frida.attach(pid)
    script = session.create_script(_JS % (json.dumps(hooks), json.dumps(list(hints))))

    def on_message(msg, data):
        if msg.get("type") == "error":
            show("  [script error] " + msg.get("description", str(msg)))
            return
        if msg.get("type") != "send":
            return
        p = msg["payload"]
        t = p.get("t")
        if t == "call":
            seq.append(p["n"])
            show(f"  [crypto] {p['m']}!{p['n']}")
        elif t == "gpa":
            dynamic.append(p["n"])
            show(f"  [GetProcAddress] {p['n']}")

    script.on("message", on_message)
    script.load()
    frida.resume(pid)
    time.sleep(secs)
    for fn in (session.detach, lambda: frida.kill(pid)):
        try:
            fn()
        except Exception:
            pass
    show(f"\n== crypto call sequence ({len(seq)}) ==")
    for i, s in enumerate(seq):
        show(f"  {i + 1:2}. {s}")
    if dynamic:
        show(f"\n== crypto primitives resolved via GetProcAddress ({len(set(dynamic))}) ==")
        for i, s in enumerate(dict.fromkeys(dynamic)):
            show(f"  {i + 1:2}. {s}")
    return seq, dynamic


def main(argv):
    if len(argv) < 2:
        sys.exit(__doc__)
    rest = argv[1:]
    cwd = None
    secs = 6
    if "--cwd" in rest:
        i = rest.index("--cwd")
        cwd = rest[i + 1]
        del rest[i : i + 2]
    if "--secs" in rest:
        i = rest.index("--secs")
        secs = int(rest[i + 1])
        del rest[i : i + 2]
    exe, args = rest[0], rest[1:]
    trace(exe, args, cwd=cwd, secs=secs)


if __name__ == "__main__":
    main(sys.argv)
