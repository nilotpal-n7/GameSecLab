# Category: hashlink

Haxe / Heaps / **HashLink** games. They all ship the same runtime, `libhl.dll`, so its internals are
**category-level ground truth**, reusable across every HashLink title (Dead Cells, Northgard,
Evoland, ...) — not a per-title secret.

The campaign targets the exported string hash `hl_hash_utf8` (HashLink `src/std/obj.c`):

```c
int hl_hash_utf8(const char *name){ int h=0; while(*name){ h=223*h+(unsigned)*name; name++; } h%=0x1FFFFF7B; return h; }
```

Two semantics matter and are reproduced in `ref_hash`:

- `(unsigned)*name` **sign-extends** the signed `char` (`0xFF` -> `0xFFFFFFFF`),
- the final `%=` is a **signed** modulo.

`campaign.py` resolves the protected export, validates the VM against this source hash, then recovers
/ peels (per-byte linear fold `acc = 223*acc + signext(byte)`) / proves it symbolically. The `hl_hash`
constants, `ref_hash`, and the test-string battery live here (category level); a title config supplies
only the packed binary + snapshot path.

See `targets/dead_cells/config.py` — it is intentionally tiny.
