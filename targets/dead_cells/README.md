# Target: dead_cells (hashlink category)

Our own VMProtect 3.11-protected copy of **Dead Cells'** `libhl.dll` (the HashLink runtime, x86/PE32).
We virtualized the exported string hash `hl_hash_utf8` (Ultra + packing) as a real-game benchmark for
the devirtualizer.

Dead Cells is a HashLink game, so the hashing ground truth is category-level
(`categories/hashlink/`). This title only names its binary + snapshot in `config.py`.

## Layout

- `config.py` — packed binary + snapshot path (tiny; HashLink does the rest).
- `benchmark.md` — the full Dead Cells VMProtect 3.11 benchmark write-up (scope, versions, results).
- `recovery/` — recovery notes.  `dumps/` — `libhl.vmp.dll`, snapshot, trace (**gitignored**).

## Run

```bash
python -m reaforge.core dead_cells [N] [modes]
```

Result: the virtualized `hl_hash_utf8` matches the HashLink source hash on the full battery; the
symbolic engine recovers it, peels the per-byte linear fold, and the all-inputs proof confirms it.

> Access note: the installed game folder (`C:\Games\Dead Cells`) is off-limits except its `ModTools`
> and `lang` subfolders — see the lab memory rule. The packed `libhl.vmp.dll` here was produced and
> placed by the user; nothing here reads the game install.
