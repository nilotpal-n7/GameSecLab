# reaforge/tests

Quick smoke tests across the arch x format matrix. Runnable with or without pytest.

```bash
python -m reaforge.tests.test_smoke                 # fast: no emulation
set RUN_CAMPAIGNS=1 && python -m reaforge.tests.test_smoke   # + real campaigns
pytest reaforge/tests/test_smoke.py                 # if pytest is installed
```

## What it covers

| test | checks | case |
| --- | --- | --- |
| `test_core_imports` | engine/peel import; `build_canon` for 32 AND 64 bit | arch matrix |
| `test_category_and_title_modules_import` | both category engines + both title configs import | EXE + DLL paths |
| `test_license_app_keygen` | clean-build keygen == VM-validated ground truth (5 serials) | — |
| `test_hashlink_ref_hash_edges` | `hl_hash_utf8` incl. sign-extension / signed-modulo edges | — |
| `test_campaign_x64_exe` | license_app validate battery -> ALL PASS | **x64 + EXE** |
| `test_campaign_x86_dll` | Dead Cells libhl validate battery -> ALL PASS | **x86 + DLL** |

The two campaign tests are opt-in (`RUN_CAMPAIGNS=1`) and need vmp-lazy-unpack + the authorized
binaries present. The matrix we have targets for is x64-EXE and x86-DLL; x86-EXE and x64-DLL slot in
the same way once a title of that shape is added (the engine and peeler are already arch-agnostic).
