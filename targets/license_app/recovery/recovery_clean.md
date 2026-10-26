# Clean-build recovery — baseline (IDA Pro 9.1)

**Difficulty: trivial (minutes).** No protection, MinGW symbols, `-O2` inlined `machine_id()`+`expected_key()`
into `check_license`, which Hex-Rays decompiled cleanly. This is the "before" measurement for the capstone.

## Recovered `check_license` (IDA Hex-Rays, verbatim logic)

```c
GetVolumeInformationA("C:\\", 0,0, &serial, 0,0,0,0);
v4 = serial ^ 0x1505;                 // acc = machine_id ^ 0x1505
v2 = 0; v3 = 0;                        // v2 = i*7 counter, v3 = nibble shift
do {
    v5 = 33 * v4;
    v6 = serial >> v3;  v3 += 4;
    v4 = v2 + (v5 ^ (v6 & 0xF));       // acc = i*7 + (33*acc ^ ((mid>>4i)&0xF))
    v2 += 7;
} while (v2 != 56);                    // 8 rounds (0,7,..,56)
return strtoul(key,0,16) == v4;
```

## Keygen (reconstructed from the decompile only): `keygen_recovered.c`

Reads C: volume serial, recomputes v4, prints the 8-hex key. Verified:
`keygen_recovered.exe` -> `75685AB2` -> `license_app.exe 75685AB2` -> **LICENSED** (matches original keygen).

## How this was done (headless, via REAForge)

`idat.exe -A -S reaforge/ida_decompile.py license_app_ida.exe` -> wrote the pseudocode automatically.
So IDA is now a scriptable step in the toolchain, not just a GUI.

## Baseline takeaway

Symbols + no obfuscation + inlined logic = one decompile, one keygen. Next layers raise this cost:
OLLVM flattening -> control flow obscured; VMProtect -> logic virtualized (expect the
keygen recovery to go from minutes to much longer / need dump+devirtualize).
