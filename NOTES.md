# NOTES — running learning log

Newest entries at the bottom. Write in your own words: what you did, what you saw, why it matters.

---

## 2026-10-22 — Setup

### Why not the Khazan install?

The first look at `C:\Games\The First Berserker - Khazan` showed it is the commercial game, not
a personal project:

- `KZ.exe` carries a valid Authenticode signature from **Neople Inc.** (DigiCert-issued).
- The UE project name is `BBQ` (`BBQ\Binaries\Win64\BBQ-Win64-Shipping.exe`), Steam app 2829250.
- `Clean_HV_Files.bat` removes FitGirl-repack and Denuvo-bypass files (`DenuvOwO.nfo`,
  `hyperkd.sys`, `SimpleSvm.sys`, a `steamclient64.dll` emulator, a `winmm.dll` proxy loader).

**Recon lesson already learned:** before running a single tool, three things told the whole
story — the code-signing certificate, the folder/project names, and leftover files. Real
analysts always start with "what is this, and where did it come from?"

**Security lesson:** hypervisor-based Denuvo bypasses require turning OFF Virtualization-Based
Security and Memory Integrity (HVCI) and loading a kernel/hypervisor driver from a crack —
that is ring -1 code from an anonymous source. Checked: VBS and HVCI are running again and no
crack drivers are registered.

### Targets chosen

- **Veloren v0.18.0** — open-source (GPL) 3D action RPG: melee, dodge-roll, health, energy
  (stamina). Single-player runs a *real server* inside your process -> perfect for seeing
  server authority overwrite client cheats.
- **Lyra Starter Game** — Epic's free UE5 sample, packaged as Shipping. Used for the
  Unreal-specific lessons (reflection, GObjects/GNames, ProcessEvent).

### Network note

`download.veloren.net` is intercepted by a **Fortinet FortiGate** TLS-inspection firewall on
this network (cert issuer `CN=FGT37DTK18800193`, not trusted by Windows). Did NOT disable
certificate checks. Got the official v0.18.0 build from Veloren's GitLab release instead.
That is itself a lesson: a man-in-the-middle box re-signing TLS is exactly what certificate
validation exists to catch.

### Re-downloading the target (targets/ is git-ignored)

- Source: GitLab release v0.18.0 -> "Windows (x86_64)" asset
  `https://gitlab.com/veloren/veloren/-/jobs/12844032151/artifacts/download`
- Saved as `targets\Veloren\_download\veloren-v0.18.0-windows-x86_64.zip` (464,592,174 bytes)
- SHA256 `71F07893D842F871C63C726095A92AFAEAE77941AF1D7186E54195032E335866`
- Extracted to `targets\Veloren\v0.18.0` (`veloren-voxygen.exe`, `veloren-server-cli.exe`, `assets\`)
