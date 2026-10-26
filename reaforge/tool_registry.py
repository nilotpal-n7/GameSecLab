"""REAForge tool registry — detect every RE tool/lib installed on this machine.

Run:  python -m reaforge.tool_registry   (or: python tool_registry.py)
Prints a capability report and writes capabilities.json next to it.
"""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent

# (name, kind, how-to-detect). path checks are Windows-first with sensible fallbacks.
PATHS = {
    "ghidra":   [r"C:\Tools\ghidra\ghidraRun.bat", r"C:\Tools\ghidra\support\analyzeHeadless.bat"],
    "x64dbg":   [r"C:\Tools\x96dbg\release\x96dbg.exe", r"C:\Tools\x96dbg\release\x64\x64dbg.exe"],
    "die":      [r"C:\Tools\DIE\diec.exe", r"C:\Tools\DIE\die.exe"],
    "gcc":      [r"C:\Tools\msys64\ucrt64\bin\gcc.exe"],
    "ollvm_clang": [r"C:\Tools\ollvm\install\bin\clang.exe"],  # Hikari/Arkari OLLVM fork (capstone C1)
    "ida":      [r"C:\Program Files\IDA Professional 9.1\ida.exe"],
    "ida_headless": [r"C:\Program Files\IDA Professional 9.1\idat.exe"],
    "scyllahide": [r"C:\Tools\x96dbg\release\x64\plugins\ScyllaHideX64DBGPlugin.dp64",
                   r"C:\Tools\x96dbg\release\x32\plugins\ScyllaHideX64DBGPlugin.dp32"],
    "novmp":    [r"C:\Tools\NoVmp\NoVmp.exe"],
    "vmprotect":[r"C:\Program Files\VMProtect Demo\VMProtect.exe", r"C:\Tools\VMProtect\VMProtect.exe"],
    "vmprotect_con":[r"C:\Program Files\VMProtect Demo\VMProtect_Con.exe"],
    "themida":  [r"C:\Tools\ThemidaDemo\Themida64.exe", r"C:\Tools\ThemidaDemo\Themida.exe"],
    "pin":      [r"C:\Tools\PIN\pin-external-4.4-99977-g54fbb8814-clang-windows\pin.exe", r"C:\Tools\PIN\pin.exe"],
}
PY_LIBS = ["capstone", "unicorn", "keystone", "lief", "pefile", "r2pipe", "frida", "angr", "triton"]

# WSL layout (see ENVIRONMENTS.md): Ubuntu = plain build box + Tigress;
# archlinux = BlackArch, the specialized Linux RE arsenal.
import re as _re

WSL_DISTROS = ["Ubuntu", "archlinux"]
WSL_TOOLS = {
    "Ubuntu":    ["gcc", "gdb", "tigress"],
    "archlinux": ["gcc", "clang", "gdb", "radare2", "rizin", "cutter",
                  "ghidra", "ropper", "ROPgadget", "nasm"],
}
# Strips OSC (shell-integration) + CSI escape noise some interactive distros emit.
_ANSI = _re.compile(r"\x1b\][^\x07]*(?:\x07|\x1b\\)|\x1b\[[0-9;?]*[A-Za-z]")


def _first_existing(paths):
    for p in paths:
        if os.path.exists(p):
            return p
    return None


def detect_py_lib(mod):
    try:
        m = __import__(mod)
        return getattr(m, "__version__", "installed")
    except Exception:
        return None


def _which_in(distro, tool):
    """Path of `tool` inside a WSL distro, or None. Validated: the probe must exit 0
    AND emit an actual path — so 'command not found' is no longer mistaken for found."""
    try:
        out = subprocess.run(["wsl", "-d", distro, "bash", "-lic",
                              f"command -v {tool} 2>/dev/null || true"],
                             capture_output=True, text=True, timeout=25)
    except Exception:
        return None
    if out.returncode != 0:
        return None
    for raw in (out.stdout or "").splitlines():
        line = _ANSI.sub("", raw).strip()
        if line.startswith("/") and "not found" not in line:
            return line
    return None


def _distro_up(distro):
    try:
        out = subprocess.run(["wsl", "-d", distro, "bash", "-lic", "true"],
                             capture_output=True, text=True, timeout=20)
        return out.returncode == 0
    except Exception:
        return False


def collect():
    caps = {"native": {}, "python_libs": {}, "wsl": {}, "ai_backends": {}}
    for name, paths in PATHS.items():
        caps["native"][name] = _first_existing(paths)
    for lib in PY_LIBS:
        caps["python_libs"][lib] = detect_py_lib(lib)
    for distro in WSL_DISTROS:
        up = _distro_up(distro)
        caps["wsl"][distro] = {"installed": up, "tools": {}}
        if up:
            for tool in WSL_TOOLS.get(distro, []):
                caps["wsl"][distro]["tools"][tool] = _which_in(distro, tool)
    # AI backends
    caps["ai_backends"]["anthropic_api_key"] = bool(os.environ.get("ANTHROPIC_API_KEY"))
    caps["ai_backends"]["ollama"] = _probe_ollama()
    caps["ai_backends"]["claude_code_driver"] = "available when run from the Claude Code session"
    return caps


def _probe_ollama():
    try:
        import urllib.request
        with urllib.request.urlopen("http://localhost:11434/api/tags", timeout=3) as r:
            data = json.loads(r.read())
            return [m.get("name") for m in data.get("models", [])] or "running (no models)"
    except Exception:
        return None


def main():
    caps = collect()
    (HERE / "capabilities.json").write_text(json.dumps(caps, indent=2))
    print("== REAForge capability report ==")
    for section in ("native", "python_libs"):
        print(f"\n[{section}]")
        for k, v in caps[section].items():
            mark = "OK " if v else "-- "
            print(f"  {mark}{k:12} {v if v else 'not found'}")
    print("\n[wsl]")
    for distro, info in caps["wsl"].items():
        print(f"  {distro} ({'installed' if info['installed'] else 'NOT INSTALLED'})")
        for tool, path in info.get("tools", {}).items():
            mark = "OK " if path else "-- "
            print(f"    {mark}{tool:12} {path if path else 'not found'}")
    print("\n[ai_backends]")
    for k, v in caps["ai_backends"].items():
        print(f"  {k}: {v}")
    print(f"\nwrote {HERE/'capabilities.json'}")


if __name__ == "__main__":
    main()
