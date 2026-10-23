"""REAForge tool registry — detect every RE tool/lib installed on this machine.

Run:  python -m reaforge.tool_registry   (or: python tool_registry.py)
Prints a capability report and writes capabilities.json next to it.
"""
from __future__ import annotations
import json, os, shutil, subprocess, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent

# (name, kind, how-to-detect). path checks are Windows-first with sensible fallbacks.
PATHS = {
    "ghidra":   [r"C:\Tools\ghidra\ghidraRun.bat", r"C:\Tools\ghidra\support\analyzeHeadless.bat"],
    "x64dbg":   [r"C:\Tools\x96gdb\release\x96dbg.exe", r"C:\Tools\x96gdb\release\x64\x64dbg.exe"],
    "die":      [r"C:\Tools\DIE\diec.exe", r"C:\Tools\DIE\die.exe"],
    "gcc":      [r"C:\Tools\msys64\ucrt64\bin\gcc.exe"],
    "scyllahide": [r"C:\Tools\x96gdb\release\x64\plugins\ScyllaHide.dp64",
                   r"C:\Tools\x96gdb\release\x32\plugins\ScyllaHide.dp32"],
    "novmp":    [r"C:\Tools\NoVmp\NoVmp.exe"],
    "vmprotect":[r"C:\Tools\VMProtect\VMProtect.exe"],
    "themida":  [r"C:\Tools\Themida\Themida.exe", r"C:\Tools\Themida\Themida64.exe"],
}
PY_LIBS = ["capstone", "unicorn", "keystone", "lief", "pefile", "r2pipe", "frida", "angr", "triton"]
WSL_TOOLS = {"tigress": "tigress --version", "gdb": "gdb --version", "radare2": "r2 -v"}


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


def detect_wsl(cmd):
    try:
        out = subprocess.run(["wsl", "-d", "Ubuntu", "bash", "-lic", cmd],
                             capture_output=True, text=True, timeout=25)
        line = (out.stdout or out.stderr).strip().splitlines()
        return line[0] if line else None
    except Exception:
        return None


def collect():
    caps = {"native": {}, "python_libs": {}, "wsl": {}, "ai_backends": {}}
    for name, paths in PATHS.items():
        caps["native"][name] = _first_existing(paths)
    for lib in PY_LIBS:
        caps["python_libs"][lib] = detect_py_lib(lib)
    for name, cmd in WSL_TOOLS.items():
        caps["wsl"][name] = detect_wsl(cmd)
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
    for section in ("native", "python_libs", "wsl"):
        print(f"\n[{section}]")
        for k, v in caps[section].items():
            mark = "OK " if v else "-- "
            print(f"  {mark}{k:12} {v if v else 'not found'}")
    print("\n[ai_backends]")
    for k, v in caps["ai_backends"].items():
        print(f"  {k}: {v}")
    print(f"\nwrote {HERE/'capabilities.json'}")


if __name__ == "__main__":
    main()
