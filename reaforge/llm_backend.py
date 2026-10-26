"""REAForge LLM backend — three modes, as requested.

  1) API mode     : multi-provider. Set a key + pick provider.
                    anthropic (ANTHROPIC_API_KEY) | openai (OPENAI_API_KEY) | gemini (GEMINI_API_KEY)
  2) Bridge mode  : NO pasting. REAForge writes the request to reaforge/bridge/pending.json and polls
                    for reply.json. When REAForge is RUN FROM the Claude Code session, Claude (me) sees
                    the pending request and writes the reply automatically -> hands-off while we work.
                    (Honest limit: this is automatic only while a Claude Code session is driving it;
                    it is not a 24/7 server. For unattended standalone runs, use API or Ollama.)
  3) Custom       : your own tool. Point CustomBackend at a command that reads prompt on stdin -> reply on stdout.

  + Ollama (local, offline) is also available: OllamaBackend (recommended model qwen2.5-coder:7b for 15GB RAM).

Select with env REAFORGE_LLM = api:anthropic | api:openai | api:gemini | bridge | ollama | custom
or call get_backend("bridge") etc. Default: auto (api if a key exists, else bridge).
"""
from __future__ import annotations

import json
import os
import subprocess
import time
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
BRIDGE = HERE / "bridge"; BRIDGE.mkdir(exist_ok=True)


class LLMBackend:
    name = "base"
    def complete(self, prompt: str, system: str = "") -> str: raise NotImplementedError


# ---------- 1) API mode (multi-provider) ----------
class AnthropicBackend(LLMBackend):
    name = "api:anthropic"; MODEL = "claude-opus-4-8"
    def __init__(self):
        self.key = os.environ["ANTHROPIC_API_KEY"]
    def complete(self, prompt, system=""):
        body = json.dumps({"model": self.MODEL, "max_tokens": 2048,
                           "system": system or "You are an expert RE planner.",
                           "messages": [{"role": "user", "content": prompt}]}).encode()
        req = urllib.request.Request("https://api.anthropic.com/v1/messages", data=body,
              headers={"x-api-key": self.key, "anthropic-version": "2023-06-01", "content-type": "application/json"})
        with urllib.request.urlopen(req, timeout=120) as r:
            return "".join(b.get("text", "") for b in json.loads(r.read())["content"])

class OpenAIBackend(LLMBackend):
    name = "api:openai"; MODEL = "gpt-4o"
    def __init__(self): self.key = os.environ["OPENAI_API_KEY"]
    def complete(self, prompt, system=""):
        body = json.dumps({"model": self.MODEL,
                           "messages": [{"role": "system", "content": system or "You are an expert RE planner."},
                                        {"role": "user", "content": prompt}]}).encode()
        req = urllib.request.Request("https://api.openai.com/v1/chat/completions", data=body,
              headers={"Authorization": f"Bearer {self.key}", "content-type": "application/json"})
        with urllib.request.urlopen(req, timeout=120) as r:
            return json.loads(r.read())["choices"][0]["message"]["content"]

class GeminiBackend(LLMBackend):
    name = "api:gemini"; MODEL = "gemini-2.0-flash"
    def __init__(self): self.key = os.environ.get("GEMINI_API_KEY") or os.environ["GOOGLE_API_KEY"]
    def complete(self, prompt, system=""):
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.MODEL}:generateContent?key={self.key}"
        body = json.dumps({"contents": [{"parts": [{"text": (system + "\n\n" + prompt).strip()}]}]}).encode()
        req = urllib.request.Request(url, data=body, headers={"content-type": "application/json"})
        with urllib.request.urlopen(req, timeout=120) as r:
            return json.loads(r.read())["candidates"][0]["content"]["parts"][0]["text"]


# ---------- 2) Bridge mode (Claude Code answers automatically) ----------
class BridgeBackend(LLMBackend):
    name = "bridge"
    def __init__(self, timeout=600): self.timeout = timeout
    def complete(self, prompt, system=""):
        rid = str(int(time.time() * 1000))
        (BRIDGE / "pending.json").write_text(json.dumps({"id": rid, "system": system, "prompt": prompt}, indent=2))
        print(f"[bridge] request {rid} written to {BRIDGE/'pending.json'} — waiting for Claude Code to reply...")
        reply = BRIDGE / f"reply_{rid}.json"
        deadline = time.time() + self.timeout
        while time.time() < deadline:
            if reply.exists():
                ans = json.loads(reply.read_text()).get("answer", "")
                reply.unlink(missing_ok=True); (BRIDGE / "pending.json").unlink(missing_ok=True)
                return ans
            time.sleep(1)
        return "(bridge timeout: no Claude Code session answered)"


# ---------- 3) Custom (your own tool) ----------
class CustomBackend(LLMBackend):
    name = "custom"
    def __init__(self): self.cmd = os.environ.get("REAFORGE_CUSTOM_CMD", "")
    def complete(self, prompt, system=""):
        if not self.cmd:
            return "(set REAFORGE_CUSTOM_CMD to your tool: reads prompt on stdin, prints reply on stdout)"
        p = subprocess.run(self.cmd, input=(system + "\n\n" + prompt), shell=True,
                           capture_output=True, text=True, timeout=600)
        return p.stdout


# ---------- optional: local Ollama ----------
class OllamaBackend(LLMBackend):
    name = "ollama"
    def __init__(self, model="qwen2.5-coder:7b"):
        self.model = os.environ.get("REAFORGE_OLLAMA_MODEL", model)
        urllib.request.urlopen("http://localhost:11434/api/tags", timeout=3)
    def complete(self, prompt, system=""):
        body = json.dumps({"model": self.model, "prompt": prompt, "system": system, "stream": False}).encode()
        req = urllib.request.Request("http://localhost:11434/api/generate", data=body,
                                     headers={"content-type": "application/json"})
        with urllib.request.urlopen(req, timeout=600) as r:
            return json.loads(r.read()).get("response", "")


def get_backend(select: str | None = None) -> LLMBackend:
    select = select or os.environ.get("REAFORGE_LLM", "auto")
    table = {"api:anthropic": AnthropicBackend, "api:openai": OpenAIBackend, "api:gemini": GeminiBackend,
             "bridge": BridgeBackend, "ollama": OllamaBackend, "custom": CustomBackend}
    if select in table:
        return table[select]()
    # auto: first working API key, else bridge
    for ctor in (AnthropicBackend, OpenAIBackend, GeminiBackend):
        try: return ctor()
        except Exception: continue
    return BridgeBackend()


if __name__ == "__main__":
    import sys
    b = get_backend(sys.argv[1] if len(sys.argv) > 1 else None)
    print(f"selected backend: {b.name}")
