"""REAForge LLM backend — pluggable AI brain.

A standalone tool cannot call *this* Claude Code chat session as an API. So the "AI" is pluggable:
  - AnthropicBackend : uses ANTHROPIC_API_KEY (best; needs your own key)
  - OllamaBackend    : local, offline (needs Ollama running)
  - ManualBackend    : writes the prompt to a file; you paste it into a chat and paste the answer back
get_backend() auto-selects the first available, preferring Anthropic > Ollama > Manual.
"""
from __future__ import annotations
import json, os, urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent


class LLMBackend:
    name = "base"
    def complete(self, prompt: str, system: str = "") -> str:
        raise NotImplementedError


class AnthropicBackend(LLMBackend):
    name = "anthropic"
    MODEL = "claude-opus-4-8"   # update as needed
    def __init__(self):
        self.key = os.environ.get("ANTHROPIC_API_KEY")
        if not self.key:
            raise RuntimeError("ANTHROPIC_API_KEY not set")
    def complete(self, prompt: str, system: str = "") -> str:
        body = json.dumps({
            "model": self.MODEL, "max_tokens": 2048,
            "system": system or "You are an expert reverse-engineering planner.",
            "messages": [{"role": "user", "content": prompt}],
        }).encode()
        req = urllib.request.Request(
            "https://api.anthropic.com/v1/messages", data=body,
            headers={"x-api-key": self.key, "anthropic-version": "2023-06-01",
                     "content-type": "application/json"})
        with urllib.request.urlopen(req, timeout=120) as r:
            data = json.loads(r.read())
        return "".join(b.get("text", "") for b in data.get("content", []))


class OllamaBackend(LLMBackend):
    name = "ollama"
    def __init__(self, model: str = "llama3.1"):
        self.model = model
        with urllib.request.urlopen("http://localhost:11434/api/tags", timeout=3):
            pass  # raises if not running
    def complete(self, prompt: str, system: str = "") -> str:
        body = json.dumps({"model": self.model, "prompt": prompt, "system": system,
                           "stream": False}).encode()
        req = urllib.request.Request("http://localhost:11434/api/generate", data=body,
                                     headers={"content-type": "application/json"})
        with urllib.request.urlopen(req, timeout=300) as r:
            return json.loads(r.read()).get("response", "")


class ManualBackend(LLMBackend):
    """No AI configured: dump the prompt for a human (or this chat) to answer."""
    name = "manual"
    def complete(self, prompt: str, system: str = "") -> str:
        out = HERE / "llm_prompt.txt"
        out.write_text((f"[SYSTEM]\n{system}\n\n" if system else "") + f"[PROMPT]\n{prompt}\n")
        print(f"[manual LLM] wrote {out} — paste it to your AI, save the reply to llm_reply.txt")
        reply = HERE / "llm_reply.txt"
        return reply.read_text() if reply.exists() else "(no llm_reply.txt yet)"


def get_backend() -> LLMBackend:
    for ctor in (AnthropicBackend, OllamaBackend, ManualBackend):
        try:
            return ctor()
        except Exception:
            continue
    return ManualBackend()


if __name__ == "__main__":
    b = get_backend()
    print(f"selected backend: {b.name}")
