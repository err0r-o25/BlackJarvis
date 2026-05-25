"""Ollama HTTP client for BlackJarvis.

Supports both /api/generate (single-turn text) and /api/chat (multi-turn
with native function calling via the 'tools' parameter).
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any, Iterator

import requests

logger = logging.getLogger(__name__)


@dataclass
class OllamaConfig:
    base_url: str = "http://localhost:11434"
    model: str = "qwen2.5:7b"
    timeout: int = 300


class OllamaClient:
    def __init__(self, config: OllamaConfig | None = None) -> None:
        self.config = config or OllamaConfig()

    def is_alive(self) -> bool:
        try:
            r = requests.get(self.config.base_url, timeout=5)
            return r.status_code == 200
        except requests.RequestException:
            return False

    def generate(
        self,
        prompt: str,
        system: str | None = None,
        stream: bool = False,
        temperature: float = 0.7,
    ) -> str:
        """Single-turn text completion via /api/generate."""
        payload = {
            "model": self.config.model,
            "prompt": prompt,
            "stream": stream,
            "options": {"temperature": temperature},
        }
        if system is not None:
            payload["system"] = system
        r = requests.post(
            f"{self.config.base_url}/api/generate",
            json=payload, timeout=self.config.timeout,
        )
        r.raise_for_status()
        return r.json()["response"]

    def stream(
        self,
        prompt: str,
        system: str | None = None,
        temperature: float = 0.7,
    ) -> Iterator[str]:
        """Stream tokens from /api/generate."""
        payload = {
            "model": self.config.model,
            "prompt": prompt,
            "stream": True,
            "options": {"temperature": temperature},
        }
        if system is not None:
            payload["system"] = system
        with requests.post(
            f"{self.config.base_url}/api/generate",
            json=payload, timeout=self.config.timeout, stream=True,
        ) as r:
            r.raise_for_status()
            for line in r.iter_lines():
                if not line:
                    continue
                chunk = json.loads(line)
                if "response" in chunk:
                    yield chunk["response"]
                if chunk.get("done"):
                    break

    def chat(
        self,
        messages: list[dict],
        tools: list[dict] | None = None,
        temperature: float = 0.7,
    ) -> dict[str, Any]:
        """Multi-turn chat via /api/chat, with optional native tool calling.

        messages: [{"role": "system"|"user"|"assistant"|"tool", "content": "..."}]
        tools:    OpenAI-style function schemas (see core/router.py TOOL_SCHEMAS)

        Returns the assistant message dict. If the model decided to call a
        tool, it contains a 'tool_calls' list:
            {"role": "assistant", "content": "",
             "tool_calls": [{"function": {"name": "...", "arguments": {...}}}]}
        """
        payload: dict[str, Any] = {
            "model": self.config.model,
            "messages": messages,
            "stream": False,
            "options": {"temperature": temperature},
        }
        if tools:
            payload["tools"] = tools
        r = requests.post(
            f"{self.config.base_url}/api/chat",
            json=payload, timeout=self.config.timeout,
        )
        r.raise_for_status()
        return r.json()["message"]
