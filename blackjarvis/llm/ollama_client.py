"""Ollama HTTP client for BlackJarvis."""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Iterator

import requests

logger = logging.getLogger(__name__)


@dataclass
class OllamaConfig:
    base_url: str = "http://localhost:11434"
    model: str = "qwen2.5:3b"
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
            json=payload,
            timeout=self.config.timeout,
        )
        r.raise_for_status()
        return r.json()["response"]

    def stream(
        self,
        prompt: str,
        system: str | None = None,
        temperature: float = 0.7,
    ) -> Iterator[str]:
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
            json=payload,
            timeout=self.config.timeout,
            stream=True,
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
