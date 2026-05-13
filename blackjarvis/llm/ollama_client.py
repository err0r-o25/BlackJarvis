"""Ollama HTTP client for BlackJarvis.

Talks to a locally running Ollama instance. All requests stay on the machine.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Iterator

import requests

logger = logging.getLogger(__name__)


@dataclass
class OllamaConfig:
    """Configuration for the Ollama client."""
    base_url: str = "http://localhost:11434"
    model: str = "qwen2.5:3b"
    timeout: int = 120


class OllamaClient:
    """Thin wrapper around the Ollama HTTP API."""

    def __init__(self, config: OllamaConfig | None = None) -> None:
        self.config = config or OllamaConfig()

    def is_alive(self) -> bool:
        """Check if the Ollama daemon is reachable."""
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
    ) -> str:
        """Send a single-turn prompt, return the full response as a string."""
        payload = {
            "model": self.config.model,
            "prompt": prompt,
            "stream": stream,
        }
        if system is not None:
            payload["system"] = system

        logger.debug("Sending prompt to model=%s len=%d", self.config.model, len(prompt))
        r = requests.post(
            f"{self.config.base_url}/api/generate",
            json=payload,
            timeout=self.config.timeout,
        )
        r.raise_for_status()
        return r.json()["response"]

    def stream(self, prompt: str, system: str | None = None) -> Iterator[str]:
        """Stream tokens as they arrive. Yields text chunks."""
        import json
        payload = {
            "model": self.config.model,
            "prompt": prompt,
            "stream": True,
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
