"""LLM-driven tool router with JSON intent format."""
from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from typing import Any

from blackjarvis.llm.ollama_client import OllamaClient

logger = logging.getLogger(__name__)


@dataclass
class Intent:
    tool: str
    args: dict[str, Any]


ROUTER_PROMPT = """You are a JSON tool router. Output ONLY a JSON object. No prose.

Tools:
1. {"tool": "list_engagements", "args": {}}
   - When user asks to list/show/see engagements or projects.
2. {"tool": "subfinder", "args": {"target": "<domain>", "engagement": "<id>"}}
   - When user asks to find/discover/enumerate subdomains.
3. {"tool": "chat", "args": {"text": "<user message>"}}
   - For anything else.

Examples:

User: list all my engagements
{"tool": "list_engagements", "args": {}}

User: show me my projects
{"tool": "list_engagements", "args": {}}

User: what engagements do I have
{"tool": "list_engagements", "args": {}}

User: find subdomains for tesla.com on engagement tesla-bb
{"tool": "subfinder", "args": {"target": "tesla.com", "engagement": "tesla-bb"}}

User: enumerate subs for example.com using iana-example
{"tool": "subfinder", "args": {"target": "example.com", "engagement": "iana-example"}}

User: hello how are you
{"tool": "chat", "args": {"text": "hello how are you"}}

User: %s
"""

JSON_RE = re.compile(r"\{.*?\}(?:\s*\})*", re.DOTALL)


def parse_intent(raw: str) -> Intent:
    """Extract a tool-shaped JSON object from raw model output.

    Tries each {...} match in order. Returns the first one that has 'tool'.
    """
    matches = re.findall(r"\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}", raw, re.DOTALL)
    last_err: Exception | None = None
    for candidate in matches:
        try:
            obj = json.loads(candidate)
        except json.JSONDecodeError as e:
            last_err = e
            continue
        if isinstance(obj, dict) and "tool" in obj:
            return Intent(tool=obj["tool"], args=obj.get("args", {}))
    if last_err:
        raise ValueError(f"no valid tool JSON found; last error: {last_err}")
    raise ValueError(f"no JSON object with 'tool' key in: {raw[:300]!r}")


def route(user_input: str, llm: OllamaClient) -> Intent:
    """Ask the LLM to classify intent. Fall back to 'chat' on parse failure."""
    prompt = ROUTER_PROMPT % user_input
    # Lower temperature → more deterministic, sticks to format
    raw = llm.generate(prompt=prompt, system=None, temperature=0.1)
    logger.debug("router raw output: %r", raw)
    try:
        intent = parse_intent(raw)
        logger.info("routed to tool=%s args=%s", intent.tool, intent.args)
        return intent
    except (ValueError, json.JSONDecodeError) as e:
        logger.warning("router parse failed (%s); falling back to chat", e)
        return Intent(tool="chat", args={"text": user_input})
