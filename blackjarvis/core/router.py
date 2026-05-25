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
2. {"tool": "subfinder", "args": {"target": "<domain>", "engagement": "<id>"}}
3. {"tool": "recon_pipeline", "args": {"target": "<domain>", "engagement": "<id>", "do_scan": false}}
4. {"tool": "recon_diff", "args": {"target": "<domain>", "engagement": "<id>", "type": "subs"}}
5. {"tool": "findings_list", "args": {"engagement": "<id>", "status": null}}
6. {"tool": "note_add", "args": {"engagement": "<id>", "text": "<note text>", "tag": ""}}
7. {"tool": "chat", "args": {"text": "<message>"}}

Rules:
- subfinder = subdomains only. recon_pipeline = full recon (subs+probe).
- recon_diff = "what changed / what's new" since last run.
- do_scan true ONLY if user explicitly wants a vuln/nuclei scan.

Examples:

User: list my engagements
{"tool": "list_engagements", "args": {}}

User: find subdomains for tesla.com on engagement tesla-bb
{"tool": "subfinder", "args": {"target": "tesla.com", "engagement": "tesla-bb"}}

User: do a full recon pipeline on example.com for iana-example
{"tool": "recon_pipeline", "args": {"target": "example.com", "engagement": "iana-example", "do_scan": false}}

User: full recon with vuln scan on example.com using iana-example
{"tool": "recon_pipeline", "args": {"target": "example.com", "engagement": "iana-example", "do_scan": true}}

User: what subdomains are new on example.com for iana-example
{"tool": "recon_diff", "args": {"target": "example.com", "engagement": "iana-example", "type": "subs"}}

User: what changed on example.com since last recon on iana-example
{"tool": "recon_diff", "args": {"target": "example.com", "engagement": "iana-example", "type": "subs"}}

User: show me findings for iana-example
{"tool": "findings_list", "args": {"engagement": "iana-example", "status": null}}

User: list draft findings for tesla-bb
{"tool": "findings_list", "args": {"engagement": "tesla-bb", "status": "draft"}}

User: take a note on iana-example that the search endpoint looks interesting
{"tool": "note_add", "args": {"engagement": "iana-example", "text": "the search endpoint looks interesting", "tag": ""}}

User: what is a subdomain
{"tool": "chat", "args": {"text": "what is a subdomain"}}

User: %s
"""


def parse_intent(raw: str) -> Intent:
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
    prompt = ROUTER_PROMPT % user_input
    raw = llm.generate(prompt=prompt, system=None, temperature=0.1)
    logger.debug("router raw output: %r", raw)
    try:
        intent = parse_intent(raw)
        logger.info("routed to tool=%s args=%s", intent.tool, intent.args)
        return intent
    except (ValueError, json.JSONDecodeError) as e:
        logger.warning("router parse failed (%s); falling back to chat", e)
        return Intent(tool="chat", args={"text": user_input})
