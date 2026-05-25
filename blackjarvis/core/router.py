"""Tool router using Ollama native function calling.

Replaces the prompt-based JSON router. Tools are defined as OpenAI-style
function schemas; the model returns structured tool_calls directly.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from blackjarvis.llm.ollama_client import OllamaClient

logger = logging.getLogger(__name__)


@dataclass
class Intent:
    tool: str
    args: dict[str, Any]


ROUTER_SYSTEM = (
    "You are BLACKJARVIS, a local pentest assistant. "
    "When the user asks to perform an action, call the appropriate tool. "
    "For greetings, definitions, or conceptual questions, respond "
    "conversationally without calling a tool."
)

TOOL_SCHEMAS: list[dict] = [
    {
        "type": "function",
        "function": {
            "name": "list_engagements",
            "description": "List all engagements (bug bounty programs or labs) the user has configured.",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "subfinder",
            "description": "Discover subdomains for a target domain via passive recon only. Use when the user wants subdomains and nothing else.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Root domain, e.g. example.com"},
                    "engagement": {"type": "string", "description": "Engagement ID this work belongs to"},
                },
                "required": ["target", "engagement"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "recon_pipeline",
            "description": "Run the full recon chain: subfinder then httpx host probing, optionally a nuclei vuln scan. Use for 'full recon', 'recon pipeline', 'complete recon'.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Root domain"},
                    "engagement": {"type": "string", "description": "Engagement ID"},
                    "do_scan": {
                        "type": "boolean",
                        "description": "Include the nuclei vulnerability scan stage. Only true if the user explicitly asks for a vuln/nuclei scan.",
                    },
                },
                "required": ["target", "engagement"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "recon_diff",
            "description": "Compare the two most recent recon runs and show what changed. Use for 'what's new', 'what changed since last recon', 'new subdomains'.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Root domain"},
                    "engagement": {"type": "string", "description": "Engagement ID"},
                    "type": {
                        "type": "string",
                        "enum": ["subs", "probe"],
                        "description": "'subs' to diff subdomain enumeration, 'probe' to diff httpx probing.",
                    },
                },
                "required": ["target", "engagement"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "findings_list",
            "description": "List vulnerability findings recorded for an engagement.",
            "parameters": {
                "type": "object",
                "properties": {
                    "engagement": {"type": "string", "description": "Engagement ID"},
                    "status": {
                        "type": "string",
                        "description": "Optional status filter: draft, reported, triaged, duplicate, resolved.",
                    },
                },
                "required": ["engagement"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "note_add",
            "description": "Save a quick timestamped note to an engagement's scratchpad.",
            "parameters": {
                "type": "object",
                "properties": {
                    "engagement": {"type": "string", "description": "Engagement ID"},
                    "text": {"type": "string", "description": "The note content"},
                    "tag": {"type": "string", "description": "Optional short tag, e.g. 'idea'"},
                },
                "required": ["engagement", "text"],
            },
        },
    },
]


def route(user_input: str, llm: OllamaClient) -> Intent:
    """Classify the user request via native function calling.

    Falls back to the 'chat' tool if the model returns no tool call.
    """
    messages = [
        {"role": "system", "content": ROUTER_SYSTEM},
        {"role": "user", "content": user_input},
    ]
    try:
        msg = llm.chat(messages=messages, tools=TOOL_SCHEMAS, temperature=0.1)
    except Exception as e:
        logger.warning("router chat call failed (%s); falling back to chat", e)
        return Intent(tool="chat", args={"text": user_input})

    tool_calls = msg.get("tool_calls") or []
    if tool_calls:
        fn = tool_calls[0].get("function", {})
        name = fn.get("name", "")
        raw_args = fn.get("arguments", {})
        # Ollama may return arguments as a dict or a JSON string
        if isinstance(raw_args, str):
            import json
            try:
                raw_args = json.loads(raw_args)
            except json.JSONDecodeError:
                raw_args = {}
        logger.info("routed to tool=%s args=%s", name, raw_args)
        return Intent(tool=name, args=raw_args or {})

    logger.info("no tool call; routing to chat")
    return Intent(tool="chat", args={"text": user_input})
