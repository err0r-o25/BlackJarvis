"""Tool registry: maps tool names to Python callables the LLM can invoke.

Each tool takes a dict of args and a context dict, and returns a string
suitable for feeding back to the LLM as observation. Tools are responsible
for their own scope enforcement, persistence, and error handling.
"""
from __future__ import annotations

import logging
from typing import Callable

from blackjarvis.memory.engagement import (
    Engagement,
    OutOfScopeError,
    list_engagements,
)
from blackjarvis.tools.subfinder import (
    SubfinderError,
    recon_subdomains,
)

logger = logging.getLogger(__name__)

ToolFn = Callable[[dict, dict], str]
TOOL_REGISTRY: dict[str, ToolFn] = {}


def register(name: str):
    """Decorator: register a function as a tool the router can call."""
    def deco(fn: ToolFn) -> ToolFn:
        TOOL_REGISTRY[name] = fn
        return fn
    return deco


@register("list_engagements")
def tool_list_engagements(args: dict, ctx: dict) -> str:
    engs = list_engagements()
    if not engs:
        return "No engagements found."
    lines = [f"Found {len(engs)} engagement(s):"]
    for e in engs:
        in_scope = ", ".join(e.scope.in_scope[:3]) or "(none)"
        lines.append(f"  - {e.id}: {e.name}  [in_scope: {in_scope}]")
    return "\n".join(lines)


@register("subfinder")
def tool_subfinder(args: dict, ctx: dict) -> str:
    target = args.get("target", "").strip()
    eng_id = args.get("engagement", "").strip()
    if not target:
        return "Error: subfinder needs a 'target' argument."
    if not eng_id:
        return "Error: subfinder needs an 'engagement' argument."

    try:
        eng = Engagement.load(eng_id)
    except FileNotFoundError:
        return f"Error: engagement {eng_id!r} not found."

    try:
        result, path = recon_subdomains(target, eng, timeout=180)
    except OutOfScopeError as e:
        return f"Refused (out of scope): {e}"
    except SubfinderError as e:
        return f"subfinder failed: {e}"

    preview = ", ".join(result.subdomains[:10])
    more = f" (+{len(result.subdomains) - 10} more)" if len(result.subdomains) > 10 else ""
    return (
        f"{result.summary()}\n"
        f"Saved to {path}.\n"
        f"First subdomains: {preview}{more}"
    )


@register("chat")
def tool_chat(args: dict, ctx: dict) -> str:
    """No tool needed; the router classified this as conversational."""
    return args.get("text", "")
