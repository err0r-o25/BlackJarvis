"""Tool registry: maps tool names to Python callables the LLM can invoke.

Each tool takes a dict of args and a context dict, and returns a string
suitable for feeding back to the LLM as observation.
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
from blackjarvis.tools.httpx import (
    HttpxError,
    probe_targets,
)
from blackjarvis.recon.pipeline import (
    run_recon_pipeline,
    persist_pipeline_result,
)

logger = logging.getLogger(__name__)

ToolFn = Callable[[dict, dict], str]
TOOL_REGISTRY: dict[str, ToolFn] = {}


def register(name: str):
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
        result, path = recon_subdomains(target, eng, timeout=240)
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


@register("probe")
def tool_probe(args: dict, ctx: dict) -> str:
    """Probe a list of hosts (or 'all subs from last subfinder run') with httpx."""
    eng_id = args.get("engagement", "").strip()
    targets_arg = args.get("targets", [])
    label = args.get("label", "manual").strip() or "manual"

    if not eng_id:
        return "Error: probe needs an 'engagement' argument."
    if not targets_arg:
        return "Error: probe needs a 'targets' list."

    try:
        eng = Engagement.load(eng_id)
    except FileNotFoundError:
        return f"Error: engagement {eng_id!r} not found."

    # Accept either list or comma-separated string
    if isinstance(targets_arg, str):
        targets = [t.strip() for t in targets_arg.split(",") if t.strip()]
    else:
        targets = list(targets_arg)

    try:
        result, path = probe_targets(targets, eng, label=label, timeout=300)
    except OutOfScopeError as e:
        return f"Refused (out of scope): {e}"
    except HttpxError as e:
        return f"httpx failed: {e}"

    alive_preview = "\n".join(
        f"  {h.status_code} {h.url} tech={h.tech}" for h in result.alive_hosts[:5]
    )
    return f"{result.summary()}\nSaved to {path}.\n{alive_preview}"


@register("recon_pipeline")
def tool_recon_pipeline(args: dict, ctx: dict) -> str:
    """Full recon chain: subfinder → httpx → (optionally) nuclei."""
    target = args.get("target", "").strip()
    eng_id = args.get("engagement", "").strip()
    do_scan = bool(args.get("do_scan", False))

    if not target:
        return "Error: recon_pipeline needs a 'target' argument."
    if not eng_id:
        return "Error: recon_pipeline needs an 'engagement' argument."

    try:
        eng = Engagement.load(eng_id)
    except FileNotFoundError:
        return f"Error: engagement {eng_id!r} not found."

    try:
        result = run_recon_pipeline(
            target, eng,
            do_subs=True, do_probe=True, do_scan=do_scan,
            max_probe_hosts=500,
        )
        path = persist_pipeline_result(result, eng)
    except OutOfScopeError as e:
        return f"Refused (out of scope): {e}"
    except Exception as e:
        return f"Pipeline error: {e}"

    return f"{result.summary()}\n\nPipeline summary saved to {path}."


@register("chat")
def tool_chat(args: dict, ctx: dict) -> str:
    return args.get("text", "")
