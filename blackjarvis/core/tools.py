"""Tool registry: maps tool names to Python callables the LLM can invoke."""
from __future__ import annotations

import logging
from typing import Callable

from blackjarvis.memory.engagement import (
    Engagement,
    OutOfScopeError,
    list_engagements,
)
from blackjarvis.memory.diff import diff_subfinder_runs, diff_httpx_runs
from blackjarvis.memory.findings import list_findings, new_finding
from blackjarvis.memory.notes import append_note
from blackjarvis.tools.subfinder import SubfinderError, recon_subdomains
from blackjarvis.tools.httpx import HttpxError, probe_targets
from blackjarvis.recon.pipeline import run_recon_pipeline, persist_pipeline_result

logger = logging.getLogger(__name__)

ToolFn = Callable[[dict, dict], str]
TOOL_REGISTRY: dict[str, ToolFn] = {}


def register(name: str):
    def deco(fn: ToolFn) -> ToolFn:
        TOOL_REGISTRY[name] = fn
        return fn
    return deco


def _load_engagement(eng_id: str) -> Engagement | str:
    """Load an engagement or return an error string."""
    if not eng_id:
        return "Error: an 'engagement' argument is required."
    try:
        return Engagement.load(eng_id)
    except FileNotFoundError:
        return f"Error: engagement {eng_id!r} not found."


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
    eng = _load_engagement(args.get("engagement", "").strip())
    if isinstance(eng, str):
        return eng
    if not target:
        return "Error: subfinder needs a 'target' argument."
    try:
        result, path = recon_subdomains(target, eng, timeout=240)
    except OutOfScopeError as e:
        return f"Refused (out of scope): {e}"
    except SubfinderError as e:
        return f"subfinder failed: {e}"
    preview = ", ".join(result.subdomains[:10])
    more = f" (+{len(result.subdomains) - 10} more)" if len(result.subdomains) > 10 else ""
    return f"{result.summary()}\nSaved to {path}.\nFirst subdomains: {preview}{more}"


@register("recon_pipeline")
def tool_recon_pipeline(args: dict, ctx: dict) -> str:
    target = args.get("target", "").strip()
    eng = _load_engagement(args.get("engagement", "").strip())
    if isinstance(eng, str):
        return eng
    if not target:
        return "Error: recon_pipeline needs a 'target' argument."
    do_scan = bool(args.get("do_scan", False))
    try:
        result = run_recon_pipeline(
            target, eng, do_subs=True, do_probe=True, do_scan=do_scan,
            max_probe_hosts=500,
        )
        path = persist_pipeline_result(result, eng)
    except OutOfScopeError as e:
        return f"Refused (out of scope): {e}"
    except Exception as e:
        return f"Pipeline error: {e}"
    return f"{result.summary()}\n\nPipeline summary saved to {path}."


@register("recon_diff")
def tool_recon_diff(args: dict, ctx: dict) -> str:
    target = args.get("target", "").strip()
    eng = _load_engagement(args.get("engagement", "").strip())
    if isinstance(eng, str):
        return eng
    diff_type = (args.get("type", "subs") or "subs").strip().lower()
    if not target:
        return "Error: recon_diff needs a 'target' argument."
    try:
        if diff_type == "probe":
            d = diff_httpx_runs(eng, target)
        else:
            d = diff_subfinder_runs(eng, target)
    except Exception as e:
        return f"Diff error: {e}"
    return d.summary()


@register("findings_list")
def tool_findings_list(args: dict, ctx: dict) -> str:
    eng = _load_engagement(args.get("engagement", "").strip())
    if isinstance(eng, str):
        return eng
    status = args.get("status") or None
    findings = list_findings(eng, status=status)
    if not findings:
        return f"No findings for engagement {eng.id!r}" + (
            f" with status {status!r}." if status else "."
        )
    lines = [f"Found {len(findings)} finding(s) for {eng.id!r}:"]
    for f in findings:
        lines.append(f"  [{f.severity}] {f.status}  {f.title}  ({f.id})")
    return "\n".join(lines)


@register("note_add")
def tool_note_add(args: dict, ctx: dict) -> str:
    eng = _load_engagement(args.get("engagement", "").strip())
    if isinstance(eng, str):
        return eng
    text = (args.get("text", "") or "").strip()
    if not text:
        return "Error: note_add needs a 'text' argument."
    tag = (args.get("tag", "") or "").strip()
    append_note(eng, text, tag=tag)
    return f"Note saved to engagement {eng.id!r}."


@register("chat")
def tool_chat(args: dict, ctx: dict) -> str:
    return args.get("text", "")
