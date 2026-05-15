"""Command-line entry point for BLACKJARVIS."""
from __future__ import annotations

import argparse
import logging
import sys

from blackjarvis.core.router import route
from blackjarvis.core.tools import TOOL_REGISTRY
from blackjarvis.llm.ollama_client import OllamaClient
from blackjarvis.llm.prompts import SYSTEM_PROMPT
from blackjarvis.memory.engagement import (
    Engagement,
    list_engagements,
    new_engagement,
)
from blackjarvis.tools.subfinder import recon_subdomains
from blackjarvis.recon.pipeline import (
    run_recon_pipeline,
    persist_pipeline_result,
)


def setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def cmd_hello(args) -> int:
    client = OllamaClient()
    if not client.is_alive():
        print("❌ Ollama not reachable", file=sys.stderr)
        return 1
    print(f"✓ Ollama alive at {client.config.base_url}")
    print(f"✓ Model: {client.config.model}")
    print()
    print("BLACKJARVIS:")
    for chunk in client.stream(
        prompt="Introduce yourself in 3 short sentences.",
        system=SYSTEM_PROMPT,
    ):
        print(chunk, end="", flush=True)
    print()
    return 0


def cmd_ask(args) -> int:
    client = OllamaClient()
    if not client.is_alive():
        print("❌ Ollama not reachable", file=sys.stderr)
        return 1

    intent = route(args.prompt, client)
    print(f"[router] → {intent.tool} {intent.args}\n")

    handler = TOOL_REGISTRY.get(intent.tool)
    if handler is None:
        print(f"unknown tool: {intent.tool}")
        return 1

    observation = handler(intent.args, ctx={})

    if intent.tool == "chat":
        for chunk in client.stream(prompt=observation, system=SYSTEM_PROMPT):
            print(chunk, end="", flush=True)
        print()
    else:
        print(observation)
        print()
        print("--- summary ---")
        summary_prompt = (
            f"The user asked: {args.prompt!r}\n"
            f"You ran the {intent.tool} tool and got this output:\n\n"
            f"{observation}\n\n"
            f"In 2-3 short sentences, summarize what was found and suggest one concrete next step."
        )
        for chunk in client.stream(prompt=summary_prompt, system=SYSTEM_PROMPT):
            print(chunk, end="", flush=True)
        print()
    return 0


def cmd_eng_list(args) -> int:
    engs = list_engagements()
    if not engs:
        print("No engagements yet. Create one with: blackjarvis engagement new ...")
        return 0
    for e in engs:
        print(f"{e.id:24}  {e.name}")
        print(f"  in_scope:     {', '.join(e.scope.in_scope) or '(none)'}")
        if e.scope.out_of_scope:
            print(f"  out_of_scope: {', '.join(e.scope.out_of_scope)}")
    return 0


def cmd_eng_new(args) -> int:
    try:
        eng = new_engagement(
            args.id, args.name,
            in_scope=args.in_scope,
            out_of_scope=args.out_of_scope or [],
            platform=args.platform or "",
        )
    except FileExistsError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    print(f"✓ Created engagement {eng.id!r} at {eng.dir}")
    return 0


def cmd_recon_subs(args) -> int:
    try:
        eng = Engagement.load(args.engagement)
    except FileNotFoundError:
        print(f"Error: engagement {args.engagement!r} not found", file=sys.stderr)
        return 1
    try:
        result, path = recon_subdomains(args.target, eng, timeout=args.timeout)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    print(result.summary())
    print(f"saved → {path}")
    return 0


def cmd_recon_pipeline(args) -> int:
    try:
        eng = Engagement.load(args.engagement)
    except FileNotFoundError:
        print(f"Error: engagement {args.engagement!r} not found", file=sys.stderr)
        return 1
    try:
        result = run_recon_pipeline(
            args.target, eng,
            do_subs=True, do_probe=True, do_scan=args.scan,
            max_probe_hosts=args.max_probe,
            max_scan_hosts=args.max_scan,
        )
        path = persist_pipeline_result(result, eng)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    print(result.summary())
    print(f"\nsaved → {path}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="blackjarvis",
        description="Local AI assistant for security research and bug bounty.",
    )
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("hello", help="Sanity check: confirm LLM is alive.")

    p_ask = sub.add_parser("ask", help="Ask in plain English; routes to a tool.")
    p_ask.add_argument("prompt")

    p_eng = sub.add_parser("engagement", help="Manage engagements.")
    eng_sub = p_eng.add_subparsers(dest="eng_cmd", required=True)
    eng_sub.add_parser("list", help="List all engagements.")
    p_new = eng_sub.add_parser("new", help="Create a new engagement.")
    p_new.add_argument("id")
    p_new.add_argument("name")
    p_new.add_argument("--in-scope", nargs="+", required=True)
    p_new.add_argument("--out-of-scope", nargs="*", default=[])
    p_new.add_argument("--platform", default="")

    p_recon = sub.add_parser("recon", help="Run reconnaissance.")
    recon_sub = p_recon.add_subparsers(dest="recon_cmd", required=True)

    p_subs = recon_sub.add_parser("subs", help="Subdomain enumeration only.")
    p_subs.add_argument("--engagement", required=True)
    p_subs.add_argument("--target", required=True)
    p_subs.add_argument("--timeout", type=int, default=240)

    p_pipe = recon_sub.add_parser("pipeline", help="Full recon: subs → probe → (optional) scan.")
    p_pipe.add_argument("--engagement", required=True)
    p_pipe.add_argument("--target", required=True)
    p_pipe.add_argument("--scan", action="store_true",
                        help="Include nuclei vuln scan stage (slow).")
    p_pipe.add_argument("--max-probe", type=int, default=500)
    p_pipe.add_argument("--max-scan", type=int, default=100)

    return p


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    setup_logging(args.verbose)

    dispatch = {
        ("hello", None): cmd_hello,
        ("ask", None): cmd_ask,
        ("engagement", "list"): cmd_eng_list,
        ("engagement", "new"): cmd_eng_new,
        ("recon", "subs"): cmd_recon_subs,
        ("recon", "pipeline"): cmd_recon_pipeline,
    }
    sub_cmd = getattr(args, "eng_cmd", None) or getattr(args, "recon_cmd", None)
    handler = dispatch.get((args.command, sub_cmd))
    if handler is None:
        parser.print_help()
        return 1
    return handler(args)


if __name__ == "__main__":
    sys.exit(main())
