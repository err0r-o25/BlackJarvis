"""Command-line entry point for BlackJarvis."""
from __future__ import annotations

import argparse
import logging
import sys

from blackjarvis.llm.ollama_client import OllamaClient, OllamaConfig
from blackjarvis.llm.prompts import SYSTEM_PROMPT


def setup_logging(verbose: bool) -> None:
    """Configure root logger."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def cmd_hello(args: argparse.Namespace) -> int:
    """First contact: ensure Ollama is alive and the model responds."""
    client = OllamaClient()

    if not client.is_alive():
        print("❌ Ollama daemon not reachable at", client.config.base_url, file=sys.stderr)
        return 1

    print(f"✓ Ollama is alive at {client.config.base_url}")
    print(f"✓ Using model: {client.config.model}")
    print()
    print("BLACKJARVIS:")
    for chunk in client.stream(
        prompt="Introduce yourself in 3 short sentences. Mention you run locally on a GTX 1650 Ti.",
        system=SYSTEM_PROMPT,
    ):
        print(chunk, end="", flush=True)
    print()
    return 0


def cmd_ask(args: argparse.Namespace) -> int:
    """Ask BlackJarvis a one-shot question."""
    client = OllamaClient()

    if not client.is_alive():
        print("❌ Ollama daemon not reachable", file=sys.stderr)
        return 1

    for chunk in client.stream(prompt=args.prompt, system=SYSTEM_PROMPT):
        print(chunk, end="", flush=True)
    print()
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="blackjarvis",
        description="Local AI assistant for security research and bug bounty.",
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("hello", help="Sanity check: confirm LLM is alive and responding.")

    p_ask = sub.add_parser("ask", help="Ask a single question.")
    p_ask.add_argument("prompt", help="The prompt to send.")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    setup_logging(args.verbose)

    if args.command == "hello":
        return cmd_hello(args)
    if args.command == "ask":
        return cmd_ask(args)
    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
