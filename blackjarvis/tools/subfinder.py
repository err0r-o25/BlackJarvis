"""Wrapper for ProjectDiscovery subfinder.

Discovers subdomains for a target domain using passive sources.
Returns structured results that downstream code (LLM, CLI, reports)
can consume without re-parsing tool output.
"""
from __future__ import annotations

import json
import logging
import shutil
import subprocess
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from blackjarvis.memory.engagement import Engagement

logger = logging.getLogger(__name__)


@dataclass
class SubfinderResult:
    """Structured result from a subfinder run."""
    target: str
    subdomains: list[str] = field(default_factory=list)
    sources: dict[str, int] = field(default_factory=dict)
    elapsed_seconds: float = 0.0
    return_code: int = 0
    stderr_tail: str = ""

    def to_json(self) -> dict:
        return asdict(self)

    def summary(self) -> str:
        """Short, human-friendly summary suitable for LLM context."""
        top_sources = sorted(
            self.sources.items(), key=lambda kv: kv[1], reverse=True
        )[:5]
        srcs = ", ".join(f"{s}({n})" for s, n in top_sources) or "none"
        return (
            f"subfinder found {len(self.subdomains)} subdomains for "
            f"{self.target!r} in {self.elapsed_seconds:.1f}s. "
            f"Top sources: {srcs}."
        )


class SubfinderError(RuntimeError):
    """subfinder failed or isn't installed."""


def _check_installed() -> None:
    if shutil.which("subfinder") is None:
        raise SubfinderError(
            "subfinder not found on $PATH. Install with: "
            "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        )


def run_subfinder(
    target: str,
    *,
    timeout: int = 180,
    extra_args: list[str] | None = None,
) -> SubfinderResult:
    """Run subfinder against a single target. Returns structured result.

    Raises SubfinderError on tool failure. Caller is responsible for
    scope-checking the target before invoking this function.
    """
    _check_installed()

    cmd = ["subfinder", "-d", target, "-silent", "-oJ"]
    if extra_args:
        cmd.extend(extra_args)

    logger.info("running: %s", " ".join(cmd))
    start = time.monotonic()
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise SubfinderError(f"subfinder timed out after {timeout}s")
    elapsed = time.monotonic() - start

    if proc.returncode != 0:
        raise SubfinderError(
            f"subfinder exited {proc.returncode}: {proc.stderr[-500:]}"
        )

    subs: list[str] = []
    sources: dict[str, int] = {}
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        host = obj.get("host")
        if host:
            subs.append(host.lower())
        src = obj.get("source", "unknown")
        sources[src] = sources.get(src, 0) + 1

    return SubfinderResult(
        target=target,
        subdomains=sorted(set(subs)),
        sources=sources,
        elapsed_seconds=round(elapsed, 2),
        return_code=proc.returncode,
        stderr_tail=proc.stderr[-500:],
    )


def persist_result(result: SubfinderResult, engagement: Engagement) -> Path:
    """Write the result to <engagement>/recon/subfinder_<target>.json.

    If a previous run exists, archive it with a timestamp suffix first,
    so diff tooling has history to compare against.
    """
    import shutil
    from datetime import datetime

    recon_dir = engagement.dir / "recon"
    recon_dir.mkdir(parents=True, exist_ok=True)
    safe = result.target.replace("/", "_").replace("..", "_")
    out = recon_dir / f"subfinder_{safe}.json"

    # Archive an existing run before overwriting
    if out.exists():
        ts = datetime.fromtimestamp(out.stat().st_mtime).strftime("%Y%m%d-%H%M%S")
        archive = recon_dir / f"subfinder_{safe}_{ts}.json"
        shutil.copy2(out, archive)
        logger.info("archived previous run to %s", archive)

    out.write_text(json.dumps(result.to_json(), indent=2))
    logger.info("wrote %d subdomains to %s", len(result.subdomains), out)
    return out


def recon_subdomains(
    target: str,
    engagement: Engagement,
    *,
    timeout: int = 180,
) -> tuple[SubfinderResult, Path]:
    """High-level: scope-check, run subfinder, persist, return both."""
    engagement.assert_in_scope(target)
    result = run_subfinder(target, timeout=timeout)
    out_path = persist_result(result, engagement)
    return result, out_path
