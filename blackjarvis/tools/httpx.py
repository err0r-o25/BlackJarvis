"""Wrapper for ProjectDiscovery httpx.

Probes a list of hosts to find which are alive, what they're running,
and basic metadata (status, title, tech). The output is the raw material
for triage: instead of staring at 40k subdomain strings, you get 200
prioritizable URLs.
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
class HttpxHost:
    """A single probed host."""
    url: str = ""
    host: str = ""
    status_code: int = 0
    title: str = ""
    tech: list[str] = field(default_factory=list)
    webserver: str = ""
    content_length: int = 0
    scheme: str = ""

    def to_json(self) -> dict:
        return asdict(self)


@dataclass
class HttpxResult:
    """Structured result from an httpx run."""
    targets_count: int = 0
    alive_hosts: list[HttpxHost] = field(default_factory=list)
    elapsed_seconds: float = 0.0
    return_code: int = 0
    stderr_tail: str = ""

    def to_json(self) -> dict:
        return {
            "targets_count": self.targets_count,
            "alive_count": len(self.alive_hosts),
            "alive_hosts": [h.to_json() for h in self.alive_hosts],
            "elapsed_seconds": self.elapsed_seconds,
            "return_code": self.return_code,
        }

    def summary(self) -> str:
        alive = len(self.alive_hosts)
        codes: dict[int, int] = {}
        for h in self.alive_hosts:
            codes[h.status_code] = codes.get(h.status_code, 0) + 1
        codes_str = ", ".join(f"{c}({n})" for c, n in sorted(codes.items())) or "none"
        return (
            f"httpx probed {self.targets_count} hosts, "
            f"{alive} alive in {self.elapsed_seconds:.1f}s. "
            f"Status codes: {codes_str}."
        )


class HttpxError(RuntimeError):
    """httpx failed or isn't installed."""


def _check_installed() -> None:
    if shutil.which("httpx") is None:
        raise HttpxError(
            "httpx not found on $PATH. Install: "
            "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
        )


def run_httpx(
    targets: list[str],
    *,
    timeout: int = 300,
    threads: int = 50,
    extra_args: list[str] | None = None,
) -> HttpxResult:
    """Probe a list of hosts/URLs with httpx. Returns structured result.

    httpx reads target list from stdin to keep argv small even for 40k+ hosts.
    """
    _check_installed()

    if not targets:
        return HttpxResult(targets_count=0, elapsed_seconds=0.0)

    cmd = [
        "httpx",
        "-silent",
        "-json",
        "-status-code",
        "-title",
        "-tech-detect",
        "-web-server",
        "-content-length",
        "-threads", str(threads),
        "-timeout", "10",
    ]
    if extra_args:
        cmd.extend(extra_args)

    logger.info("running httpx against %d targets", len(targets))
    start = time.monotonic()
    try:
        proc = subprocess.run(
            cmd,
            input="\n".join(targets),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise HttpxError(f"httpx timed out after {timeout}s")
    elapsed = time.monotonic() - start

    if proc.returncode != 0:
        # httpx sometimes returns non-zero with partial results; keep them
        logger.warning("httpx exited %d: %s", proc.returncode, proc.stderr[-300:])

    alive: list[HttpxHost] = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        alive.append(HttpxHost(
            url=obj.get("url", ""),
            host=obj.get("host", "") or obj.get("input", ""),
            status_code=int(obj.get("status_code") or obj.get("status-code") or 0),
            title=obj.get("title", "") or "",
            tech=list(obj.get("tech", []) or obj.get("technologies", []) or []),
            webserver=obj.get("webserver", "") or obj.get("web-server", "") or "",
            content_length=int(obj.get("content_length") or obj.get("content-length") or 0),
            scheme=obj.get("scheme", "") or "",
        ))

    return HttpxResult(
        targets_count=len(targets),
        alive_hosts=alive,
        elapsed_seconds=round(elapsed, 2),
        return_code=proc.returncode,
        stderr_tail=proc.stderr[-500:],
    )


def persist_result(result: HttpxResult, engagement: Engagement, label: str = "alive") -> Path:
    """Write probe result to <engagement>/recon/httpx_<label>.json."""
    recon_dir = engagement.dir / "recon"
    recon_dir.mkdir(parents=True, exist_ok=True)
    safe = label.replace("/", "_").replace("..", "_")
    out = recon_dir / f"httpx_{safe}.json"
    out.write_text(json.dumps(result.to_json(), indent=2))
    logger.info("wrote %d alive hosts to %s", len(result.alive_hosts), out)
    return out


def probe_targets(
    targets: list[str],
    engagement: Engagement,
    *,
    label: str = "alive",
    timeout: int = 300,
) -> tuple[HttpxResult, Path]:
    """High-level: scope-check each target, run httpx, persist, return."""
    # Scope-check every target before probing
    for t in targets:
        # Strip scheme/path for scope check — scope is on hostnames
        host = t.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
        engagement.assert_in_scope(host)

    result = run_httpx(targets, timeout=timeout)
    out_path = persist_result(result, engagement, label=label)
    return result, out_path
