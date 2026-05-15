"""Wrapper for ProjectDiscovery nuclei.

Runs templated vulnerability checks against URLs. Templates cover CVEs,
exposed configs, default credentials, security misconfigurations, etc.
We default to medium+ severity to filter noise.
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
class NucleiFinding:
    """A single vulnerability finding from nuclei."""
    template_id: str = ""
    name: str = ""
    severity: str = ""
    matched_at: str = ""
    host: str = ""
    type: str = ""
    description: str = ""
    tags: list[str] = field(default_factory=list)

    def to_json(self) -> dict:
        return asdict(self)


@dataclass
class NucleiResult:
    """Structured result from a nuclei run."""
    targets_count: int = 0
    findings: list[NucleiFinding] = field(default_factory=list)
    elapsed_seconds: float = 0.0
    return_code: int = 0
    stderr_tail: str = ""

    def to_json(self) -> dict:
        return {
            "targets_count": self.targets_count,
            "findings_count": len(self.findings),
            "findings": [f.to_json() for f in self.findings],
            "elapsed_seconds": self.elapsed_seconds,
            "return_code": self.return_code,
        }

    def severity_counts(self) -> dict[str, int]:
        """Count findings by severity."""
        out: dict[str, int] = {}
        for f in self.findings:
            out[f.severity] = out.get(f.severity, 0) + 1
        return out

    def summary(self) -> str:
        sev = self.severity_counts()
        order = ["critical", "high", "medium", "low", "info", "unknown"]
        parts = [f"{s}({sev[s]})" for s in order if s in sev]
        sev_str = ", ".join(parts) or "no findings"
        return (
            f"nuclei scanned {self.targets_count} targets, "
            f"{len(self.findings)} findings in {self.elapsed_seconds:.1f}s. "
            f"Breakdown: {sev_str}."
        )


class NucleiError(RuntimeError):
    """nuclei failed or isn't installed."""


def _check_installed() -> None:
    if shutil.which("nuclei") is None:
        raise NucleiError(
            "nuclei not found on $PATH. Install: "
            "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
        )


def run_nuclei(
    targets: list[str],
    *,
    severity: str = "medium,high,critical",
    timeout: int = 600,
    rate_limit: int = 150,
    extra_args: list[str] | None = None,
) -> NucleiResult:
    """Run nuclei against a list of URLs.

    severity: comma-separated list. Default "medium,high,critical" filters
    out the firehose of info/low findings that aren't usually actionable.
    """
    _check_installed()

    if not targets:
        return NucleiResult(targets_count=0, elapsed_seconds=0.0)

    cmd = [
        "nuclei",
        "-silent",
        "-jsonl",
        "-severity", severity,
        "-rate-limit", str(rate_limit),
        "-timeout", "10",
        "-disable-update-check",
    ]
    if extra_args:
        cmd.extend(extra_args)

    logger.info("running nuclei against %d targets (severity=%s)", len(targets), severity)
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
        raise NucleiError(f"nuclei timed out after {timeout}s")
    elapsed = time.monotonic() - start

    if proc.returncode != 0:
        logger.warning("nuclei exited %d: %s", proc.returncode, proc.stderr[-300:])

    findings: list[NucleiFinding] = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = obj.get("info", {}) or {}
        findings.append(NucleiFinding(
            template_id=obj.get("template-id", "") or obj.get("templateID", ""),
            name=info.get("name", "") or "",
            severity=(info.get("severity", "") or "unknown").lower(),
            matched_at=obj.get("matched-at", "") or obj.get("matched", ""),
            host=obj.get("host", "") or "",
            type=obj.get("type", "") or "",
            description=(info.get("description", "") or "")[:300],
            tags=list(info.get("tags", []) or []),
        ))

    return NucleiResult(
        targets_count=len(targets),
        findings=findings,
        elapsed_seconds=round(elapsed, 2),
        return_code=proc.returncode,
        stderr_tail=proc.stderr[-500:],
    )


def persist_result(result: NucleiResult, engagement: Engagement, label: str = "scan") -> Path:
    """Write scan result to <engagement>/findings/nuclei_<label>.json."""
    findings_dir = engagement.dir / "findings"
    findings_dir.mkdir(parents=True, exist_ok=True)
    safe = label.replace("/", "_").replace("..", "_")
    out = findings_dir / f"nuclei_{safe}.json"
    out.write_text(json.dumps(result.to_json(), indent=2))
    logger.info("wrote %d findings to %s", len(result.findings), out)
    return out


def scan_targets(
    targets: list[str],
    engagement: Engagement,
    *,
    label: str = "scan",
    severity: str = "medium,high,critical",
    timeout: int = 600,
) -> tuple[NucleiResult, Path]:
    """High-level: scope-check each target, run nuclei, persist, return."""
    for t in targets:
        host = t.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
        engagement.assert_in_scope(host)

    result = run_nuclei(targets, severity=severity, timeout=timeout)
    out_path = persist_result(result, engagement, label=label)
    return result, out_path
