"""Recon pipelines: chained tool runs with structured results.

The recon pipeline is the heart of BlackJarvis's bug bounty workflow:
  subfinder (subdomain enum)
      │
      ▼
  httpx (probe which are alive + tech detection)
      │
      ▼
  nuclei (vulnerability template scan)

Each stage is optional, each persists structured output, and the
PipelineResult gives the LLM enough context to summarize and suggest
next steps.
"""
from __future__ import annotations

import logging
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from blackjarvis.memory.engagement import Engagement
from blackjarvis.tools.subfinder import (
    SubfinderError,
    SubfinderResult,
    recon_subdomains,
)
from blackjarvis.tools.httpx import (
    HttpxError,
    HttpxResult,
    probe_targets,
)
from blackjarvis.tools.nuclei import (
    NucleiError,
    NucleiResult,
    scan_targets,
)

logger = logging.getLogger(__name__)


@dataclass
class StageResult:
    """Lightweight summary of one pipeline stage."""
    name: str
    ok: bool
    elapsed_seconds: float = 0.0
    output_count: int = 0
    saved_to: str = ""
    error: str = ""

    def to_json(self) -> dict:
        return asdict(self)


@dataclass
class PipelineResult:
    """Result of an end-to-end recon pipeline run."""
    target: str
    engagement_id: str
    stages: list[StageResult] = field(default_factory=list)
    total_seconds: float = 0.0

    # Stage-specific result objects (None if stage skipped or failed early)
    subfinder: SubfinderResult | None = None
    httpx: HttpxResult | None = None
    nuclei: NucleiResult | None = None

    def to_json(self) -> dict:
        return {
            "target": self.target,
            "engagement_id": self.engagement_id,
            "stages": [s.to_json() for s in self.stages],
            "total_seconds": self.total_seconds,
            "subfinder_summary": self.subfinder.summary() if self.subfinder else None,
            "httpx_summary": self.httpx.summary() if self.httpx else None,
            "nuclei_summary": self.nuclei.summary() if self.nuclei else None,
        }

    def summary(self) -> str:
        """Human/LLM-friendly multi-line summary of the whole run."""
        lines = [
            f"=== Recon pipeline for {self.target!r} on engagement {self.engagement_id!r} ===",
            f"Total time: {self.total_seconds:.1f}s",
            "",
        ]
        for s in self.stages:
            status = "✓" if s.ok else "✗"
            lines.append(
                f"  {status} {s.name:10} {s.elapsed_seconds:6.1f}s  "
                f"output={s.output_count}  "
                + (f"saved={s.saved_to}" if s.saved_to else f"error={s.error}")
            )
        lines.append("")
        if self.subfinder:
            lines.append(self.subfinder.summary())
        if self.httpx:
            lines.append(self.httpx.summary())
        if self.nuclei:
            lines.append(self.nuclei.summary())
        return "\n".join(lines)


def run_recon_pipeline(
    target: str,
    engagement: Engagement,
    *,
    do_subs: bool = True,
    do_probe: bool = True,
    do_scan: bool = False,  # off by default — slow + noisy
    max_probe_hosts: int = 500,
    max_scan_hosts: int = 100,
    nuclei_severity: str = "medium,high,critical",
    subfinder_timeout: int = 240,
    httpx_timeout: int = 300,
    nuclei_timeout: int = 900,
) -> PipelineResult:
    """Run the full recon chain. Scope-check happens inside each tool wrapper.

    Stage caps (max_probe_hosts, max_scan_hosts) keep the pipeline responsive
    on huge subdomain sets. Adjust per-engagement if you want exhaustive runs.
    """
    engagement.assert_in_scope(target)

    result = PipelineResult(target=target, engagement_id=engagement.id)
    overall_start = time.monotonic()

    # ----- Stage 1: subfinder -----
    if do_subs:
        stage_start = time.monotonic()
        logger.info("pipeline stage 1/3: subfinder")
        try:
            sub_result, sub_path = recon_subdomains(target, engagement, timeout=subfinder_timeout)
            result.subfinder = sub_result
            result.stages.append(StageResult(
                name="subfinder", ok=True,
                elapsed_seconds=round(time.monotonic() - stage_start, 2),
                output_count=len(sub_result.subdomains),
                saved_to=str(sub_path),
            ))
        except SubfinderError as e:
            result.stages.append(StageResult(
                name="subfinder", ok=False,
                elapsed_seconds=round(time.monotonic() - stage_start, 2),
                error=str(e),
            ))
            logger.error("subfinder stage failed: %s", e)
            result.total_seconds = round(time.monotonic() - overall_start, 2)
            return result
    else:
        result.stages.append(StageResult(name="subfinder", ok=True, error="(skipped)"))

    # ----- Stage 2: httpx -----
    if do_probe and result.subfinder:
        stage_start = time.monotonic()
        probe_input = result.subfinder.subdomains[:max_probe_hosts]
        if len(result.subfinder.subdomains) > max_probe_hosts:
            logger.info(
                "capping probe input at %d (subfinder found %d)",
                max_probe_hosts, len(result.subfinder.subdomains),
            )
        logger.info("pipeline stage 2/3: httpx (%d targets)", len(probe_input))
        try:
            probe_result, probe_path = probe_targets(
                probe_input, engagement, label=target, timeout=httpx_timeout,
            )
            result.httpx = probe_result
            result.stages.append(StageResult(
                name="httpx", ok=True,
                elapsed_seconds=round(time.monotonic() - stage_start, 2),
                output_count=len(probe_result.alive_hosts),
                saved_to=str(probe_path),
            ))
        except HttpxError as e:
            result.stages.append(StageResult(
                name="httpx", ok=False,
                elapsed_seconds=round(time.monotonic() - stage_start, 2),
                error=str(e),
            ))
            logger.error("httpx stage failed: %s", e)
            result.total_seconds = round(time.monotonic() - overall_start, 2)
            return result
    else:
        result.stages.append(StageResult(name="httpx", ok=True, error="(skipped)"))

    # ----- Stage 3: nuclei -----
    if do_scan and result.httpx and result.httpx.alive_hosts:
        stage_start = time.monotonic()
        scan_input = [h.url for h in result.httpx.alive_hosts[:max_scan_hosts] if h.url]
        if len(result.httpx.alive_hosts) > max_scan_hosts:
            logger.info(
                "capping scan input at %d (httpx found %d alive)",
                max_scan_hosts, len(result.httpx.alive_hosts),
            )
        logger.info("pipeline stage 3/3: nuclei (%d targets)", len(scan_input))
        try:
            scan_result, scan_path = scan_targets(
                scan_input, engagement, label=target,
                severity=nuclei_severity, timeout=nuclei_timeout,
            )
            result.nuclei = scan_result
            result.stages.append(StageResult(
                name="nuclei", ok=True,
                elapsed_seconds=round(time.monotonic() - stage_start, 2),
                output_count=len(scan_result.findings),
                saved_to=str(scan_path),
            ))
        except NucleiError as e:
            result.stages.append(StageResult(
                name="nuclei", ok=False,
                elapsed_seconds=round(time.monotonic() - stage_start, 2),
                error=str(e),
            ))
            logger.error("nuclei stage failed: %s", e)
    else:
        result.stages.append(StageResult(name="nuclei", ok=True, error="(skipped)"))

    result.total_seconds = round(time.monotonic() - overall_start, 2)
    return result


def persist_pipeline_result(result: PipelineResult, engagement: Engagement) -> Path:
    """Write the pipeline summary JSON to engagement recon dir."""
    import json
    recon_dir = engagement.dir / "recon"
    recon_dir.mkdir(parents=True, exist_ok=True)
    safe = result.target.replace("/", "_").replace("..", "_")
    out = recon_dir / f"pipeline_{safe}.json"
    out.write_text(json.dumps(result.to_json(), indent=2))
    return out
