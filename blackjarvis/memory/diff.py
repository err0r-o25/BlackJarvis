"""Recon diff: compare two recon runs and surface what changed.

Bug bounty value lives in *changes*: a subdomain that appeared this week,
a host that went from down to alive, a tech stack that shifted. This module
diffs the two most recent recon artifacts for a target.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path

from blackjarvis.memory.engagement import Engagement

logger = logging.getLogger(__name__)


@dataclass
class SubdomainDiff:
    """Difference between two subfinder runs for a target."""
    target: str
    previous_file: str = ""
    current_file: str = ""
    added: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    unchanged_count: int = 0
    has_history: bool = True

    def summary(self) -> str:
        if not self.has_history:
            return (
                f"No previous subfinder run found for {self.target!r}. "
                f"Run recon again later to enable diffing."
            )
        lines = [
            f"Subdomain diff for {self.target!r}:",
            f"  + {len(self.added)} new",
            f"  - {len(self.removed)} gone",
            f"  = {self.unchanged_count} unchanged",
        ]
        if self.added:
            preview = ", ".join(self.added[:15])
            more = f" (+{len(self.added) - 15} more)" if len(self.added) > 15 else ""
            lines.append(f"  NEW: {preview}{more}")
        if self.removed:
            preview = ", ".join(self.removed[:10])
            more = f" (+{len(self.removed) - 10} more)" if len(self.removed) > 10 else ""
            lines.append(f"  GONE: {preview}{more}")
        return "\n".join(lines)


@dataclass
class HttpxDiff:
    """Difference between two httpx runs for a label."""
    label: str
    previous_file: str = ""
    current_file: str = ""
    new_alive: list[str] = field(default_factory=list)
    gone: list[str] = field(default_factory=list)
    changed_status: list[tuple[str, int, int]] = field(default_factory=list)
    changed_tech: list[tuple[str, list[str], list[str]]] = field(default_factory=list)
    has_history: bool = True

    def summary(self) -> str:
        if not self.has_history:
            return (
                f"No previous httpx run found for {self.label!r}. "
                f"Run probing again later to enable diffing."
            )
        lines = [
            f"Httpx diff for {self.label!r}:",
            f"  + {len(self.new_alive)} newly alive",
            f"  - {len(self.gone)} gone offline",
            f"  ~ {len(self.changed_status)} status changed",
            f"  ~ {len(self.changed_tech)} tech changed",
        ]
        for host in self.new_alive[:10]:
            lines.append(f"  NEW ALIVE: {host}")
        for host, old, new in self.changed_status[:10]:
            lines.append(f"  STATUS: {host}  {old} -> {new}")
        for host, old_t, new_t in self.changed_tech[:10]:
            lines.append(f"  TECH: {host}  {old_t} -> {new_t}")
        return "\n".join(lines)


def _two_most_recent(recon_dir: Path, prefix: str) -> tuple[Path | None, Path | None]:
    """Return (previous, current) — the two most recently modified matching files.

    'current' is the canonical (non-timestamped) file if present, else newest.
    """
    if not recon_dir.exists():
        return None, None
    matches = sorted(
        recon_dir.glob(f"{prefix}*.json"),
        key=lambda p: p.stat().st_mtime,
    )
    if len(matches) < 2:
        return None, (matches[0] if matches else None)
    return matches[-2], matches[-1]


def diff_subfinder_runs(engagement: Engagement, target: str) -> SubdomainDiff:
    """Diff the two most recent subfinder runs for a target."""
    recon_dir = engagement.dir / "recon"
    safe = target.replace("/", "_").replace("..", "_")
    prev_path, curr_path = _two_most_recent(recon_dir, f"subfinder_{safe}")

    if prev_path is None or curr_path is None:
        return SubdomainDiff(target=target, has_history=False)

    prev_data = json.loads(prev_path.read_text())
    curr_data = json.loads(curr_path.read_text())
    prev_subs = set(prev_data.get("subdomains", []))
    curr_subs = set(curr_data.get("subdomains", []))

    added = sorted(curr_subs - prev_subs)
    removed = sorted(prev_subs - curr_subs)
    unchanged = len(curr_subs & prev_subs)

    logger.info(
        "subdomain diff %s: +%d -%d =%d",
        target, len(added), len(removed), unchanged,
    )
    return SubdomainDiff(
        target=target,
        previous_file=str(prev_path),
        current_file=str(curr_path),
        added=added,
        removed=removed,
        unchanged_count=unchanged,
    )


def diff_httpx_runs(engagement: Engagement, label: str) -> HttpxDiff:
    """Diff the two most recent httpx runs for a label."""
    recon_dir = engagement.dir / "recon"
    safe = label.replace("/", "_").replace("..", "_")
    prev_path, curr_path = _two_most_recent(recon_dir, f"httpx_{safe}")

    if prev_path is None or curr_path is None:
        return HttpxDiff(label=label, has_history=False)

    prev_data = json.loads(prev_path.read_text())
    curr_data = json.loads(curr_path.read_text())

    def index(data: dict) -> dict[str, dict]:
        return {h.get("host") or h.get("url", ""): h
                for h in data.get("alive_hosts", [])}

    prev_hosts = index(prev_data)
    curr_hosts = index(curr_data)

    new_alive = sorted(set(curr_hosts) - set(prev_hosts))
    gone = sorted(set(prev_hosts) - set(curr_hosts))

    changed_status: list[tuple[str, int, int]] = []
    changed_tech: list[tuple[str, list[str], list[str]]] = []
    for host in set(curr_hosts) & set(prev_hosts):
        p, c = prev_hosts[host], curr_hosts[host]
        if p.get("status_code") != c.get("status_code"):
            changed_status.append(
                (host, p.get("status_code", 0), c.get("status_code", 0))
            )
        if sorted(p.get("tech", [])) != sorted(c.get("tech", [])):
            changed_tech.append(
                (host, p.get("tech", []), c.get("tech", []))
            )

    logger.info(
        "httpx diff %s: +%d -%d ~status%d ~tech%d",
        label, len(new_alive), len(gone),
        len(changed_status), len(changed_tech),
    )
    return HttpxDiff(
        label=label,
        previous_file=str(prev_path),
        current_file=str(curr_path),
        new_alive=new_alive,
        gone=gone,
        changed_status=changed_status,
        changed_tech=changed_tech,
    )
