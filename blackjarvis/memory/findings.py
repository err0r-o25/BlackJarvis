"""Findings: structured vulnerability records per engagement.

A finding is a markdown file with YAML frontmatter, stored in the
engagement's findings/ directory. It captures a vulnerability or notable
observation in a form that can later become a bug bounty report.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path

from blackjarvis.memory.engagement import Engagement

logger = logging.getLogger(__name__)

VALID_SEVERITIES = {"info", "low", "medium", "high", "critical"}
VALID_STATUSES = {"draft", "reported", "triaged", "duplicate", "resolved"}

FINDING_TEMPLATE = """## Summary
{summary}

## Steps to reproduce
1.

## Impact

## Proof of concept

1
## Remediation
"""


def slugify(text: str) -> str:
    """Turn a title into a kebab-case slug."""
    text = text.lower().strip()
    text = re.sub(r"[^a-z0-9]+", "-", text)
    return text.strip("-")[:40]


@dataclass
class Finding:
    id: str
    engagement: str
    title: str
    severity: str = "medium"
    status: str = "draft"
    target: str = ""
    created: str = ""
    tags: list[str] = field(default_factory=list)
    body: str = ""
    file_path: Path | None = None

    def to_markdown(self) -> str:
        """Render the finding as a markdown file with YAML frontmatter."""
        tags_str = "[" + ", ".join(self.tags) + "]"
        fm = "\n".join([
            "---",
            f"id: {self.id}",
            f"engagement: {self.engagement}",
            f"title: {self.title}",
            f"severity: {self.severity}",
            f"status: {self.status}",
            f"target: {self.target}",
            f"created: {self.created}",
            f"tags: {tags_str}",
            "---",
        ])
        return f"{fm}\n\n# {self.title}\n\n{self.body}\n"

    def save(self, engagement: Engagement) -> Path:
        findings_dir = engagement.dir / "findings"
        findings_dir.mkdir(parents=True, exist_ok=True)
        out = findings_dir / f"{self.id}.md"
        out.write_text(self.to_markdown())
        self.file_path = out
        logger.info("saved finding %s to %s", self.id, out)
        return out

    @classmethod
    def parse(cls, path: Path) -> "Finding":
        """Parse a finding markdown file with YAML frontmatter."""
        text = path.read_text()
        if not text.startswith("---"):
            raise ValueError(f"{path} has no YAML frontmatter")

        # Split: ['', frontmatter, body...]
        parts = text.split("---", 2)
        if len(parts) < 3:
            raise ValueError(f"{path} has malformed frontmatter")
        fm_block, body = parts[1], parts[2]

        meta: dict[str, str] = {}
        for line in fm_block.strip().splitlines():
            if ":" not in line:
                continue
            key, _, val = line.partition(":")
            meta[key.strip()] = val.strip()

        tags_raw = meta.get("tags", "[]").strip("[]")
        tags = [t.strip() for t in tags_raw.split(",") if t.strip()]

        # Body: strip the leading "# Title" line if present
        body = body.strip()
        body = re.sub(r"^#\s+.*\n+", "", body, count=1)

        return cls(
            id=meta.get("id", path.stem),
            engagement=meta.get("engagement", ""),
            title=meta.get("title", ""),
            severity=meta.get("severity", "medium"),
            status=meta.get("status", "draft"),
            target=meta.get("target", ""),
            created=meta.get("created", ""),
            tags=tags,
            body=body,
            file_path=path,
        )


def new_finding(
    engagement: Engagement,
    title: str,
    *,
    severity: str = "medium",
    status: str = "draft",
    target: str = "",
    tags: list[str] | None = None,
    body: str = "",
) -> Finding:
    """Create and save a new finding. Auto-generates a dated kebab-case ID."""
    severity = severity.lower()
    if severity not in VALID_SEVERITIES:
        raise ValueError(
            f"invalid severity {severity!r}; must be one of {sorted(VALID_SEVERITIES)}"
        )
    status = status.lower()
    if status not in VALID_STATUSES:
        raise ValueError(
            f"invalid status {status!r}; must be one of {sorted(VALID_STATUSES)}"
        )

    finding_id = f"{date.today().isoformat()}-{slugify(title)}"
    if not body:
        body = FINDING_TEMPLATE.format(summary="")

    finding = Finding(
        id=finding_id,
        engagement=engagement.id,
        title=title,
        severity=severity,
        status=status,
        target=target,
        created=datetime.now().isoformat(timespec="seconds"),
        tags=list(tags or []),
        body=body,
    )
    finding.save(engagement)
    return finding


def list_findings(
    engagement: Engagement,
    *,
    status: str | None = None,
    severity: str | None = None,
) -> list[Finding]:
    """List all findings for an engagement, optionally filtered."""
    findings_dir = engagement.dir / "findings"
    if not findings_dir.exists():
        return []

    out: list[Finding] = []
    for path in sorted(findings_dir.glob("*.md")):
        try:
            f = Finding.parse(path)
        except (ValueError, OSError) as e:
            logger.warning("skipping unparseable finding %s: %s", path, e)
            continue
        if status and f.status != status.lower():
            continue
        if severity and f.severity != severity.lower():
            continue
        out.append(f)
    return out
