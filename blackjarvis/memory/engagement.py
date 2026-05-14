"""Engagement: a named scope of authorized work.

An engagement is the unit of bug bounty work — typically one program
(e.g. "acme-corp-bb") or one personal lab ("home-lab"). Every tool
invocation belongs to an engagement, and scope rules attach here.
"""
from __future__ import annotations

import fnmatch
import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)

ENGAGEMENTS_DIR = Path.home() / "projects" / "BlackJarvis" / "engagements"


class OutOfScopeError(RuntimeError):
    """Raised when a target is not authorized for the current engagement."""


@dataclass
class Scope:
    """In-scope and out-of-scope patterns. fnmatch-style wildcards."""
    in_scope: list[str] = field(default_factory=list)
    out_of_scope: list[str] = field(default_factory=list)


@dataclass
class Engagement:
    id: str
    name: str
    platform: str = ""
    created: str = ""
    scope: Scope = field(default_factory=Scope)
    notes: str = ""

    @property
    def dir(self) -> Path:
        return ENGAGEMENTS_DIR / self.id

    @property
    def manifest_path(self) -> Path:
        return self.dir / "engagement.json"

    def save(self) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        data = asdict(self)
        self.manifest_path.write_text(json.dumps(data, indent=2))
        logger.info("saved engagement %s to %s", self.id, self.manifest_path)

    @classmethod
    def load(cls, engagement_id: str) -> "Engagement":
        path = ENGAGEMENTS_DIR / engagement_id / "engagement.json"
        if not path.exists():
            raise FileNotFoundError(f"no engagement {engagement_id!r}")
        data = json.loads(path.read_text())
        data["scope"] = Scope(**data.get("scope", {}))
        return cls(**data)

    def is_in_scope(self, target: str) -> bool:
        """Return True iff target matches an in-scope pattern AND no out-of-scope."""
        t = target.lower().strip()
        # Out-of-scope wins
        for pat in self.scope.out_of_scope:
            if fnmatch.fnmatch(t, pat.lower()):
                return False
        # Must match at least one in-scope pattern
        for pat in self.scope.in_scope:
            if fnmatch.fnmatch(t, pat.lower()):
                return True
        return False

    def assert_in_scope(self, target: str) -> None:
        """Raise OutOfScopeError if target is not authorized."""
        if not self.is_in_scope(target):
            raise OutOfScopeError(
                f"{target!r} is not in scope for engagement {self.id!r}"
            )


def list_engagements() -> list[Engagement]:
    """List all engagements on disk."""
    if not ENGAGEMENTS_DIR.exists():
        return []
    out = []
    for child in sorted(ENGAGEMENTS_DIR.iterdir()):
        if (child / "engagement.json").exists():
            try:
                out.append(Engagement.load(child.name))
            except Exception as e:
                logger.warning("skipping %s: %s", child.name, e)
    return out


def new_engagement(
    eid: str,
    name: str,
    *,
    in_scope: list[str],
    out_of_scope: list[str] | None = None,
    platform: str = "",
) -> Engagement:
    """Create and save a new engagement."""
    if (ENGAGEMENTS_DIR / eid / "engagement.json").exists():
        raise FileExistsError(f"engagement {eid!r} already exists")
    eng = Engagement(
        id=eid,
        name=name,
        platform=platform,
        created=datetime.now().isoformat(timespec="seconds"),
        scope=Scope(in_scope=list(in_scope), out_of_scope=list(out_of_scope or [])),
    )
    eng.save()
    return eng
