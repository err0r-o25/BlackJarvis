"""Notes: a lightweight timestamped scratchpad per engagement.

Findings are structured records meant to become reports. Notes are the
opposite — quick, unstructured capture: a hunch, an observation, a URL to
revisit. Appended to <engagement>/notes.md.
"""
from __future__ import annotations

import logging
from datetime import datetime

from blackjarvis.memory.engagement import Engagement

logger = logging.getLogger(__name__)


def append_note(engagement: Engagement, text: str, *, tag: str = "") -> None:
    """Append a timestamped note to the engagement's notes.md."""
    engagement.dir.mkdir(parents=True, exist_ok=True)
    notes_path = engagement.dir / "notes.md"

    ts = datetime.now().strftime("%Y-%m-%d %H:%M")
    header = f"## {ts}"
    if tag:
        header += f"  [{tag}]"

    entry = f"{header}\n{text.strip()}\n\n"

    # Create with a title if the file doesn't exist yet
    if not notes_path.exists():
        notes_path.write_text(f"# Notes — {engagement.name}\n\n")

    with notes_path.open("a") as f:
        f.write(entry)
    logger.info("appended note to %s", notes_path)


def read_notes(engagement: Engagement) -> str:
    """Return the full notes.md content, or a placeholder if none exist."""
    notes_path = engagement.dir / "notes.md"
    if not notes_path.exists():
        return f"No notes yet for engagement {engagement.id!r}."
    return notes_path.read_text()
