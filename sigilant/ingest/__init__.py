from __future__ import annotations

from pathlib import Path

from ..models import Event
from . import linux_auth, web, windows

PARSERS = {
    "windows": windows,
    "linux_auth": linux_auth,
    "web": web,
}


def detect_type(path: Path) -> str | None:
    with open(path, encoding="utf-8-sig", errors="replace") as fh:
        head = [fh.readline() for _ in range(20)]
    head = [h for h in head if h.strip()]
    for name in ("windows", "web", "linux_auth"):
        if PARSERS[name].sniff(head):
            return name
    return None


def load_path(path: Path, year: int | None = None) -> tuple[list[Event], dict[str, int]]:
    files = sorted(p for p in path.rglob("*") if p.is_file()) if path.is_dir() else [path]
    events: list[Event] = []
    stats: dict[str, int] = {}
    for f in files:
        kind = detect_type(f)
        if kind is None:
            continue
        parser = PARSERS[kind]
        parsed = parser.parse_file(f, year) if kind == "linux_auth" else parser.parse_file(f)
        stats[f"{f.name} ({kind})"] = len(parsed)
        events.extend(parsed)
    events.sort(key=lambda e: e["@timestamp"])
    return events, stats
