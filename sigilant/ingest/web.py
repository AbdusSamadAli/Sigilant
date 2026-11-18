from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from urllib.parse import unquote_plus, urlsplit

from ..models import Event

COMBINED = re.compile(
    r'^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<time>[^\]]+)\] "(?P<method>[A-Z]+) (?P<url>\S+)[^"]*" '
    r'(?P<status>\d{3}) (?P<size>\S+)(?: "(?P<referrer>[^"]*)" "(?P<ua>[^"]*)")?'
)


def parse_line(line: str, host: str = "webserver") -> Event | None:
    m = COMBINED.match(line)
    if not m:
        return None
    url = m["url"]
    decoded = unquote_plus(unquote_plus(url))
    return {
        "@timestamp": datetime.strptime(m["time"], "%d/%b/%Y:%H:%M:%S %z"),
        "event.dataset": "web.access",
        "logsource.category": "webserver",
        "host.name": host,
        "source.ip": m["ip"],
        "user.name": None if m["user"] == "-" else m["user"],
        "http.request.method": m["method"],
        "url.original": url,
        "url.decoded": decoded,
        "url.path": urlsplit(decoded).path,
        "http.response.status_code": int(m["status"]),
        "user_agent.original": m["ua"] or "",
        "event.action": "http_request",
        "message": line.rstrip("\n"),
    }


def host_from_filename(path: Path) -> str:
    stem = path.name.split("_access")[0] if "_access" in path.name else "webserver"
    return stem


def parse_file(path: Path) -> list[Event]:
    host = host_from_filename(path)
    with open(path, encoding="utf-8", errors="replace") as fh:
        return [{k: v for k, v in ev.items() if v is not None}
                for line in fh if (ev := parse_line(line, host))]


def sniff(first_lines: list[str]) -> bool:
    return any(COMBINED.match(line) for line in first_lines)
