from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

from ..models import Event

HEADER = re.compile(
    r"^(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T[\d:.]+(?:Z|[+-]\d{2}:?\d{2})?)\s+"
    r"(?P<host>\S+)\s+(?P<proc>[\w\-./]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<msg>.*)$"
)
FAILED = re.compile(r"Failed (?P<method>\S+) for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+)")
ACCEPTED = re.compile(r"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+)")
INVALID = re.compile(r"Invalid user (?P<user>\S*) from (?P<ip>\S+)")
SUDO = re.compile(r"^\s*(?P<user>\S+) : .*?USER=(?P<target>\S+) ; COMMAND=(?P<cmd>.+)$")
USERADD = re.compile(r"new user: name=(?P<user>[^,]+)")
USERMOD_GROUP = re.compile(r"add '(?P<user>[^']+)' to group '(?P<group>[^']+)'")


def _parse_ts(raw: str, year: int) -> datetime:
    if raw[:4].isdigit():
        ts = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
    return datetime.strptime(f"{year} {' '.join(raw.split())}", "%Y %b %d %H:%M:%S").replace(tzinfo=timezone.utc)


def parse_line(line: str, year: int | None = None) -> Event | None:
    m = HEADER.match(line.rstrip("\n"))
    if not m:
        return None
    year = year or datetime.now(timezone.utc).year
    msg = m["msg"]
    ev: Event = {
        "@timestamp": _parse_ts(m["ts"], year),
        "event.dataset": "linux.auth",
        "logsource.product": "linux",
        "logsource.service": "auth",
        "host.name": m["host"],
        "process.name": m["proc"],
        "process.pid": m["pid"],
        "message": msg,
        "_raw": line.rstrip("\n"),
    }
    proc = m["proc"]
    if proc == "sshd":
        if fm := FAILED.search(msg):
            ev.update({"event.action": "ssh_login", "event.outcome": "failure", "user.name": fm["user"],
                       "source.ip": fm["ip"], "auth.method": fm["method"]})
        elif am := ACCEPTED.search(msg):
            ev.update({"event.action": "ssh_login", "event.outcome": "success", "user.name": am["user"],
                       "source.ip": am["ip"], "auth.method": am["method"]})
        elif im := INVALID.search(msg):
            ev.update({"event.action": "ssh_invalid_user", "event.outcome": "failure",
                       "user.name": im["user"], "source.ip": im["ip"]})
    elif proc == "sudo":
        if sm := SUDO.search(msg):
            ev.update({"event.action": "sudo_command", "user.name": sm["user"],
                       "user.target.name": sm["target"], "process.command_line": sm["cmd"].strip()})
    elif proc == "useradd":
        if um := USERADD.search(msg):
            ev.update({"event.action": "user_created", "user.target.name": um["user"]})
    elif proc in ("usermod", "gpasswd"):
        if gm := USERMOD_GROUP.search(msg):
            ev.update({"event.action": "group_member_added", "user.target.name": gm["user"],
                       "group.name": gm["group"]})
    return ev


def parse_file(path: Path, year: int | None = None) -> list[Event]:
    with open(path, encoding="utf-8", errors="replace") as fh:
        return [ev for line in fh if (ev := parse_line(line, year))]


def sniff(first_lines: list[str]) -> bool:
    return any(HEADER.match(line) and re.search(r"\b(sshd|sudo|useradd|CRON|systemd-logind)\b", line)
               for line in first_lines)
