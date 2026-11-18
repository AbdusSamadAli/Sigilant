from __future__ import annotations

import base64
import binascii
import json
import re
from datetime import datetime, timezone
from pathlib import Path

from ..models import Event

SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"

SECURITY_ACTIONS = {
    4624: ("logon", "success"), 4625: ("logon", "failure"), 4634: ("logoff", "success"),
    4648: ("explicit_credential_logon", "success"), 4672: ("special_privileges_assigned", "success"),
    4688: ("process_created", "success"), 4698: ("scheduled_task_created", "success"),
    4720: ("user_created", "success"), 4726: ("user_deleted", "success"),
    4728: ("group_member_added", "success"), 4732: ("group_member_added", "success"),
    4756: ("group_member_added", "success"), 4740: ("account_locked", "success"),
    1102: ("audit_log_cleared", "success"),
}
SYSMON_CATEGORIES = {
    1: ("process_creation", "process_created"), 3: ("network_connection", "network_connection"),
    10: ("process_access", "process_accessed"), 11: ("file_event", "file_created"),
    13: ("registry_set", "registry_value_set"), 22: ("dns_query", "dns_query"),
}


def _ts(raw: str) -> datetime:
    raw = raw.strip()
    if raw.startswith("/Date("):
        ms = int(raw[6:].split(")")[0].split("+")[0].split("-")[0])
        return datetime.fromtimestamp(ms / 1000, tz=timezone.utc)
    if "." in raw:
        head, frac = raw.split(".", 1)
        digits = "".join(c for c in frac if c.isdigit())
        tz = frac[len(digits):]
        raw = f"{head}.{digits[:6]}{tz}"
    ts = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)


def _clean(v):
    return None if v in ("-", "", None) else v


ENC_ARG = re.compile(r"\s[-/](?:e|ec|enc|enco\w*)\s+([A-Za-z0-9+/=]{16,})", re.IGNORECASE)


def decode_powershell(cmdline: str | None) -> str | None:
    if not cmdline or not (m := ENC_ARG.search(cmdline)):
        return None
    try:
        return base64.b64decode(m.group(1)).decode("utf-16-le")
    except (binascii.Error, UnicodeDecodeError):
        return None


def normalise(rec: dict) -> Event:
    data = rec.get("EventData") or {}
    eid = int(rec["EventID"])
    channel = rec.get("Channel", "Security")
    host = (rec.get("Computer") or "").split(".")[0]
    ev: Event = {
        "@timestamp": _ts(rec["TimeCreated"]),
        "event.dataset": "windows.sysmon" if channel == SYSMON_CHANNEL else "windows.security",
        "logsource.product": "windows",
        "logsource.service": "sysmon" if channel == SYSMON_CHANNEL else "security",
        "host.name": host,
        "event.code": eid,
        "EventID": eid,
        "Channel": channel,
        "message": rec.get("Message", ""),
        **data,
    }
    if channel == SYSMON_CHANNEL:
        category, action = SYSMON_CATEGORIES.get(eid, (None, f"sysmon_{eid}"))
        ev["logsource.category"] = category
        ev["event.action"] = action
        if user := data.get("User"):
            ev["user.name"] = user.split("\\")[-1]
        ev["process.executable"] = data.get("Image") or data.get("SourceImage")
        ev["process.command_line"] = data.get("CommandLine")
        ev["process.parent.executable"] = data.get("ParentImage")
        if eid == 3:
            ev["destination.ip"] = data.get("DestinationIp")
            ev["source.ip"] = data.get("SourceIp")
        if hashes := data.get("Hashes"):
            for part in hashes.split(","):
                algo, _, value = part.partition("=")
                ev[f"file.hash.{algo.strip().lower()}"] = value.strip().lower()
    else:
        action, outcome = SECURITY_ACTIONS.get(eid, (f"security_{eid}", None))
        ev["event.action"] = action
        if outcome:
            ev["event.outcome"] = outcome
        if eid == 4688:
            ev["logsource.category"] = "process_creation"
            ev.setdefault("Image", data.get("NewProcessName"))
            ev.setdefault("ParentImage", data.get("ParentProcessName"))
            ev["process.executable"] = ev["Image"]
            ev["process.command_line"] = data.get("CommandLine")
        if eid in (4624, 4625, 4648):
            ev["user.name"] = _clean(data.get("TargetUserName"))
            ev["source.ip"] = _clean(data.get("IpAddress"))
            ev["logon.type"] = data.get("LogonType")
        elif eid in (4720, 4726, 4728, 4732, 4756):
            ev["user.name"] = _clean(data.get("SubjectUserName"))
            ev["user.target.name"] = _clean(data.get("TargetUserName") if eid in (4720, 4726)
                                            else (data.get("MemberName") or "").split(",")[0].replace("CN=", ""))
            if eid in (4728, 4732, 4756):
                ev["group.name"] = data.get("TargetUserName")
        else:
            ev["user.name"] = _clean(data.get("SubjectUserName"))
    if decoded := decode_powershell(ev.get("process.command_line")):
        ev["process.command_line.decoded"] = decoded
    return {k: v for k, v in ev.items() if v is not None}


def parse_file(path: Path) -> list[Event]:
    events = []
    with open(path, encoding="utf-8-sig", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(normalise(json.loads(line)))
            except (json.JSONDecodeError, KeyError, ValueError):
                continue
    return events


def sniff(first_lines: list[str]) -> bool:
    for line in first_lines:
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(rec, dict) and "EventID" in rec and "TimeCreated" in rec:
            return True
    return False
