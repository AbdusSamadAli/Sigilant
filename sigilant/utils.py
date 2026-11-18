from __future__ import annotations

import ipaddress
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

_DURATION = re.compile(r"^(\d+)\s*([smhd])$")
_UNITS = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}


def parse_duration(text: str | int) -> timedelta:
    if isinstance(text, int):
        return timedelta(seconds=text)
    m = _DURATION.match(str(text).strip().lower())
    if not m:
        raise ValueError(f"Invalid duration: {text!r} (use e.g. 30s, 2m, 1h)")
    return timedelta(**{_UNITS[m.group(2)]: int(m.group(1))})


def is_public_ip(value: str | None) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except (ValueError, TypeError):
        return False
    return ip.is_global


def is_ip(value: str | None) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except (ValueError, TypeError):
        return False


def iso(ts: datetime | None) -> str | None:
    if ts is None:
        return None
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return ts.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def json_default(obj):
    if isinstance(obj, datetime):
        return iso(obj)
    if isinstance(obj, Path):
        return str(obj)
    if hasattr(obj, "to_dict"):
        return obj.to_dict()
    if isinstance(obj, set):
        return sorted(obj)
    raise TypeError(f"Not JSON serialisable: {type(obj)}")


def dumps(obj, **kw) -> str:
    return json.dumps(obj, default=json_default, **kw)
