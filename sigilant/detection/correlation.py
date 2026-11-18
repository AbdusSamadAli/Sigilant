from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path

import yaml

from ..mitre import parse_tags
from ..models import Alert, Event, extract_entities
from ..utils import parse_duration
from .sigma import LEVELS, SigmaError, _split_key, match_selection

MAX_EVIDENCE = 15
TYPES = {"threshold", "distinct_count", "sequence"}


@dataclass
class CorrelationRule:
    id: str
    title: str
    type: str
    level: str
    description: str
    group_by: list[str]
    timeframe: timedelta
    filter: dict | None = None
    threshold: int = 0
    distinct_field: str | None = None
    steps: list[dict] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    falsepositives: list[str] = field(default_factory=list)
    path: str = ""

    def __post_init__(self):
        self.techniques, self.tactics = parse_tags(self.tags)

    @classmethod
    def from_dict(cls, d: dict, path: str = "") -> "CorrelationRule":
        for key in ("id", "title", "type", "level", "group_by", "timeframe"):
            if key not in d:
                raise SigmaError(f"{path}: missing required field '{key}'")
        if d["type"] not in TYPES:
            raise SigmaError(f"{path}: unknown correlation type {d['type']!r}")
        if d["level"] not in LEVELS:
            raise SigmaError(f"{path}: invalid level {d['level']!r}")
        rule = cls(id=d["id"], title=d["title"], type=d["type"], level=d["level"],
                   description=d.get("description", ""), group_by=list(d["group_by"]),
                   timeframe=parse_duration(d["timeframe"]), filter=d.get("filter"),
                   threshold=int(d.get("threshold", 0)), distinct_field=d.get("distinct_field"),
                   steps=d.get("steps", []), tags=d.get("tags", []),
                   falsepositives=d.get("falsepositives", []), path=path)
        if rule.type == "sequence":
            if len(rule.steps) != 2:
                raise SigmaError(f"{path}: sequence rules need exactly 2 steps")
            filters = [s["filter"] for s in rule.steps]
        else:
            if not rule.filter or rule.threshold < 1:
                raise SigmaError(f"{path}: '{rule.type}' needs filter and threshold >= 1")
            if rule.type == "distinct_count" and not rule.distinct_field:
                raise SigmaError(f"{path}: distinct_count needs distinct_field")
            filters = [rule.filter]
        for flt in filters:
            for key in flt:
                _split_key(key)
        return rule

    def _key(self, ev: Event):
        key = tuple(ev.get(f) for f in self.group_by)
        return None if any(k in (None, "") for k in key) else key

    def _alert(self, events: list[Event], key, extra: str) -> Alert:
        group = ", ".join(f"{f}={v}" for f, v in zip(self.group_by, key))
        return Alert(
            rule_id=self.id, rule_title=self.title, rule_type="correlation", severity=self.level,
            description=f"{self.description.strip()} [{group}; {extra}]",
            first_seen=events[0]["@timestamp"], last_seen=events[-1]["@timestamp"],
            techniques=self.techniques, tactics=self.tactics, event_count=len(events),
            evidence=events[:MAX_EVIDENCE], entities=extract_entities(events),
            false_positives=self.falsepositives,
        )

    def evaluate(self, events: list[Event]) -> list[Alert]:
        if self.type == "sequence":
            return self._sequence(events)
        windows: dict[tuple, deque] = {}
        active: dict[tuple, dict] = {}
        fired: list[dict] = []
        for ev in events:
            if not match_selection(ev, self.filter):
                continue
            key = self._key(ev)
            if key is None:
                continue
            ts = ev["@timestamp"]
            if (cur := active.get(key)) and ts - cur["last"] <= self.timeframe:
                cur["events"].append(ev)
                cur["last"] = ts
                continue
            win = windows.setdefault(key, deque())
            win.append(ev)
            while win and ts - win[0]["@timestamp"] > self.timeframe:
                win.popleft()
            if self.type == "threshold":
                hit = len(win) >= self.threshold
            else:
                hit = len({e.get(self.distinct_field) for e in win}) >= self.threshold
            if hit:
                cur = {"key": key, "events": list(win), "last": ts}
                active[key] = cur
                fired.append(cur)
                win.clear()
        alerts = []
        for cur in fired:
            evs = cur["events"]
            if self.type == "threshold":
                extra = f"{len(evs)} events"
            else:
                distinct = sorted({str(e.get(self.distinct_field)) for e in evs})
                extra = f"{len(evs)} events, {len(distinct)} distinct {self.distinct_field}"
            alerts.append(self._alert(evs, cur["key"], extra))
        return alerts

    def _sequence(self, events: list[Event]) -> list[Alert]:
        first, second = self.steps
        need = int(first.get("min_count", 1))
        history: dict[tuple, deque] = {}
        alerts = []
        for ev in events:
            key = self._key(ev)
            if key is None:
                continue
            ts = ev["@timestamp"]
            if match_selection(ev, first["filter"]):
                history.setdefault(key, deque()).append(ev)
            elif match_selection(ev, second["filter"]):
                hist = history.get(key, deque())
                while hist and ts - hist[0]["@timestamp"] > self.timeframe:
                    hist.popleft()
                if len(hist) >= need:
                    evs = list(hist)[-(MAX_EVIDENCE - 1):] + [ev]
                    alert = self._alert(evs, key, f"{len(hist)} prior '{first.get('name', 'step1')}' "
                                                  f"then '{second.get('name', 'step2')}'")
                    alert.event_count = len(hist) + 1
                    alerts.append(alert)
                    hist.clear()
        return alerts


def load_correlation_rules(directory: Path) -> list[CorrelationRule]:
    rules = []
    for path in sorted(Path(directory).rglob("*.yml")):
        with open(path, encoding="utf-8") as fh:
            for doc in yaml.safe_load_all(fh):
                if doc:
                    rules.append(CorrelationRule.from_dict(doc, str(path)))
    return rules
