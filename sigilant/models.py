from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from datetime import datetime

from .mitre import tactic_rank

Event = dict

SEVERITY_ORDER = ["informational", "low", "medium", "high", "critical"]

ENTITY_FIELDS = ("source.ip", "destination.ip", "host.name", "user.name", "user.target.name",
                 "file.hash.sha256", "url.domain", "process.executable")


def extract_entities(events: list[Event]) -> dict[str, list[str]]:
    out: dict[str, set[str]] = {}
    for ev in events:
        for key in ENTITY_FIELDS:
            val = ev.get(key)
            if val not in (None, "", "-"):
                out.setdefault(key, set()).add(str(val))
    return {k: sorted(v) for k, v in out.items()}


@dataclass
class Alert:
    rule_id: str
    rule_title: str
    rule_type: str
    severity: str
    description: str
    first_seen: datetime
    last_seen: datetime
    techniques: list[str]
    tactics: list[str]
    event_count: int
    evidence: list[Event]
    entities: dict[str, list[str]]
    false_positives: list[str] = field(default_factory=list)
    enrichment: dict = field(default_factory=dict)
    score: int = 0
    alert_id: str = ""

    def __post_init__(self):
        if not self.alert_id:
            seed = f"{self.rule_id}|{self.first_seen.isoformat()}|{sorted(self.entities.items())}"
            self.alert_id = "ALRT-" + hashlib.sha1(seed.encode()).hexdigest()[:10].upper()

    @property
    def primary_tactic_rank(self) -> int:
        return min((tactic_rank(t) for t in self.tactics), default=99)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["evidence"] = [{k: v for k, v in e.items() if k != "_raw"} for e in self.evidence]
        return d


@dataclass
class Case:
    case_id: str
    title: str
    alerts: list[Alert]
    score: int
    priority: str
    entities: dict[str, list[str]]
    tactics: list[str]
    techniques: list[str]
    first_seen: datetime
    last_seen: datetime
    playbooks: list[dict] = field(default_factory=list)
    actions: list[dict] = field(default_factory=list)
    summary: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["alerts"] = [a.to_dict() for a in self.alerts]
        return d
