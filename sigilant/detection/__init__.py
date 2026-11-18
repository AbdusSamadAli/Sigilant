from __future__ import annotations

from pathlib import Path

from ..models import Alert, Event, extract_entities
from .correlation import CorrelationRule, load_correlation_rules
from .sigma import SigmaRule, load_rules

__all__ = ["DetectionEngine", "SigmaRule", "CorrelationRule"]

MERGE_SECONDS = 600


class DetectionEngine:
    def __init__(self, sigma_rules: list[SigmaRule], correlation_rules: list[CorrelationRule]):
        self.sigma_rules = sigma_rules
        self.correlation_rules = correlation_rules

    @classmethod
    def from_directory(cls, rules_dir: Path) -> "DetectionEngine":
        rules_dir = Path(rules_dir)
        return cls(load_rules(rules_dir / "sigma"), load_correlation_rules(rules_dir / "correlation"))

    def run(self, events: list[Event]) -> list[Alert]:
        alerts = self._run_sigma(events)
        for rule in self.correlation_rules:
            alerts.extend(rule.evaluate(events))
        alerts.sort(key=lambda a: a.first_seen)
        return alerts

    def _run_sigma(self, events: list[Event]) -> list[Alert]:
        open_alerts: dict[tuple, Alert] = {}
        out: list[Alert] = []
        for ev in events:
            for rule in self.sigma_rules:
                if not rule.matches(ev):
                    continue
                key = (rule.id, ev.get("host.name"))
                cur = open_alerts.get(key)
                if cur and (ev["@timestamp"] - cur.last_seen).total_seconds() <= MERGE_SECONDS:
                    cur.event_count += 1
                    cur.last_seen = ev["@timestamp"]
                    if len(cur.evidence) < 15:
                        cur.evidence.append(ev)
                    cur.entities = extract_entities(cur.evidence)
                    continue
                alert = Alert(
                    rule_id=rule.id, rule_title=rule.title, rule_type="sigma", severity=rule.level,
                    description=rule.description.strip(), first_seen=ev["@timestamp"],
                    last_seen=ev["@timestamp"], techniques=rule.techniques, tactics=rule.tactics,
                    event_count=1, evidence=[ev], entities=extract_entities([ev]),
                    false_positives=rule.falsepositives,
                )
                open_alerts[key] = alert
                out.append(alert)
        return out
