from __future__ import annotations

import hashlib
from pathlib import Path

import yaml

from .mitre import TACTICS, tactic_rank
from .models import Alert, Case
from .utils import is_public_ip

SEVERITY_BASE = {"informational": 10, "low": 20, "medium": 40, "high": 60, "critical": 80}
INTEL_BONUS = {"malicious": 20, "suspicious": 10}
CRITICALITY_BONUS = {"critical": 15, "high": 10, "medium": 5, "low": 0}
PRIORITY_SLA = {"P1": "15 min", "P2": "1 hour", "P3": "8 hours", "P4": "next business day"}


def priority_for(score: int) -> str:
    return "P1" if score >= 85 else "P2" if score >= 65 else "P3" if score >= 40 else "P4"


class AssetInventory:
    def __init__(self, assets: dict[str, dict]):
        self.assets = {k.lower(): {"name": k, **v} for k, v in assets.items()}
        self.by_ip = {v["ip"]: v["name"] for v in self.assets.values() if v.get("ip")}

    @classmethod
    def load(cls, path: Path) -> "AssetInventory":
        if not path.exists():
            return cls({})
        with open(path, encoding="utf-8") as fh:
            return cls((yaml.safe_load(fh) or {}).get("assets", {}))

    def get(self, host: str | None) -> dict:
        return self.assets.get((host or "").lower(), {})

    def criticality(self, host: str | None) -> str:
        return self.get(host).get("criticality", "low")


def score_alert(alert: Alert, assets: AssetInventory) -> int:
    score = SEVERITY_BASE.get(alert.severity, 20)
    verdicts = [e.get("verdict") for e in alert.enrichment.values()]
    score += max((INTEL_BONUS.get(v, 0) for v in verdicts), default=0)
    hosts = alert.entities.get("host.name", [])
    score += max((CRITICALITY_BONUS[assets.criticality(h)] for h in hosts), default=0)
    if alert.event_count >= 20:
        score += 5
    alert.score = min(score, 100)
    return alert.score


class _UnionFind:
    def __init__(self, n):
        self.parent = list(range(n))

    def find(self, x):
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a, b):
        self.parent[self.find(a)] = self.find(b)


def _tokens(alert: Alert, assets: AssetInventory) -> set[str]:
    toks = {f"host:{h.lower()}" for h in alert.entities.get("host.name", [])}
    for ip in alert.entities.get("source.ip", []):
        if is_public_ip(ip):
            toks.add(f"ip:{ip}")
        elif ip in assets.by_ip:
            toks.add(f"host:{assets.by_ip[ip].lower()}")
    return toks


def build_cases(alerts: list[Alert], assets: AssetInventory) -> list[Case]:
    for a in alerts:
        score_alert(a, assets)
    uf = _UnionFind(len(alerts))
    owner: dict[str, int] = {}
    for i, alert in enumerate(alerts):
        for tok in _tokens(alert, assets):
            if tok in owner:
                uf.union(i, owner[tok])
            else:
                owner[tok] = i
    groups: dict[int, list[Alert]] = {}
    for i, alert in enumerate(alerts):
        groups.setdefault(uf.find(i), []).append(alert)

    cases = []
    for members in groups.values():
        members.sort(key=lambda a: a.first_seen)
        tactics = sorted({t for a in members for t in a.tactics}, key=tactic_rank)
        techniques = sorted({t for a in members for t in a.techniques})
        score = min(100, max(a.score for a in members) + 5 * max(0, len(tactics) - 1))
        entities: dict[str, set] = {}
        for a in members:
            for k, vals in a.entities.items():
                entities.setdefault(k, set()).update(vals)
        hosts = sorted(entities.get("host.name", []))
        top = max(members, key=lambda a: a.score)
        if len(tactics) >= 3:
            title = f"Multi-stage intrusion on {', '.join(hosts) or 'unknown host'}"
        else:
            title = f"{top.rule_title} on {', '.join(hosts) or 'unknown host'}"
        seed = "|".join(a.alert_id for a in members)
        case = Case(
            case_id="CASE-" + hashlib.sha1(seed.encode()).hexdigest()[:8].upper(),
            title=title, alerts=members, score=score, priority=priority_for(score),
            entities={k: sorted(v) for k, v in entities.items()}, tactics=tactics, techniques=techniques,
            first_seen=members[0].first_seen, last_seen=max(a.last_seen for a in members),
        )
        case.summary = summarise(case, assets)
        cases.append(case)
    cases.sort(key=lambda c: (-c.score, c.first_seen))
    return cases


def summarise(case: Case, assets: AssetInventory) -> str:
    hosts = case.entities.get("host.name", [])
    host_desc = ", ".join(f"{h} ({assets.get(h).get('role', 'unknown role')})" for h in hosts)
    attackers = [ip for ip in case.entities.get("source.ip", []) if is_public_ip(ip)]
    lines = [f"{len(case.alerts)} alert(s) between {case.first_seen:%Y-%m-%d %H:%M} and "
             f"{case.last_seen:%H:%M} UTC affecting {host_desc or 'unknown hosts'}."]
    if attackers:
        lines.append(f"External source IP(s): {', '.join(attackers)}.")
    stages = [t for t in TACTICS if t in case.tactics]
    if stages:
        lines.append("Observed kill-chain stages: " + " -> ".join(s.replace('_', ' ') for s in stages) + ".")
    malicious = sorted({ioc for a in case.alerts for ioc, e in a.enrichment.items() if e.get("verdict") == "malicious"})
    if malicious:
        lines.append(f"Threat intel flags as malicious: {', '.join(malicious)}.")
    return " ".join(lines)
