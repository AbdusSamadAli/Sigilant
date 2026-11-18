from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .mitre import TACTICS, technique_name, technique_url
from .models import Alert, Case
from .triage import PRIORITY_SLA
from .utils import dumps

TEMPLATES = Path(__file__).parent / "templates"


def _evidence_line(ev: dict) -> str:
    if ev.get("_raw"):
        return ev["_raw"]
    if ev.get("event.dataset", "").startswith("windows"):
        bits = [f"EID {ev.get('EventID')}", ev.get("host.name", "")]
        for k in ("user.name", "user.target.name", "group.name", "source.ip", "Image", "CommandLine",
                  "TargetImage", "GrantedAccess", "TaskName", "DestinationIp"):
            if ev.get(k):
                bits.append(f"{k}={ev[k]}")
        return " | ".join(str(b) for b in bits)
    return str(ev.get("message", ""))[:300]


def write_alerts_jsonl(alerts: list[Alert], path: Path) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        for a in alerts:
            d = a.to_dict()
            d["evidence"] = [_evidence_line(e) for e in a.evidence]
            fh.write(dumps(d) + "\n")


def write_cases_json(cases: list[Case], path: Path) -> None:
    payload = []
    for c in cases:
        d = c.to_dict()
        for a, src in zip(d["alerts"], c.alerts):
            a["evidence"] = [_evidence_line(e) for e in src.evidence]
        payload.append(d)
    path.write_text(dumps(payload, indent=2), encoding="utf-8")


def markdown_report(cases: list[Case], stats: dict) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    out = ["# Sigilant Incident Report", "", f"_Generated {now}_", "",
           "## Executive summary", "",
           f"- Events analysed: **{stats['events']}** from {len(stats['sources'])} log source(s)",
           f"- Alerts raised: **{stats['alerts']}**, correlated into **{len(cases)}** case(s)",
           "- Priority breakdown: " + ", ".join(f"{p}: {n}" for p, n in sorted(Counter(c.priority for c in cases).items())),
           f"- ATT&CK techniques observed: {len({t for c in cases for t in c.techniques})}", ""]
    out += ["| Case | Priority | Score | Title | Alerts | Tactics |", "|---|---|---|---|---|---|"]
    out += [f"| {c.case_id} | **{c.priority}** | {c.score} | {c.title} | {len(c.alerts)} | "
            f"{', '.join(t.replace('_', ' ') for t in c.tactics)} |" for c in cases]
    for c in cases:
        out += ["", "---", "", f"## {c.case_id} - {c.title}", "",
                f"**Priority:** {c.priority} (respond within {PRIORITY_SLA[c.priority]}) &nbsp; **Risk score:** {c.score}/100  ",
                f"**Window:** {c.first_seen:%Y-%m-%d %H:%M:%S} -> {c.last_seen:%Y-%m-%d %H:%M:%S} UTC", "",
                f"> {c.summary}", "", "### Timeline", "",
                "| Time (UTC) | Severity | Score | Detection | ATT&CK | Events |", "|---|---|---|---|---|---|"]
        for a in c.alerts:
            techs = ", ".join(f"[{t}]({technique_url(t)})" for t in a.techniques)
            out.append(f"| {a.first_seen:%H:%M:%S} | {a.severity} | {a.score} | {a.rule_title} | {techs} | {a.event_count} |")
        out += ["", "### MITRE ATT&CK mapping", ""]
        out += [f"- **{t}** {technique_name(t)}" for t in c.techniques]
        iocs = {ioc: e for a in c.alerts for ioc, e in a.enrichment.items()}
        if iocs:
            out += ["", "### Indicators of compromise", "", "| IOC | Type | Verdict | Sources |", "|---|---|---|---|"]
            for ioc, e in iocs.items():
                srcs = "; ".join(f"{r['provider']}: {r['verdict']} ({r['score']})" for r in e.get("results", []))
                out.append(f"| `{ioc}` | {e.get('type')} | **{e.get('verdict')}** | {srcs or '-'} |")
        ents = c.entities
        out += ["", "### Affected entities", ""]
        for key in ("host.name", "user.name", "user.target.name", "source.ip"):
            if ents.get(key):
                out.append(f"- `{key}`: {', '.join(ents[key])}")
        if c.playbooks:
            out += ["", "### Playbooks triggered", ""]
            for pb in c.playbooks:
                out += [f"**{pb['id']} - {pb['name']}** (triggered by {', '.join(pb['triggered_by'])})", ""]
                out += [f"{i}. {s}" for i, s in enumerate(pb["steps"], 1)] + [""]
        if c.actions:
            out += ["### Proposed containment (pending analyst approval)", "", "| Action | Target | Command |", "|---|---|---|"]
            out += [f"| {a['action']} | `{a['target']}` | `{a['command'].splitlines()[0]}` |" for a in c.actions]
        out += ["", "### Evidence (sample)", "", "```"]
        for a in c.alerts:
            out.append(f"# {a.rule_title}")
            out += [_evidence_line(e) for e in a.evidence[:3]]
        out += ["```", ""]
        fps = sorted({fp for a in c.alerts for fp in a.false_positives})
        if fps:
            out += ["### False-positive considerations", ""] + [f"- {fp}" for fp in fps] + [""]
        out += ["### Analyst verdict", "", "- [ ] True positive  - [ ] Benign true positive  - [ ] False positive", "",
                "_Notes:_", ""]
    return "\n".join(out)


def html_dashboard(cases: list[Case], alerts: list[Alert], stats: dict) -> str:
    env = Environment(loader=FileSystemLoader(TEMPLATES), autoescape=select_autoescape(["html", "j2"]))
    tactic_counts = Counter(t for a in alerts for t in a.tactics)
    tech_by_tactic: dict[str, Counter] = {t: Counter() for t in TACTICS}
    for a in alerts:
        for tac in a.tactics:
            for tech in a.techniques:
                tech_by_tactic[tac][tech] += 1
    return env.get_template("dashboard.html.j2").render(
        generated=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        cases=cases, alerts=alerts, stats=stats,
        severity_counts=Counter(a.severity for a in alerts),
        priority_counts=Counter(c.priority for c in cases),
        tactics=[t for t in TACTICS if tactic_counts[t]], tactic_counts=tactic_counts,
        tech_by_tactic=tech_by_tactic, technique_name=technique_name, technique_url=technique_url,
        evidence_line=_evidence_line, sla=PRIORITY_SLA,
    )


def write_all(out_dir: Path, cases: list[Case], alerts: list[Alert], stats: dict) -> dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    paths = {"alerts": out_dir / "alerts.jsonl", "cases": out_dir / "cases.json",
             "report": out_dir / "incident_report.md", "dashboard": out_dir / "dashboard.html"}
    write_alerts_jsonl(alerts, paths["alerts"])
    write_cases_json(cases, paths["cases"])
    paths["report"].write_text(markdown_report(cases, stats), encoding="utf-8")
    paths["dashboard"].write_text(html_dashboard(cases, alerts, stats), encoding="utf-8")
    return paths
