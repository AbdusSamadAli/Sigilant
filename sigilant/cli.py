from __future__ import annotations

import argparse
import sys
import tempfile
from datetime import date
from pathlib import Path

from rich.console import Console
from rich.table import Table

from . import __version__
from .pipeline import ROOT, PipelineConfig, run

console = Console()
PRIO_STYLE = {"P1": "bold white on red", "P2": "bold black on dark_orange", "P3": "black on yellow", "P4": "white on blue"}
SEV_STYLE = {"critical": "bold red", "high": "dark_orange", "medium": "yellow", "low": "cyan", "informational": "dim"}


def cmd_simulate(args) -> int:
    from .simulate import generate
    day = date.fromisoformat(args.date) if args.date else None
    counts = generate(Path(args.out), day, args.seed)
    for name, n in counts.items():
        console.print(f"  [green]wrote[/] {Path(args.out) / name}  ({n} lines)")
    return 0


def cmd_run(args) -> int:
    cfg = PipelineConfig(input=Path(args.input), output=Path(args.out), offline=args.offline,
                         rules_dir=Path(args.rules), year=args.year)
    with console.status("Running pipeline...") as status:
        result = run(cfg, progress=lambda m: status.update(f"[bold]{m}..."))
    s = result.stats
    console.rule("[bold]Sigilant run summary")
    console.print(f"Events: [bold]{s['events']}[/] from {len(s['sources'])} source(s)  |  "
                  f"Rules: {s['rules']['sigma']} Sigma + {s['rules']['correlation']} correlation  |  "
                  f"Alerts: [bold]{s['alerts']}[/]  |  Cases: [bold]{len(result.cases)}[/]  |  "
                  f"Intel: {', '.join(s['providers'])}")

    t = Table(title="Alerts", show_lines=False, header_style="bold")
    for col in ("Time (UTC)", "Severity", "Score", "Rule", "ATT&CK", "Entities"):
        t.add_column(col)
    for a in result.alerts:
        ents = ", ".join(a.entities.get("host.name", []) + [ip for ip in a.entities.get("source.ip", [])])
        t.add_row(a.first_seen.strftime("%m-%d %H:%M:%S"), f"[{SEV_STYLE[a.severity]}]{a.severity}[/]",
                  str(a.score), a.rule_title + (f" (x{a.event_count})" if a.event_count > 1 else ""),
                  ", ".join(a.techniques), ents)
    console.print(t)

    ct = Table(title="Cases (triage queue)", header_style="bold")
    for col in ("Priority", "Case", "Score", "Title", "Alerts", "Kill-chain stages", "Actions"):
        ct.add_column(col)
    for c in result.cases:
        ct.add_row(f"[{PRIO_STYLE[c.priority]}] {c.priority} [/]", c.case_id, str(c.score), c.title,
                   str(len(c.alerts)), " > ".join(t.replace("_", " ") for t in c.tactics), str(len(c.actions)))
    console.print(ct)
    for name, path in result.outputs.items():
        console.print(f"  [green]{name:<10}[/] {path}")
    if any(c.actions for c in result.cases):
        resp = Path(args.out) / "response"
        console.print(f"  [green]{'response':<10}[/] {resp}  (containment scripts - review before running)")
    timing = ", ".join(f"{k} {v * 1000:.0f}ms" for k, v in result.timings.items())
    console.print(f"[dim]timings: {timing}[/]")
    return 0


def cmd_rules(args) -> int:
    from .detection.correlation import load_correlation_rules
    from .detection.sigma import SigmaError, load_rules
    rules_dir = Path(args.rules)
    try:
        sigma = load_rules(rules_dir / "sigma")
        corr = load_correlation_rules(rules_dir / "correlation")
    except (SigmaError, KeyError, TypeError) as exc:
        console.print(f"[bold red]Rule validation failed:[/] {exc}")
        return 1

    if args.action == "validate":
        problems = []
        for r in sigma:
            if not r.techniques:
                problems.append(f"{r.path}: no ATT&CK technique tag")
            if not r.falsepositives:
                problems.append(f"{r.path}: falsepositives not documented")
        for r in corr:
            if not r.techniques:
                problems.append(f"{r.path}: no ATT&CK technique tag")
        for p in problems:
            console.print(f"[yellow]warning[/] {p}")
        console.print(f"[green]OK[/] {len(sigma)} Sigma rules and {len(corr)} correlation rules are valid.")
        return 1 if (problems and args.strict) else 0

    if args.action == "export":
        for r in sigma:
            console.print(f"[bold cyan]# {r.id}[/]  ({r.level})", highlight=False)
            print(r.to_query(args.target) + "\n")
        return 0

    if args.action == "test":
        from .detection import DetectionEngine
        from .ingest import load_path
        from .simulate import generate
        with tempfile.TemporaryDirectory() as tmp:
            generate(Path(tmp))
            events, _ = load_path(Path(tmp))
        alerts = DetectionEngine(sigma, corr).run(events)
        fired = {a.rule_id for a in alerts}
        t = Table(title="Rule coverage on lab dataset", header_style="bold")
        t.add_column("Rule")
        t.add_column("Type")
        t.add_column("Result")
        missing = 0
        for r in [*sigma, *corr]:
            ok = r.id in fired
            missing += not ok
            t.add_row(r.title, "sigma" if r in sigma else "correlation",
                      "[green]fired[/]" if ok else "[red]did not fire[/]")
        console.print(t)
        return 1 if missing else 0
    return 2


def cmd_enrich(args) -> int:
    from .enrichment import Enricher
    enricher = Enricher(ROOT / "data" / "threat_intel.csv", Path(".cache") / "intel.sqlite", offline=args.offline)
    t = Table(title=f"IOC enrichment ({', '.join(enricher.provider_names)})", header_style="bold")
    for col in ("IOC", "Type", "Verdict", "Score", "Details"):
        t.add_column(col)
    for ioc in args.iocs:
        r = enricher.lookup(ioc.strip())
        details = "; ".join(f"{x['provider']}: " + ", ".join(f"{k}={v}" for k, v in x["details"].items() if v)
                            for x in r["results"] if x["details"]) or "-"
        style = {"malicious": "bold red", "suspicious": "yellow", "clean": "green"}.get(r["verdict"], "dim")
        t.add_row(ioc, str(r["type"]), f"[{style}]{r['verdict']}[/]", str(r.get("score", 0)), details)
    console.print(t)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sigilant", description="Sigilant pipeline: detect, enrich, triage, respond.")
    p.add_argument("--version", action="version", version=f"sigilant {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("simulate", help="generate a lab dataset with embedded attacks")
    s.add_argument("--out", default="samples")
    s.add_argument("--date", help="scenario date YYYY-MM-DD (default 2026-11-18)")
    s.add_argument("--seed", type=int, default=7)
    s.set_defaults(func=cmd_simulate)

    r = sub.add_parser("run", help="run the full pipeline on a log file or directory")
    r.add_argument("--input", "-i", required=True)
    r.add_argument("--out", "-o", default="output")
    r.add_argument("--rules", default=str(ROOT / "rules"))
    r.add_argument("--offline", action="store_true", help="use only the local threat-intel feed (no API calls)")
    r.add_argument("--year", type=int, help="year for BSD-syslog timestamps that lack one")
    r.set_defaults(func=cmd_run)

    ru = sub.add_parser("rules", help="validate, export or test detection rules")
    ru.add_argument("action", choices=["validate", "export", "test"])
    ru.add_argument("--rules", default=str(ROOT / "rules"))
    ru.add_argument("--target", choices=["splunk", "kql"], default="splunk")
    ru.add_argument("--strict", action="store_true", help="treat warnings as errors")
    ru.set_defaults(func=cmd_rules)

    e = sub.add_parser("enrich", help="look up IOCs (IP, domain, hash)")
    e.add_argument("iocs", nargs="+")
    e.add_argument("--offline", action="store_true")
    e.set_defaults(func=cmd_enrich)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
