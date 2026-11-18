from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path

from .detection import DetectionEngine
from .enrichment import Enricher
from .ingest import load_path
from .models import Alert, Case
from .playbooks import apply_playbooks, load_playbooks, write_response_files
from .report import write_all
from .triage import AssetInventory, build_cases

ROOT = Path(__file__).resolve().parent.parent


@dataclass
class PipelineConfig:
    input: Path
    output: Path = Path("output")
    rules_dir: Path = ROOT / "rules"
    assets: Path = ROOT / "config" / "assets.yml"
    playbooks: Path = ROOT / "config" / "playbooks.yml"
    intel_feed: Path = ROOT / "data" / "threat_intel.csv"
    cache: Path = Path(".cache") / "intel.sqlite"
    offline: bool = False
    year: int | None = None


@dataclass
class PipelineResult:
    events: int
    alerts: list[Alert]
    cases: list[Case]
    stats: dict
    outputs: dict[str, Path]
    timings: dict[str, float] = field(default_factory=dict)


def run(cfg: PipelineConfig, progress=None) -> PipelineResult:
    step = progress or (lambda msg: None)
    timings: dict[str, float] = {}

    def timed(name, fn, *args):
        t0 = time.perf_counter()
        out = fn(*args)
        timings[name] = time.perf_counter() - t0
        return out

    step("Ingesting and normalising logs")
    events, sources = timed("ingest", load_path, cfg.input, cfg.year)
    if not events:
        raise SystemExit(f"No parsable log files found in {cfg.input}")

    step("Running detection rules")
    engine = DetectionEngine.from_directory(cfg.rules_dir)
    alerts = timed("detect", engine.run, events)

    step("Enriching indicators with threat intelligence")
    enricher = Enricher(cfg.intel_feed, cfg.cache, offline=cfg.offline)
    timed("enrich", enricher.enrich, alerts)

    step("Scoring alerts and correlating into cases")
    assets = AssetInventory.load(cfg.assets)
    cases = timed("triage", build_cases, alerts, assets)

    step("Applying response playbooks")
    apply_playbooks(cases, load_playbooks(cfg.playbooks))
    write_response_files(cases, cfg.output)

    stats = {
        "events": len(events), "sources": sources, "alerts": len(alerts),
        "rules": {"sigma": len(engine.sigma_rules), "correlation": len(engine.correlation_rules)},
        "providers": enricher.provider_names,
        "techniques": len({t for a in alerts for t in a.techniques}),
        "noise_reduction": len(events) / max(1, len(alerts)),
    }
    step("Writing reports")
    outputs = timed("report", write_all, cfg.output, cases, alerts, stats)
    return PipelineResult(len(events), alerts, cases, stats, outputs, timings)
