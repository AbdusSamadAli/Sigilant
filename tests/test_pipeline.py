import json

import pytest

from sigilant.pipeline import PipelineConfig, run
from sigilant.simulate import PAYLOAD_SHA256, generate


@pytest.fixture(scope="module")
def result(tmp_path_factory):
    base = tmp_path_factory.mktemp("e2e")
    generate(base / "logs")
    cfg = PipelineConfig(input=base / "logs", output=base / "out", cache=base / "cache.sqlite", offline=True)
    return run(cfg), base / "out"


def test_all_rules_fire(result):
    res, _ = result
    fired = {a.rule_id for a in res.alerts}
    assert res.stats["rules"]["sigma"] + res.stats["rules"]["correlation"] == len(fired)


def test_no_false_positives_from_benign_noise(result):
    res, _ = result
    blob = json.dumps([e.get("ParentImage", "") + e.get("SourceImage", "") for a in res.alerts for e in a.evidence])
    assert "GoogleUpdate" not in blob and "MsMpEng" not in blob
    assert not any("10.0.0.31" in a.entities.get("source.ip", []) for a in res.alerts)


def test_cases_are_correlated(result):
    res, _ = result
    assert len(res.cases) == 2 and all(c.priority == "P1" for c in res.cases)
    windows_case = next(c for c in res.cases if "WS01" in c.entities["host.name"])
    assert "DC01" in windows_case.entities["host.name"]
    assert "lateral_movement" in windows_case.tactics


def test_intel_enrichment_finds_hidden_c2_domain(result):
    res, _ = result
    iocs = {ioc: e["verdict"] for a in res.alerts for ioc, e in a.enrichment.items()}
    assert iocs["update-cdn-microsoft.com"] == "malicious"
    assert iocs[PAYLOAD_SHA256] == "malicious"


def test_response_actions_are_safe(result):
    res, out = result
    actions = [a for c in res.cases for a in c.actions]
    assert all(a["status"] == "pending_approval" for a in actions)
    hashes = {a["target"] for a in actions if a["action"] == "block_hash"}
    assert hashes == {PAYLOAD_SHA256}
    disabled = {a["target"] for a in actions if a["action"] == "disable_account"}
    assert disabled == {"sysupdate", "helpdesk_svc"}
    assert (out / "dashboard.html").stat().st_size > 5000
    assert len((out / "alerts.jsonl").read_text().splitlines()) == len(res.alerts)
