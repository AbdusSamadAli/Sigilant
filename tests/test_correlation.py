from datetime import datetime, timedelta, timezone

from sigilant.detection.correlation import CorrelationRule

T0 = datetime(2026, 11, 18, 2, 0, tzinfo=timezone.utc)
FAIL = {"event.action": "ssh_login", "event.outcome": "failure"}
OK = {"event.action": "ssh_login", "event.outcome": "success"}


def ev(sec, ip="1.2.3.4", user="root", **kw):
    return {"@timestamp": T0 + timedelta(seconds=sec), "source.ip": ip, "user.name": user, **FAIL, **kw}


def make(**kw):
    base = {"id": "r", "title": "r", "level": "high", "group_by": ["source.ip"], "timeframe": "2m",
            "tags": ["attack.t1110.001"]}
    return CorrelationRule.from_dict({**base, **kw})


def test_threshold_fires_once_and_extends():
    r = make(type="threshold", filter=FAIL, threshold=5)
    alerts = r.evaluate([ev(i * 5) for i in range(20)])
    assert len(alerts) == 1 and alerts[0].event_count == 20


def test_threshold_respects_window():
    r = make(type="threshold", filter=FAIL, threshold=5)
    assert r.evaluate([ev(i * 60) for i in range(10)]) == []


def test_threshold_groups_separately():
    r = make(type="threshold", filter=FAIL, threshold=5)
    events = sorted([ev(i, ip="1.1.1.1") for i in range(3)] + [ev(i, ip="2.2.2.2") for i in range(3)],
                    key=lambda e: e["@timestamp"])
    assert r.evaluate(events) == []


def test_distinct_count_detects_spraying():
    r = make(type="distinct_count", filter=FAIL, threshold=4, distinct_field="user.name", timeframe="10m")
    spray = [ev(i * 3, user=u) for i, u in enumerate(["a", "b", "c", "d", "e"])]
    brute = [ev(i * 3, ip="9.9.9.9", user="root") for i in range(10)]
    alerts = r.evaluate(sorted(spray + brute, key=lambda e: e["@timestamp"]))
    assert [a.entities["source.ip"] for a in alerts] == [["1.2.3.4"]]


def test_sequence_success_after_failures():
    r = make(type="sequence", timeframe="10m",
             steps=[{"filter": FAIL, "min_count": 5}, {"filter": OK}])
    events = [ev(i * 5) for i in range(6)] + [{**ev(40), **OK}]
    alerts = r.evaluate(events)
    assert len(alerts) == 1 and alerts[0].severity == "high"
    assert r.evaluate([ev(0), {**ev(5), **OK}]) == []
