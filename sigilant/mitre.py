from __future__ import annotations

TACTICS = [
    "reconnaissance", "resource_development", "initial_access", "execution", "persistence",
    "privilege_escalation", "defense_evasion", "credential_access", "discovery",
    "lateral_movement", "collection", "command_and_control", "exfiltration", "impact",
]

TECHNIQUES = {
    "T1003.001": "OS Credential Dumping: LSASS Memory",
    "T1053.005": "Scheduled Task/Job: Scheduled Task",
    "T1059.001": "Command and Scripting Interpreter: PowerShell",
    "T1059.004": "Command and Scripting Interpreter: Unix Shell",
    "T1070.001": "Indicator Removal: Clear Windows Event Logs",
    "T1078": "Valid Accounts",
    "T1098": "Account Manipulation",
    "T1105": "Ingress Tool Transfer",
    "T1110.001": "Brute Force: Password Guessing",
    "T1110.003": "Brute Force: Password Spraying",
    "T1136.001": "Create Account: Local Account",
    "T1190": "Exploit Public-Facing Application",
    "T1548.003": "Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
    "T1566.001": "Phishing: Spearphishing Attachment",
    "T1595.002": "Active Scanning: Vulnerability Scanning",
    "T1595.003": "Active Scanning: Wordlist Scanning",
    "T1027": "Obfuscated Files or Information",
    "T1033": "System Owner/User Discovery",
    "T1059": "Command and Scripting Interpreter",
    "T1087.002": "Account Discovery: Domain Account",
    "T1110": "Brute Force",
    "T1204.002": "User Execution: Malicious File",
    "T1140": "Deobfuscate/Decode Files or Information",
}


def tactic_rank(tactic: str) -> int:
    try:
        return TACTICS.index(tactic)
    except ValueError:
        return 99


def parse_tags(tags: list[str]) -> tuple[list[str], list[str]]:
    techniques, tactics = [], []
    for tag in tags or []:
        tag = tag.lower()
        if not tag.startswith("attack."):
            continue
        value = tag[len("attack."):]
        if value[:1] == "t" and value[1:2].isdigit():
            techniques.append(value.upper())
        elif value.replace("-", "_") in TACTICS:
            tactics.append(value.replace("-", "_"))
    return techniques, tactics


def technique_name(tid: str) -> str:
    return TECHNIQUES.get(tid, "")


def technique_url(tid: str) -> str:
    return "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/"
