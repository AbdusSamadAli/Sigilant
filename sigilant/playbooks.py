from __future__ import annotations

import re
from pathlib import Path

import yaml

from .models import Alert, Case
from .utils import is_public_ip

TASK_NAME = re.compile(r'/tn\s+(?:"([^"]+)"|(\S+))', re.IGNORECASE)
PROTECTED_ACCOUNTS = {"root", "administrator", "system", "local service", "network service", "krbtgt"}

def load_playbooks(path: Path) -> list[dict]:
    with open(path, encoding="utf-8") as fh:
        return (yaml.safe_load(fh) or {}).get("playbooks", [])


def _platform(alert: Alert) -> str:
    datasets = {e.get("event.dataset", "") for e in alert.evidence}
    return "windows" if any(d.startswith("windows") for d in datasets) else "linux"


def _matches(pb: dict, alert: Alert) -> bool:
    if alert.rule_id in pb.get("match_rules", []):
        return True
    return any(t == p or t.startswith(p + ".") for t in alert.techniques for p in pb.get("match_techniques", []))


def _commands(action: str, target: str, platform: str) -> str:
    if action == "block_ip":
        if platform == "windows":
            return "\n".join(f'New-NetFirewallRule -DisplayName "Sigilant block {target} {d}" -Direction {d} '
                             f'-RemoteAddress {target} -Action Block' for d in ("Inbound", "Outbound"))
        return f"sudo iptables -I INPUT -s {target} -j DROP"
    if action == "disable_account":
        return f"net user {target} /active:no" if platform == "windows" else f"sudo usermod -L -e 1 {target}"
    if action == "reset_credentials":
        return (f"# Force password reset + revoke sessions for '{target}'"
                + ("" if platform == "windows" else f"\nsudo passwd -e {target} && sudo pkill -KILL -u {target}"))
    if action == "isolate_host":
        return f"# EDR: network-isolate host '{target}' (e.g. Defender 'Isolate device'); keep for forensics"
    if action == "block_hash":
        return f"# EDR / AV: add SHA256 {target} to the custom block list"
    if action == "remove_scheduled_task":
        return f'schtasks /Delete /TN "{target}" /F'
    return f"# {action}: {target}"


def _targets(action: str, alerts: list[Alert]) -> list[tuple[str, str]]:
    out = []
    for a in alerts:
        plat = _platform(a)
        ents = a.entities
        if action == "block_ip":
            out += [(ip, plat) for ip in ents.get("source.ip", []) + ents.get("destination.ip", [])
                    if is_public_ip(ip)]
        elif action == "disable_account":
            out += [(u, plat) for u in ents.get("user.target.name", []) if u.lower() not in PROTECTED_ACCOUNTS]
        elif action == "reset_credentials":
            out += [(e["user.name"], plat) for e in a.evidence
                    if e.get("event.outcome") == "success" and e.get("user.name")
                    and e["user.name"].lower() not in PROTECTED_ACCOUNTS]
        elif action == "isolate_host":
            out += [(h, plat) for h in ents.get("host.name", [])]
        elif action == "block_hash":
            out += [(h, plat) for h in ents.get("file.hash.sha256", [])
                    if a.enrichment.get(h, {}).get("verdict") in ("malicious", "suspicious")]
        elif action == "remove_scheduled_task":
            for ev in a.evidence:
                tn = ev.get("TaskName")
                if not tn and (m := TASK_NAME.search(str(ev.get("CommandLine", "")))):
                    tn = m.group(1) or m.group(2)
                if tn:
                    out.append((tn.lstrip("\\"), "windows"))
    return list(dict.fromkeys(out))


def apply_playbooks(cases: list[Case], playbooks: list[dict]) -> None:
    for case in cases:
        case.playbooks, case.actions = [], []
        seen_actions = set()
        for pb in playbooks:
            matched = [a for a in case.alerts if _matches(pb, a)]
            if not matched:
                continue
            if pb.get("min_priority") and case.priority > pb["min_priority"]:
                continue
            case.playbooks.append({"id": pb["id"], "name": pb["name"], "steps": pb.get("steps", []),
                                   "triggered_by": sorted({a.rule_id for a in matched})})
            for action in pb.get("actions", []):
                for target, plat in _targets(action, matched):
                    key = (action, target)
                    if key in seen_actions:
                        continue
                    seen_actions.add(key)
                    case.actions.append({"action": action, "target": target, "platform": plat,
                                         "playbook": pb["id"], "command": _commands(action, target, plat),
                                         "status": "pending_approval"})


def write_response_files(cases: list[Case], out_dir: Path) -> None:
    for case in cases:
        if not case.actions:
            continue
        d = out_dir / "response" / case.case_id
        d.mkdir(parents=True, exist_ok=True)
        for plat, ext, comment in (("linux", "sh", "#"), ("windows", "ps1", "#")):
            acts = [a for a in case.actions if a["platform"] == plat]
            if not acts:
                continue
            lines = [f"{comment} Sigilant containment for {case.case_id} ({case.priority}) - {case.title}",
                     f"{comment} GENERATED FOR REVIEW. Nothing has been executed. Approve each line before running.",
                     ""]
            for a in acts:
                lines += [f"{comment} [{a['playbook']}] {a['action']} -> {a['target']}", a["command"], ""]
            (d / f"containment.{ext}").write_text("\n".join(lines), encoding="utf-8")
        ips = sorted({a["target"] for a in case.actions if a["action"] == "block_ip"})
        if ips:
            (d / "blocklist.txt").write_text("\n".join(ips) + "\n", encoding="utf-8")
