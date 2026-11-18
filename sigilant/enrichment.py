from __future__ import annotations

import csv
import json
import os
import re
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

import requests

from .models import Alert
from .utils import is_ip, is_public_ip

HASH_RE = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")
DOMAIN_RE = re.compile(r"^(?=.{4,253}$)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$", re.I)


def ioc_type(value: str) -> str | None:
    if is_ip(value):
        return "ip"
    if HASH_RE.match(value):
        return "hash"
    if value.lower().startswith(("http://", "https://")):
        return "url"
    if DOMAIN_RE.match(value):
        return "domain"
    return None


@dataclass
class IntelResult:
    provider: str
    ioc: str
    verdict: str
    score: int
    details: dict

    def to_dict(self):
        return self.__dict__


class Cache:
    def __init__(self, path: Path, ttl_hours: int = 24):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path)
        self.ttl = ttl_hours * 3600
        self.db.execute("CREATE TABLE IF NOT EXISTS intel (provider TEXT, ioc TEXT, ts REAL, data TEXT,"
                        " PRIMARY KEY (provider, ioc))")

    def get(self, provider: str, ioc: str) -> IntelResult | None:
        row = self.db.execute("SELECT ts, data FROM intel WHERE provider=? AND ioc=?", (provider, ioc)).fetchone()
        if row and time.time() - row[0] < self.ttl:
            return IntelResult(**json.loads(row[1]))
        return None

    def set(self, result: IntelResult) -> None:
        self.db.execute("INSERT OR REPLACE INTO intel VALUES (?,?,?,?)",
                        (result.provider, result.ioc, time.time(), json.dumps(result.to_dict())))
        self.db.commit()


class RateLimiter:

    def __init__(self, per_minute: int):
        self.interval = 60.0 / per_minute
        self.last = 0.0
        self.lock = threading.Lock()

    def wait(self):
        with self.lock:
            delay = self.last + self.interval - time.monotonic()
            if delay > 0:
                time.sleep(delay)
            self.last = time.monotonic()


def _get_json(url: str, *, headers: dict, params: dict | None = None, limiter: RateLimiter,
              retries: int = 3) -> dict | None:
    for attempt in range(retries):
        limiter.wait()
        try:
            resp = requests.get(url, headers=headers, params=params, timeout=15)
        except requests.RequestException:
            time.sleep(2 ** attempt)
            continue
        if resp.status_code == 429:
            time.sleep(float(resp.headers.get("Retry-After", 2 ** (attempt + 2))))
            continue
        if resp.status_code == 404:
            return {}
        if resp.ok:
            return resp.json()
        return None
    return None


class LocalFeed:
    name = "local_feed"
    supports = {"ip", "domain", "hash", "url"}

    def __init__(self, path: Path):
        self.iocs: dict[str, dict] = {}
        if path.exists():
            with open(path, encoding="utf-8") as fh:
                for row in csv.DictReader(fh):
                    self.iocs[row["ioc"].strip().lower()] = row

    def lookup(self, ioc: str, kind: str) -> IntelResult | None:
        row = self.iocs.get(ioc.lower())
        if not row:
            return IntelResult(self.name, ioc, "unknown", 0, {})
        conf = int(row.get("confidence") or 80)
        return IntelResult(self.name, ioc, "malicious" if conf >= 70 else "suspicious", conf,
                           {"source": row.get("source"), "description": row.get("description")})


class AbuseIPDB:
    name = "abuseipdb"
    supports = {"ip"}

    def __init__(self, key: str):
        self.key = key
        self.limiter = RateLimiter(per_minute=30)

    def lookup(self, ioc: str, kind: str) -> IntelResult | None:
        data = _get_json("https://api.abuseipdb.com/api/v2/check",
                         headers={"Key": self.key, "Accept": "application/json"},
                         params={"ipAddress": ioc, "maxAgeInDays": 90}, limiter=self.limiter)
        if data is None:
            return None
        d = data.get("data", {})
        score = int(d.get("abuseConfidenceScore", 0))
        verdict = "malicious" if score >= 75 else "suspicious" if score >= 25 else "clean"
        return IntelResult(self.name, ioc, verdict, score, {
            "country": d.get("countryCode"), "isp": d.get("isp"), "usage": d.get("usageType"),
            "total_reports": d.get("totalReports"), "is_tor": d.get("isTor")})


class VirusTotal:
    name = "virustotal"
    supports = {"ip", "domain", "hash"}
    PATHS = {"ip": "ip_addresses", "domain": "domains", "hash": "files"}

    def __init__(self, key: str):
        self.key = key
        self.limiter = RateLimiter(per_minute=4)

    def lookup(self, ioc: str, kind: str) -> IntelResult | None:
        data = _get_json(f"https://www.virustotal.com/api/v3/{self.PATHS[kind]}/{ioc}",
                         headers={"x-apikey": self.key}, limiter=self.limiter)
        if data is None:
            return None
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        mal, sus = stats.get("malicious", 0), stats.get("suspicious", 0)
        total = sum(stats.values()) or 1
        verdict = "malicious" if mal >= 3 else "suspicious" if mal + sus >= 1 else ("clean" if stats else "unknown")
        return IntelResult(self.name, ioc, verdict, min(100, round(100 * (mal + sus) / total * 3)), {
            "malicious": mal, "suspicious": sus, "engines": total,
            "name": attrs.get("meaningful_name"), "as_owner": attrs.get("as_owner"),
            "country": attrs.get("country")})


VERDICT_RANK = {"malicious": 3, "suspicious": 2, "clean": 1, "unknown": 0}


class Enricher:
    def __init__(self, feed_path: Path, cache_path: Path, offline: bool = False):
        self.providers = [LocalFeed(feed_path)]
        if not offline:
            if key := os.getenv("ABUSEIPDB_API_KEY"):
                self.providers.append(AbuseIPDB(key))
            if key := os.getenv("VT_API_KEY"):
                self.providers.append(VirusTotal(key))
        self.cache = Cache(cache_path)

    @property
    def provider_names(self) -> list[str]:
        return [p.name for p in self.providers]

    def lookup(self, ioc: str) -> dict:
        kind = ioc_type(ioc)
        if kind is None or (kind == "ip" and not is_public_ip(ioc)):
            return {"ioc": ioc, "type": kind, "verdict": "skipped", "results": []}
        results = []
        for prov in self.providers:
            if kind not in prov.supports:
                continue
            res = None if prov.name == "local_feed" else self.cache.get(prov.name, ioc)
            if res is None:
                res = prov.lookup(ioc, kind)
                if res and prov.name != "local_feed":
                    self.cache.set(res)
            if res:
                results.append(res)
        best = max(results, key=lambda r: (VERDICT_RANK[r.verdict], r.score), default=None)
        return {"ioc": ioc, "type": kind, "verdict": best.verdict if best else "unknown",
                "score": best.score if best else 0, "results": [r.to_dict() for r in results]}

    @staticmethod
    def iocs_for(alert: Alert) -> list[str]:
        ents = alert.entities
        iocs = [ip for key in ("source.ip", "destination.ip") for ip in ents.get(key, []) if is_public_ip(ip)]
        iocs += ents.get("file.hash.sha256", [])
        for ev in alert.evidence:
            text = f"{ev.get('process.command_line', '')} {ev.get('process.command_line.decoded', '')}"
            for url in re.findall(r"https?://[^\s\"')]+", text):
                host = urlsplit(url).hostname or ""
                if host and host not in iocs:
                    iocs.append(host)
        return list(dict.fromkeys(iocs))

    def enrich(self, alerts: list[Alert]) -> dict[str, dict]:
        seen: dict[str, dict] = {}
        for alert in alerts:
            alert.enrichment = {}
            for ioc in self.iocs_for(alert):
                if ioc not in seen:
                    seen[ioc] = self.lookup(ioc)
                alert.enrichment[ioc] = seen[ioc]
        return seen
