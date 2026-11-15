"""IP reputation: AbuseIPDB (optional, needs an API key) plus plain-text blocklist feeds.

Reputation is cached in the database, lookups only happen for public IPs and
never inside the ingest request (they run in a background thread).
"""

from __future__ import annotations

import ipaddress
import logging
import threading
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Optional

import requests
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import settings
from app.models import IPReputation
from app.services.normalizer import is_public_ip
from app.services.types import ReputationInfo

log = logging.getLogger("sentinelx.intel")

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"


class BlocklistStore:
    """In-memory set of blocklisted IPs/CIDRs loaded from public feeds."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._ips: dict[str, str] = {}
        self._nets: list[tuple[Any, str]] = []
        self.loaded_at: Optional[datetime] = None

    @staticmethod
    def parse(text: str) -> tuple[list[str], list[str]]:
        ips: list[str] = []
        nets: list[str] = []
        for line in text.splitlines():
            line = line.split("#", 1)[0].split(";", 1)[0].strip()
            if not line:
                continue
            token = line.split()[0].split(",")[0]
            try:
                if "/" in token:
                    nets.append(str(ipaddress.ip_network(token, strict=False)))
                else:
                    ips.append(str(ipaddress.ip_address(token)))
            except ValueError:
                continue
        return ips, nets

    def load(self, feeds: dict[str, str]) -> int:
        ips: dict[str, str] = {}
        nets: list[tuple] = []
        for name, text in feeds.items():
            feed_ips, feed_nets = self.parse(text)
            for ip in feed_ips:
                ips.setdefault(ip, name)
            nets.extend((ipaddress.ip_network(n), name) for n in feed_nets)
        with self._lock:
            self._ips, self._nets = ips, nets
            self.loaded_at = datetime.now(timezone.utc)
        return len(ips) + len(nets)

    def match(self, ip: str) -> Optional[str]:
        with self._lock:
            hit = self._ips.get(ip)
            if hit:
                return hit
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                return None
            for net, name in self._nets:
                if addr.version == net.version and addr in net:
                    return name
        return None

    @property
    def size(self) -> int:
        return len(self._ips) + len(self._nets)


blocklist = BlocklistStore()


def refresh_blocklists() -> int:
    """Download configured feeds. Failures are logged and leave the old data in place."""
    urls = settings.feed_urls
    if not urls:
        return 0
    feeds: dict[str, str] = {}
    for url in urls:
        try:
            resp = requests.get(url, timeout=20, headers={"User-Agent": "SentinelX/1.0"})
            resp.raise_for_status()
            name = url.rstrip("/").rsplit("/", 1)[-1] or url
            feeds[name] = resp.text[:20_000_000]
        except requests.RequestException as exc:
            log.warning("threat feed %s failed: %s", url, exc)
    if not feeds:
        return 0
    count = blocklist.load(feeds)
    log.info("loaded %d blocklist entries from %d feed(s)", count, len(feeds))
    return count


def _from_row(row: IPReputation) -> ReputationInfo:
    return ReputationInfo(
        ip=row.ip,
        score=row.score,
        is_malicious=row.is_malicious,
        source=row.source,
        country=row.country,
        isp=row.isp,
        total_reports=row.total_reports,
    )


def get_reputations(db: Session, ips: Iterable[str]) -> dict[str, ReputationInfo]:
    """Synchronous, network-free lookup: blocklist feeds first, then the DB cache."""
    result: dict[str, ReputationInfo] = {}
    wanted = {ip for ip in ips if is_public_ip(ip)}
    if not wanted:
        return result
    for ip in wanted:
        feed = blocklist.match(ip)
        if feed:
            result[ip] = ReputationInfo(ip=ip, score=100, is_malicious=True, source=f"blocklist:{feed}")
    rest = wanted - set(result)
    if rest:
        for row in db.scalars(select(IPReputation).where(IPReputation.ip.in_(sorted(rest)))):
            result[row.ip] = _from_row(row)
    return result


def lookup_abuseipdb(ip: str) -> Optional[ReputationInfo]:
    if not settings.abuseipdb_api_key:
        return None
    try:
        resp = requests.get(
            ABUSEIPDB_URL,
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": settings.abuseipdb_api_key, "Accept": "application/json"},
            timeout=8,
        )
        if resp.status_code == 429:
            log.warning("AbuseIPDB rate limit reached")
            return None
        resp.raise_for_status()
        data = resp.json().get("data", {})
    except (requests.RequestException, ValueError) as exc:
        log.warning("AbuseIPDB lookup failed for %s: %s", ip, exc)
        return None
    score = int(data.get("abuseConfidenceScore", 0))
    return ReputationInfo(
        ip=ip,
        score=score,
        is_malicious=score >= 75,
        source="abuseipdb",
        country=data.get("countryCode"),
        isp=data.get("isp"),
        total_reports=int(data.get("totalReports", 0)),
    )


def save_reputation(db: Session, info: ReputationInfo) -> None:
    row = db.get(IPReputation, info.ip)
    now = datetime.now(timezone.utc)
    if row is None:
        row = IPReputation(ip=info.ip)
        db.add(row)
    row.score = info.score
    row.is_malicious = info.is_malicious
    row.source = info.source
    row.country = info.country
    row.isp = info.isp
    row.total_reports = info.total_reports
    row.checked_at = now


def ips_needing_lookup(db: Session, ips: Iterable[str]) -> list[str]:
    """Public IPs with no fresh cached reputation (and not already covered by a blocklist)."""
    if not settings.abuseipdb_api_key:
        return []
    public = {ip for ip in ips if is_public_ip(ip) and not blocklist.match(ip)}
    if not public:
        return []
    cutoff = datetime.now(timezone.utc) - timedelta(hours=settings.reputation_ttl_hours)
    fresh = {
        row.ip
        for row in db.scalars(select(IPReputation).where(IPReputation.ip.in_(sorted(public)), IPReputation.checked_at >= cutoff))
    }
    return sorted(public - fresh)[: settings.abuseipdb_max_lookups_per_batch]
