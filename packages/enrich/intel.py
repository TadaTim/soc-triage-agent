"""Threat-intel feed, asset inventory, and SOC allowlists.

All three are loaded from committed snapshot files under packages/enrich/data
— the same shape as production, where these arrive as feed/inventory syncs.
Domain lookups walk parent domains (a hit on `evil.example` also matches
`a.b.evil.example`), which is how real feeds are consumed.
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

DATA_DIR = Path(__file__).with_name("data")

# RFC 5737 documentation ranges — never routable, never a real threat.
DOCUMENTATION_NETS = [
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
]


@dataclass(frozen=True)
class IntelRecord:
    value: str
    type: str
    confidence: float
    source: str
    tags: list[str] = field(default_factory=list)
    matched_value: str = ""  # the feed entry that matched (may be a parent domain)

    def __post_init__(self) -> None:
        if not self.matched_value:
            object.__setattr__(self, "matched_value", self.value)


class ThreatIntel:
    def __init__(
        self,
        indicators: dict[str, IntelRecord],
        known_good_sha256: set[str],
        scanner_ips: set[str],
        office_egress_ips: set[str],
        trusted_domains: set[str],
        pentest_engagements: list[dict[str, str]],
    ) -> None:
        self._indicators = indicators
        self._known_good = known_good_sha256
        self._scanner_ips = scanner_ips
        self._office_egress = office_egress_ips
        self._trusted_domains = trusted_domains
        self._engagements = pentest_engagements

    @classmethod
    def from_data_dir(cls, data_dir: Path = DATA_DIR) -> ThreatIntel:
        feed = json.loads((data_dir / "threat_intel.json").read_text())
        allow = json.loads((data_dir / "allowlist.json").read_text())
        indicators = {
            entry["value"]: IntelRecord(
                value=entry["value"],
                type=entry["type"],
                confidence=float(entry["confidence"]),
                source=entry["source"],
                tags=list(entry.get("tags", [])),
            )
            for entry in feed["indicators"]
        }
        return cls(
            indicators=indicators,
            known_good_sha256=set(feed.get("known_good_sha256", [])),
            scanner_ips=set(allow.get("scanner_ips", [])),
            office_egress_ips=set(allow.get("office_egress_ips", [])),
            trusted_domains=set(allow.get("trusted_domains", [])),
            pentest_engagements=list(allow.get("pentest_engagements", [])),
        )

    def lookup(self, value: str) -> IntelRecord | None:
        """Exact match, then parent-domain walk for domains."""
        value = value.lower()
        if value in self._indicators:
            return self._indicators[value]
        labels = value.split(".")
        for i in range(1, len(labels) - 1):
            parent = ".".join(labels[i:])
            if parent in self._indicators:
                record = self._indicators[parent]
                return IntelRecord(
                    value=value,
                    type=record.type,
                    confidence=record.confidence,
                    source=record.source,
                    tags=record.tags,
                    matched_value=parent,
                )
        return None

    def is_known_good_hash(self, value: str) -> bool:
        return value.lower() in self._known_good

    def is_scanner(self, ip: str) -> bool:
        return ip in self._scanner_ips

    def is_office_egress(self, ip: str) -> bool:
        return ip in self._office_egress

    def is_trusted_domain(self, domain: str) -> bool:
        domain = domain.lower()
        if domain in self._trusted_domains:
            return True
        labels = domain.split(".")
        return any(".".join(labels[i:]) in self._trusted_domains for i in range(1, len(labels) - 1))

    def engagement_for(self, host: str | None, on: date) -> dict[str, str] | None:
        """Return the authorized pentest engagement covering host+date, if any."""
        if host is None:
            return None
        for engagement in self._engagements:
            if engagement["host"] != host:
                continue
            if (
                date.fromisoformat(engagement["start"])
                <= on
                <= date.fromisoformat(engagement["end"])
            ):
                return engagement
        return None


def ip_class(ip: str) -> str:
    """Classify an IP: 'global', 'private', 'documentation', or 'other'."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "other"
    if any(addr in net for net in DOCUMENTATION_NETS):
        return "documentation"
    if addr.is_private:
        return "private"
    if addr.is_global:
        return "global"
    return "other"


@dataclass(frozen=True)
class Asset:
    host: str
    ip: str
    criticality: str  # low | medium | high | critical
    owner: str
    type: str


class AssetInventory:
    def __init__(self, assets: dict[str, Asset]) -> None:
        self._assets = assets

    @classmethod
    def from_data_dir(cls, data_dir: Path = DATA_DIR) -> AssetInventory:
        raw = json.loads((data_dir / "assets.json").read_text())
        return cls({entry["host"]: Asset(**entry) for entry in raw["assets"]})

    def lookup(self, host: str | None) -> Asset | None:
        if host is None:
            return None
        return self._assets.get(host)
