"""Threat-intel / asset / allowlist unit tests."""

from __future__ import annotations

from datetime import date

import pytest

from packages.enrich.intel import AssetInventory, ThreatIntel, ip_class


@pytest.fixture(scope="module")
def intel() -> ThreatIntel:
    return ThreatIntel.from_data_dir()


def test_lookup_exact_and_parent(intel: ThreatIntel) -> None:
    assert intel.lookup("185.220.101.7") is not None
    hit = intel.lookup("a1b2c3.secure-login-verify.com")
    assert hit is not None and hit.matched_value == "secure-login-verify.com"
    assert intel.lookup("example.org") is None
    assert intel.lookup("8.8.8.8") is None


def test_known_good_and_allowlists(intel: ThreatIntel) -> None:
    from packages.evals import pools

    assert intel.is_known_good_hash(pools.GOOD_SHA256[0])
    assert not intel.is_known_good_hash(pools.BAD_SHA256[0])
    assert intel.is_scanner("10.13.0.50")
    assert intel.is_office_egress("72.165.34.18")
    assert intel.is_trusted_domain("update.microsoft.com")
    assert intel.is_trusted_domain("cdn.update.microsoft.com")  # parent walk
    assert not intel.is_trusted_domain("secure-login-verify.com")


def test_engagement_window(intel: ThreatIntel) -> None:
    hit = intel.engagement_for("WS-1031", date(2026, 1, 14))
    assert hit is not None and hit["ticket"] == "PT-2026-118"
    assert intel.engagement_for("WS-1031", date(2026, 2, 1)) is None  # outside window
    assert intel.engagement_for("WS-9999", date(2026, 1, 14)) is None  # wrong host
    assert intel.engagement_for(None, date(2026, 1, 14)) is None


def test_ip_class() -> None:
    assert ip_class("185.220.101.7") == "global"
    assert ip_class("10.13.7.15") == "private"
    assert ip_class("203.0.113.10") == "documentation"
    assert ip_class("198.51.100.23") == "documentation"
    assert ip_class("192.0.2.44") == "documentation"
    assert ip_class("not-an-ip") == "other"
    assert ip_class("240.0.0.1") == "private"  # ipaddress treats 240/4 as not globally reachable
    assert ip_class("224.0.0.1") == "global"  # ipaddress marks multicast globally scoped


def test_asset_inventory() -> None:
    assets = AssetInventory.from_data_dir()
    dc = assets.lookup("DC-01")
    assert dc is not None and dc.criticality == "critical"
    assert assets.lookup("WS-9999") is None
    assert assets.lookup(None) is None
