"""Canonical indicator pools shared by the threat-intel feed builder and the
golden-dataset generator.

The intel feed (packages/enrich/data/threat_intel.json) is BUILT from these
pools by tools/build_intel_feed.py and committed, so the enrichment layer and
the eval set agree on which indicators are "known bad" — exactly like a real
SOC, where the intel feed exists before the alerts arrive.

All addresses/domains here are synthetic. Public-looking IPs are illustrative;
documentation-range IPs (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) are
used deliberately for the adversarial "threat report" cases.
"""

from __future__ import annotations

import hashlib


def _sha(seed: str) -> str:
    return hashlib.sha256(seed.encode()).hexdigest()


# --- Known-bad indicators: present in the threat-intel feed -------------------

BAD_IPS: list[str] = [
    f"{prefix}.{host}"
    for prefix in (
        "185.220.101",
        "45.155.204",
        "193.32.162",
        "91.240.118",
        "103.75.201",
        "196.251.72",
    )
    for host in (7, 23, 41, 88, 130, 254)
]  # 36 addresses

BAD_DOMAINS: list[str] = [
    "cdn-update-service.net",
    "secure-login-verify.com",
    "account-recovery-portal.net",
    "fileshare-delivery.com",
    "doc-viewer-online.net",
    "payment-confirm-center.com",
    "telemetry-collect.io",
    "update-flash-player.net",
    "mailbox-quota-alert.com",
    "storage-sync-service.net",
    "invoice-portal-online.com",
    "hr-benefits-login.net",
    "tax-docs-secure.com",
    "parcel-tracking-hub.net",
    "banking-session-verify.com",
    "cloud-drive-share.net",
    "vpn-gateway-update.com",
    "helpdesk-ticket-portal.net",
    "crypto-wallet-verify.io",
    "streaming-account-alert.com",
    "utility-bill-pay.net",
    "travel-booking-confirm.com",
    "software-license-renew.net",
    "domain-expiry-notice.com",
    "payroll-direct-update.net",
    "insurance-claim-portal.com",
    "edu-portal-signin.net",
    "gov-forms-download.com",
    "mobile-carrier-alert.net",
    "loyalty-points-claim.com",
]  # 30 domains

BAD_SHA256: list[str] = [_sha(f"malware-sample-{i}") for i in range(30)]

# --- Indicators NOT in the feed (behavior must catch these cases) ------------

UNKNOWN_BAD_IPS: list[str] = [f"176.113.115.{h}" for h in (19, 62, 140)] + [
    f"89.208.33.{h}" for h in (51, 97)
]

DGA_DOMAINS: list[str] = [
    "xj4k9pzq2m.top",
    "qzv8wn3brk7.xyz",
    "m2p9x7kq4wz.top",
    "zk8w2n5p9qrx.xyz",
    "v7b3n9m2k8qw.top",
    "p9q4w7z2x5kn.xyz",
]

UNKNOWN_SHA256: list[str] = [_sha(f"unknown-binary-{i}") for i in range(12)]

# --- Benign reference data ----------------------------------------------------

GOOD_SHA256: list[str] = [_sha(f"legit-binary-{i}") for i in range(30)]

GOOD_DOMAINS: list[str] = [
    "update.microsoft.com",
    "download.mozilla.org",
    "archive.ubuntu.com",
    "dl.google.com",
    "swcdn.apple.com",
]

POPULAR_DOMAINS: list[str] = [
    "www.google.com",
    "en.wikipedia.org",
    "github.com",
    "stackoverflow.com",
    "www.nytimes.com",
    "www.amazon.com",
    "login.microsoftonline.com",
    "www.bbc.com",
]

DOC_IPS: list[str] = ["203.0.113.10", "198.51.100.23", "192.0.2.44"]

SCANNER_IP = "10.13.0.50"
OFFICE_EGRESS_IP = "72.165.34.18"
BACKUP_SERVER_IP = "10.13.4.20"

USERS: list[str] = [
    "j.martinez",
    "a.okafor",
    "s.nguyen",
    "t.alvarez",
    "r.kowalski",
    "m.haddad",
    "e.fischer",
    "d.oneill",
    "k.tanaka",
    "b.novak",
]

WORKSTATIONS: list[str] = [f"WS-{n}" for n in range(1001, 1061)]
SERVERS: list[str] = [f"SRV-{n}" for n in range(2001, 2013)]
PENTEST_HOST = "WS-1031"
PENTEST_TICKET = "PT-2026-118"
