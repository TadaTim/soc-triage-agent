"""Build packages/enrich/data/threat_intel.json from packages/evals/pools.py.

Run once (and whenever pools change); the output is committed so the feed is
a static, reviewable artifact — like a real intel feed snapshot.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from packages.evals import pools  # noqa: E402

OUT = ROOT / "packages" / "enrich" / "data" / "threat_intel.json"

FAMILIES = ["loader", "stealer", "ransomware", "rat", "phishing-kit"]


def main() -> int:
    indicators: list[dict[str, object]] = []
    for i, ip in enumerate(pools.BAD_IPS):
        indicators.append(
            {
                "value": ip,
                "type": "ipv4",
                "confidence": round(0.86 + (i % 14) / 100.0, 2),
                "source": "feed:community-threat-intel",
                "tags": ["c2", FAMILIES[i % len(FAMILIES)]],
            }
        )
    for i, domain in enumerate(pools.BAD_DOMAINS):
        indicators.append(
            {
                "value": domain,
                "type": "domain",
                "confidence": round(0.85 + (i % 15) / 100.0, 2),
                "source": "feed:phishing-url-exchange",
                "tags": ["phishing" if i % 2 == 0 else "c2"],
            }
        )
    for i, digest in enumerate(pools.BAD_SHA256):
        indicators.append(
            {
                "value": digest,
                "type": "sha256",
                "confidence": round(0.90 + (i % 10) / 100.0, 2),
                "source": "feed:malware-sample-exchange",
                "tags": [FAMILIES[(i + 2) % len(FAMILIES)]],
            }
        )
    doc = {
        "version": "2026-01-15",
        "note": (
            "Synthetic threat-intel snapshot built from packages/evals/pools.py "
            "by tools/build_intel_feed.py. All indicators are illustrative."
        ),
        "indicators": indicators,
        "known_good_sha256": pools.GOOD_SHA256,
    }
    OUT.write_text(json.dumps(doc, indent=2) + "\n")
    print(f"wrote {OUT} with {len(indicators)} indicators")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
