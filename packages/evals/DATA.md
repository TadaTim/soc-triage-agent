# Golden Dataset — Provenance & Method

**File:** `dataset.jsonl` · **Size:** 500 alerts · **Generator:** `generate.py`
(seeded RNG, seed `20260115`; regenerate with `python -m packages.evals.generate`
— output is byte-identical for a given seed).

## Changelog

- **v1 (2026-01-15):** initial 500-alert set — 315 benign / 165 malicious /
  20 needs-human, including 70 adversarial cases. See method below.

## Why the dataset is built here (Stage 3), not at the AI stage

A triage system's thresholds are only meaningful against a labeled set that
exists *before* the scoring rules are tuned. Building the eval set at the data
stage means Stage 4/6 code is written against a fixed target, and any later
label change is a deliberate, changelogged event (CI enforces this — see the
dataset-regression job in `.github/workflows/ci.yml`).

## Sources & approach

The set is **synthetic**, assembled from templates modeled on the alert shapes
of public SOC/IR corpora and write-ups — the MITRE ATT&CK® technique
descriptions (attack.mitre.org) for behavior shapes (beaconing T1113-adjacent
patterns, PowerShell download cradles T1059.001, DNS tunneling T1071.004,
brute force T1110), the Sigma rule corpus (github.com/SigmaHQ/sigma) for
detection-title conventions, and standard blue-team training ranges for the
benign background (vulnerability scans, patch cycles, backup windows).
No real incident data, real indicators, or personal data are included: every
IP, domain, and hash is fabricated. Known-bad indicators live in
`packages/evals/pools.py`, from which the threat-intel snapshot
(`packages/enrich/data/threat_intel.json`) is built by
`tools/build_intel_feed.py` — the feed therefore predates the alerts, as it
would in a real SOC.

## Composition

| Class | Count | Notes |
|---|---|---|
| Benign | 315 | Background SOC noise: scans, updates, backups, logons, maintenance |
| Malicious | 165 | Intel-detectable (feed hits) and behavior-detectable (download cradle) |
| Needs human | 20 | Genuinely ambiguous: encoded command with no payload, unknown hash on a server, DGA-shaped domain absent from feeds |

## Adversarial cases (70)

Built on the design premise that attackers craft telemetry to be closed as
benign, and that scary language is cheap:

- **Benign-looking malicious (20):** informational "successful logon",
  "scheduled transfer completed", "installation completed" — whose only tell
  is a threat-intel hit on an IP / domain / hash.
- **Scary-looking benign (50):** a threat-intel digest quoting
  documentation-range IPs (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) and
  an `.invalid` illustration domain; an authorized red-team exercise inside
  its engagement-window (the pentest calendar is the ground truth); a
  ransomware *scare* (tech-support pop-up) with zero forensic evidence.

## Labeling rules

Each record carries `expected_disposition` and `expected_iocs` (the exact
normalized indicator set embedded in the payload, tracked by the generator as
it composes the text). The extractor is implemented independently and
unit-tested on hand-written strings, so IoC F1 measures the extractor — not
the generator's bookkeeping.

Ambiguous records are labeled `needs_human`: a correct system escalates them;
closing one as benign counts against benign-closure precision, and calling
one malicious counts against exact-match accuracy (reported, not gated).
