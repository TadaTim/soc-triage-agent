# Autonomous SOC Triage & Investigation Agent

A production-shaped security-operations triage system: a **deterministic
enrichment pipeline** closes the overwhelming majority of alerts with no LLM
involvement; a **bounded LLM investigation agent** handles only escalations;
and **containment can never be executed by the system** — it exists solely
as human-decided approval requests.

Built stage by stage from the design in `ai-portfolio-projects-muse.md`
(Project 1), with the golden eval dataset created at the *data* stage —
before the scoring rules it now judges.

## Architecture

```
                 ┌──────────────┐   dedup    ┌────────────────┐
 raw alerts ───► │ ingest       ├──────────► │ enrich         │ deterministic:
 (webhook/Kafka) │ (apps/       │  collapse  │ (packages/     │ IoC extraction,
                 │  consumers)  │  storms    │  enrich)       │ intel, scoring
                 └──────────────┘            └───────┬────────┘
                                                     │ verdict or escalate
                                          ┌──────────▼─────────┐
                                          │ investigate        │ ≤3 tool calls,
                                          │ (packages/         │ 1 generation,
                                          │  investigate)      │ schema-validated
                                          └──────────┬─────────┘
                                                     │ may recommend
                                          ┌──────────▼─────────┐
                                          │ ApprovalRequest    │ human decides.
                                          │ (never executed    │ There is no
                                          │  by this system)   │ execute path.
                                          └────────────────────┘
```

- **apps/api** — FastAPI: alert intake, verdict lineage queries, approval console, `/metrics`.
- **apps/consumers** — pipeline services (ingest → dedup → enrich → investigate) with retry/DLQ policy, storm-mode shedding, and verdict re-opening on late events; `kafka_runner.py` is the thin Kafka transport shell.
- **packages/schemas** — Pydantic v2 contracts, Kafka topics-as-code, Alembic migrations (expand/contract).
- **packages/enrich** — IoC extraction (defang-aware, offset-exact), threat-intel/asset/allowlist lookups, legible signal scoring.
- **packages/investigate** — LLM gateway (timeout, circuit breaker, cost log), bounded agent, report-vs-enrichment validation.
- **packages/evals** — the 500-alert golden dataset, its generator, DATA.md provenance, and the scoring harness.
- **packages/observability** — JSON logging (payloads by hash only), Prometheus metrics, OpenTelemetry tracing with Kafka header propagation.

## Key invariants (enforced by tests, not conventions)

1. **An InvestigationReport cannot cite an invented IoC** — every cited value must resolve to an enrichment record or the report is discarded and the alert goes to a human. (`tests/contract`, `tests/unit/test_investigate.py`)
2. **No API shape executes containment.** Routes can create and decide `ApprovalRequest`s only; a contract test sweeps the live route table. Containment at *any* confidence requires a human approval record.
3. **≥95% of alerts resolve deterministically.** The eval harness gates on it, because the $0.015/alert blended cost target is impossible otherwise.
4. **Verdicts are append-only.** A late event re-opens a verdict as a new record with `supersedes_id` — history is never silently rewritten.
5. **Poison messages never crash-loop a partition** — parse failures go straight to the dead-letter store; transient failures get 5 attempts with exponential backoff + full jitter, then the DLQ with full error history.
6. **Triage never blocks on the model.** Provider outage/timeout/open breaker → enrichment-only `needs_human` verdicts while deterministic triage continues (verified: see below).

## Eval scorecard (golden dataset, 500 alerts)

```
alerts scored:                500
benign-closure precision:     1.0000  [PASS] gate >= 0.99
malicious recall:             1.0000  [PASS] gate >= 0.95
IoC extraction F1:            1.0000  [PASS] gate >= 0.95 (P 1.000 / R 1.000)
deterministic resolution:     0.9560  [PASS] gate >= 0.95 (escalation 0.0440)
blended cost per alert:       $0.00015  [PASS] gate <= $0.015
exact-match accuracy:         1.0000  (reported)
```

Dataset: 315 benign / 165 malicious / 20 needs-human, including **70
adversarial cases** (benign-looking attacks whose only tell is an intel hit;
scary-looking benign noise: documentation-range "indicators" in a threat
digest, an authorized pentest inside its engagement window, a ransomware
scare pop-up). Two real C2 alerts escalate rather than auto-close because
they land on the pentest host inside its window — the system escalates
exactly where a good analyst would hesitate. Provenance and labeling rules:
`packages/evals/DATA.md`.

## Running it

```bash
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"

make lint typecheck     # ruff + mypy strict
make test               # unit + contract tiers (76 tests)
make coverage-enrich    # packages.enrich coverage gate (>=95%; currently 97%)
make eval               # golden-dataset scorecard; exits non-zero on a gate miss
make schemas            # committed JSON-schema drift check
.venv/bin/python tools/check_migrations.py        # expand/contract discipline
.venv/bin/python -m packages.evals.generate       # regenerate the dataset (deterministic)

# API demo (in-process store; FakeProvider — no API keys needed):
.venv/bin/uvicorn apps.api.main:app --port 8000
curl -X POST localhost:8000/v1/alerts -H 'content-type: application/json' -d '{...Alert...}'
```

Full deployment (`docker compose up`): Redpanda + Postgres + Redis +
Tempo/Grafana, topics provisioned from `packages/schemas/topics.py`.

## Verification status

**Verified by execution in this environment** (Python 3.12, no Docker):

- All 8 build stages: ruff clean, **mypy strict clean** (34 files), 76 tests passing.
- Eval harness: all gates pass (scorecard above), reproduced across runs.
- Migrations: Alembic chain renders upgrade + downgrade SQL offline; expand/contract guard passes; the same-migration add+NOT-NULL and unreviewed-DROP cases are unit-tested failures.
- Design Verification Gate: 50× duplicate burst → exactly 1 investigation (test); no containment-execution route (contract test over the live route table); eval gates (above); LLM-provider-disabled run → deterministic verdicts still issued, escalations degrade to `needs_human` (script-verified).
- CI workflows validated with `actionlint`; schema-drift and dataset-changelog guards tested in both directions.

**Written in full, but NOT executed here** (requires Docker / a broker / API keys):

- `tests/integration/` — Testcontainers Kafka + Postgres tests (full path over the wire; Alembic upgrade against real Postgres). They skip cleanly without Docker; the identical pipeline semantics are covered in-process by the unit tier.
- `apps/consumers/kafka_runner.py` — the Kafka transport (lazy `kafka-python` import); services it drives are fully tested in-process.
- `docker-compose.yml` / Dockerfiles / release workflow — YAML- and actionlint-validated, not run (no Docker in this environment).
- Real LLM providers — the gateway's provider protocol is implemented by the deterministic `FakeProvider` (used by tests/evals/local dev, clearly labeled); a production provider slots into the same protocol and is held to the same `InvestigationReport` validation.

## Deliberate design decisions worth arguing with

- **The scoring model is a legible weighted sum**, not a learned model: an analyst must be able to replay any verdict signal-by-signal. The eval numbers say the legibility costs nothing on this dataset.
- **Medium-confidence intel (0.5–0.85) scores +40 but cannot hard-close** an alert as malicious — only ≥0.85 confidence is decisive alone.
- **Escalation is a success state**, not a failure: the deterministic layer is allowed to say "I don't know" (4.4% of the golden set) and is never allowed to guess benign.
- **The pentest calendar is ground truth**: identical tooling is benign inside an authorized window and an incident outside it; context, not content, decides.
