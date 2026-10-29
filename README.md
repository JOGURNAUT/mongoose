[![CI](https://github.com/JOGURNAUT/mongoose/actions/workflows/ci.yml/badge.svg)](https://github.com/JOGURNAUT/mongoose/actions/workflows/ci.yml)

# Mongoose

A SOAR-lite alert triage service: ingest a security alert (a suspicious IP,
a file hash, a login event), enrich it against threat-intel sources, classify
its severity with deterministic rules, and return a playbook of suggested
response actions. Pairs with [Meerkat](https://github.com/JOGURNAUT/meerkat),
which applies the same evidence-based, deterministic-classification
philosophy to log-based intrusion detection instead of live alert enrichment.

## Why it's built this way

**Classification is deterministic, not an LLM call.** Severity needs to be
the same every time for the same input, and auditable: every verdict carries
a `reasons` list of plain evidence (the actual score, the actual ratio, the
actual rule that fired), not a generated explanation. This mirrors a design
used elsewhere (OZi's release-sentinel): the model, if there is one, stays
advisory; a deterministic stage makes the call.

**It fails closed.** When enrichment can't produce a real verdict, either
because a lookup errored or because an indicator has never been seen by any
scan engine before, the alert is classified `UNKNOWN`, not `LOW`. The
playbook for `UNKNOWN` explicitly escalates to manual review and says not to
auto-clear. A tool that quietly reads "no data" as "safe" is worse than
useless in this domain, since every wrong-direction failure mode fails
toward silence rather than toward attention.

## Running it

```bash
python -m venv .venv
.venv\Scripts\activate              # Windows
pip install -r requirements.txt

cp .env.example .env                # optional: leave the two API keys blank to run in MOCK mode
uvicorn app.main:app --reload
```

With no `ABUSEIPDB_API_KEY` / `VIRUSTOTAL_API_KEY` set, Mongoose runs in
**MOCK mode**: enrichment is a deterministic function of the indicator
itself (same IP or hash always gets the same mock verdict, across runs),
so the whole pipeline can be built, demoed, and tested without live keys
or rate limits. Set both real keys in `.env` to query AbuseIPDB and
VirusTotal live instead.

### Try it

```bash
# brute-force login
curl -X POST localhost:8000/alerts -H "Content-Type: application/json" \
  -d '{"type":"login","user":"r.srivastava","failed_attempts_last_5min":9}'

# impossible travel
curl -X POST localhost:8000/alerts -H "Content-Type: application/json" \
  -d '{"type":"login","user":"r.srivastava","country":"RU","last_known_country":"IN","minutes_since_last_login":8}'

# IP reputation (mock or live, depending on .env)
curl -X POST localhost:8000/alerts -H "Content-Type: application/json" \
  -d '{"type":"ip_traffic","source_ip":"203.0.113.5"}'

# file hash reputation
curl -X POST localhost:8000/alerts -H "Content-Type: application/json" \
  -d '{"type":"file_hash","file_hash":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}'

curl localhost:8000/alerts          # list everything ingested so far
```

A real run against the mock backend (see [Why it's built this way](#why-its-built-this-way)) returning the fail-closed path:

```json
{
  "severity": "UNKNOWN",
  "reasons": ["file hash not seen by any scan engine yet (0/0) — insufficient evidence either way"],
  "actions": [
    "FAIL CLOSED: evidence was insufficient to score this alert automatically",
    "Route to manual analyst review before closing",
    "Do not auto-clear — treat as at least MEDIUM until a human confirms otherwise"
  ]
}
```

## Severity distribution on a real-scale batch, not just one example

A single curl example proves the pipeline runs; it doesn't prove the
thresholds produce a sane spread instead of collapsing everything into
one bucket. `scripts/eval_distribution.py` runs classification over
2,000 mock-enriched indicators each and reports the breakdown:

```bash
PYTHONPATH=. python scripts/eval_distribution.py
```

```
IP classification over 2000 mock indicators:
  HIGH       512  (25.6%)
  MEDIUM     982  (49.1%)
  LOW        506  (25.3%)
  UNKNOWN      0  (0.0%)

File-hash classification over 2000 mock indicators:
  HIGH      1239  (62.0%)
  MEDIUM     425  (21.2%)
  LOW         93  (4.7%)
  UNKNOWN    243  (12.2%)
```

IP severity never lands `UNKNOWN` because the mock always returns a real
confidence score (0-100); file-hash severity does, by design — about 1
in 8 mock hashes simulate a file no scan engine has seen before, which
is exactly the fail-closed path this tool exists to handle correctly.

## Tests

```bash
pip install -r requirements-dev.txt
pytest -q
```

22 tests, no network calls, no API keys required. They cover: every
severity boundary for IP and file-hash classification, the brute-force and
impossible-travel login rules, that an enrichment *failure* is scored
`UNKNOWN` and never silently downgraded to `LOW`, that the mock enrichment
is deterministic (same input, same output, across calls), that the
"never seen" (0/0) bucket is actually reachable through the live API path
and not just through a direct unit-test call, and the full HTTP surface
(ingest, list, get-by-id, 404, required-field validation).

## Architecture

```
app/
  main.py        FastAPI routes: POST /alerts, GET /alerts, GET /alerts/{id}, GET /health
  models.py      Pydantic request/response models + the SQLModel table
  enrichment.py  AbuseIPDB (IP) and VirusTotal (file hash) lookups, with a mock mode
  classify.py    Deterministic severity rules over enrichment + alert context
  playbook.py    Severity -> suggested actions, with the fail-closed UNKNOWN path
  storage.py     SQLite persistence (SQLModel/SQLAlchemy)
  config.py      Env-driven config; MOCK_MODE is derived, not set directly
tests/
  test_classify.py          severity boundaries, enrichment-failure handling
  test_playbook.py          action mapping, fail-closed behaviour
  test_enrichment_mock.py   mock determinism, the never-seen bucket is reachable
  test_api.py               full HTTP surface, end to end
```

## What this doesn't do yet

- Only two enrichment sources (AbuseIPDB, VirusTotal). A real SOC tool would
  correlate across several and handle disagreement between them.
- No deduplication: the same IP reported twice creates two alert rows, not
  one alert with an updated report count.
- No authentication on the API itself — fine for a local demo, not for
  anything that would actually receive alerts from a detection system.
- Alert ingestion is synchronous per-request; a real pipeline would queue
  alerts and enrich asynchronously so a slow upstream API can't block intake.
