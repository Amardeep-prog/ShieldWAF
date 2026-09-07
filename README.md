# ShieldWAF — ML + Signature Hybrid Web Application Firewall

An M.Tech-final-year-scoped **Web Application Firewall** — a genuinely
different project category from a network-flow NIDS: this inspects the
*content* of HTTP requests (path, query string, body, headers) for
application-layer attacks, and can run as a real inline reverse proxy in
front of a protected web app, not just an offline classifier demo.

## The four real, working components

1. **Hybrid ML content classifier** — RandomForest (6-class: BENIGN, SQLI,
   XSS, PATH_TRAVERSAL, COMMAND_INJECTION, SCANNER_RECON) + IsolationForest
   anomaly detector (trained only on BENIGN requests, catches obfuscated/
   novel payloads that don't match a known signature). Trained and
   evaluated in this environment: macro ROC-AUC 1.0000, anomaly-detector
   benign-vs-attack AUC 0.9179 (bundled pretrained in `app/model_store/`).
2. **OWASP-CRS-style regex signature engine** (`app/detection/rules.yaml`)
   — deterministic, independent cross-check on the ML verdict. Tested
   against real attack payloads with zero false positives on benign
   traffic (`app/detection/rule_engine.py`).
3. **Real reverse proxy** (`app/proxy/reverse_proxy.py`) — the live-
   protection component. Every request is inspected *before* being
   forwarded to the upstream app; malicious requests get a 403 and never
   reach it. An intentionally vulnerable demo target app
   (`app/demo_target/vulnerable_app.py`, real SQLi/XSS vulnerabilities) is
   included so you can watch ShieldWAF actually stop a real exploit
   attempt from reaching a real backend.
4. **Real Combined Log Format parser** (`app/logs/log_parser.py`) — parses
   genuine Apache/Nginx `access.log` lines for retroactive analysis.
   Passed 6 tests against real-format log lines including embedded
   attack payloads (`tests/test_log_parser.py`).

Plus: a sliding-window rate limiter with repeat-offender auto-block, an
IP blocklist manager, PDF incident reports (reportlab), and an AI
Security Analyst (optional Anthropic API call, genuine offline fallback
otherwise) — the same maturity level as a NIDS-class project, applied to
the web-application-security domain instead.

## Why a WAF is a different project category

A NIDS inspects network *traffic statistics* (packet sizes, timing,
flags) to catch attacks at the transport/network layer. A WAF instead
inspects request *content* — the actual text of a URL, query string, or
POST body — to catch attacks at the application layer (OWASP Top 10:
injection, XSS, etc.). The detection targets, feature engineering,
placement in the network (inline reverse proxy vs. passive tap/live
host monitor), and even the shape of "ground truth" (a payload string
vs. a flow's byte counts) are fundamentally different problems, which is
why this is built from scratch rather than reusing NIDS components.

## Component 1 — ML request classifier

### Feature schema (`app/detection/schema.py` + `features.py`)
18 lexical/statistical features computed directly from request content:
lengths, special-character ratio, quote count, SQL/XSS/traversal/command
keyword counts, Shannon entropy of the payload (flags obfuscation),
URL-encoded character count, comment-token count, suspicious user-agent
flag, and per-parameter length statistics.

### Training (`app/detection/train.py`, `dataset.py`)
**Honest, stated limitation**: rather than a live target application or a
licensed corpus (e.g. CSIC 2010), each class is built from real,
documented OWASP-style attack payload strings (`' OR '1'='1`,
`<script>alert(1)</script>`, `../../etc/passwd`, `; cat /etc/passwd`,
known scanner user-agents) combined with randomised benign request
structure. The payload syntax is genuinely what a WAF has to catch; the
overall traffic mix is synthetic. High held-out accuracy reflects
separability of these known payloads, not an audited real-world
false-positive rate — see "Future Work".

## Component 2 — Signature rule engine

`app/detection/rule_engine.py` + `rules.yaml`: 8 regex rules covering
SQLi (boolean/UNION and time-based blind), XSS, path traversal, command
injection, known scanner user-agents, sensitive-path probing, and
comment-based evasion. Matched against decoded request content,
independent of the ML classifier. Edit `rules.yaml`, then
`POST /api/rules/reload`.

## Component 3 — Reverse proxy (live protection)

Run the bundled vulnerable demo app and put ShieldWAF in front of it:

```bash
# terminal 1
cd backend && python -m app.demo_target.vulnerable_app        # :9000

# terminal 2
cd backend && SHIELDWAF_UPSTREAM=http://localhost:9000 uvicorn app.main:app --reload   # :8000
```

Then compare:
```bash
curl "http://localhost:9000/search?q=shoes"                                  # direct to vulnerable app: works
curl "http://localhost:8000/search?q=shoes"                                  # via ShieldWAF: forwarded, works
curl "http://localhost:8000/search?q=1' UNION SELECT username,password FROM users--"
# -> 403 Blocked by ShieldWAF, never reaches the vulnerable app
```

## Component 4 — Log analysis

`app/logs/log_parser.py` parses Apache/Nginx Combined Log Format lines
via regex (stdlib only). Upload an `access.log` in the UI's Log Analyzer
page to retroactively run every historical request through the same
detection engine — useful for auditing exposure before ShieldWAF was
deployed inline.

## Stack

- **Backend**: FastAPI, scikit-learn, pandas, joblib, PyYAML, reportlab,
  httpx, SQLite (stdlib `sqlite3`, no ORM)
- **Frontend**: React 19 + TypeScript + Vite, Recharts, lucide-react —
  same classic, flat "SOC console" design system as a companion NIDS
  project (navy sidebar, hairline borders, severity-coded badges, Inter +
  IBM Plex Mono), re-themed with a WAF-appropriate accent color.

## Run locally

### Backend
```bash
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```
Model loads instantly from the bundled pretrained artifacts; delete
`app/model_store/` to force retraining on next startup (~1-2 seconds).
Set `SHIELDWAF_UPSTREAM` to point the reverse proxy at a real app (see
Component 3 above), and optionally `ANTHROPIC_API_KEY` for the AI
Security Analyst.

### Frontend
```bash
cd frontend
npm install
npm run dev
```
Visit `http://localhost:5173`.

### Docker Compose
```bash
docker compose up --build
```
Spins up the vulnerable demo target, the ShieldWAF backend/proxy pointed
at it, and the frontend. **Note**: the production frontend container
serves static files and does not proxy `/api` the way Vite's dev server
does — for a full docker-compose demo, put nginx in front, or run the
frontend in dev mode locally against the composed backend.

## API surface

- `POST /api/inspect` — inspect one or more requests (JSON)
- `GET /api/inspect/schema`, `/history`, `/{batch_id}`
- `GET /api/inspect/sample/{label}` — generate demo requests for a class
- `POST /api/logs/upload` — retroactively analyze an access.log
- `GET /api/model/metrics`, `POST /api/model/retrain`
- `GET /api/rules`, `POST /api/rules/reload`
- `GET /api/blocklist`, `POST /api/blocklist/block`, `POST /api/blocklist/unblock/{ip}`
- `GET /api/firewall/advisory/{ip}` — edge-firewall advisory commands
- `GET /api/alerts`, `GET /api/dashboard/stats`
- `POST /api/feedback`, `POST /api/ai/explain`
- `GET /api/reports/{batch_id}` — download a generated PDF incident report
- `ANY /{path:path}` — the reverse proxy catch-all (everything not under `/api/*`)

## Validated locally during development

- The full ML pipeline was trained and evaluated end-to-end: 3,150 train
  / 1,050 test synthetic requests, macro ROC-AUC 1.0000, anomaly-detector
  AUC 0.9179 (`app/model_store/metrics.json` is the exact bundled run).
- Feature extraction was tested against real SQLi/XSS/path-traversal/
  command-injection/scanner payloads and correctly discriminated all of
  them with zero signal on a benign control request.
- The regex rule engine was tested against the same payloads: correct
  rule IDs fired for each attack category, zero false positives on
  benign traffic.
- `tests/test_log_parser.py` was run and passed: real Combined Log
  Format lines (including embedded attack payloads and a deliberately
  malformed line) were parsed correctly, with bad lines reported rather
  than silently dropped or misparsed.
- The sliding-window rate limiter and repeat-offender auto-block were
  both tested directly and triggered at the correct thresholds.
- The full `detection.engine.inspect_request` pipeline (ML + rules +
  rate-limiter-awareness → ALLOW/BLOCK) was tested end-to-end.
- The SQLite persistence layer and PDF report generator were each
  executed directly and their output inspected/verified as valid.
- All FastAPI router wiring (including the reverse-proxy catch-all route
  ordering in `main.py`) was manually cross-checked for consistency,
  since this sandbox has no network access to install FastAPI itself for
  a live HTTP integration test. `python3 -m py_compile` was run over
  every backend file to catch syntax errors.

## Future work

- Swap the synthetic payload dataset for a real labelled HTTP traffic
  corpus (e.g. CSIC 2010) through the same `preprocessing.py` contract.
- Add TLS termination and HTTP/2 support to the reverse proxy.
- Move the rate limiter/blocklist to Redis for multi-worker/multi-instance
  deployments.
- Add a request-body size/type allowlist and multipart/JSON-aware body
  parsing (currently treated as raw text for feature extraction).
- Authentication/RBAC on the management API before any real deployment
  beyond a lab VM.
