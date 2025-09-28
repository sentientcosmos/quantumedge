\# QubitGrid™ | Prompt Injection Scanner



This is part of the \*\*QubitGrid™ platform\*\*, a suite of pre-audit readiness tools for AI, blockchain, and advanced technologies.



\## Important Note

QubitGrid™ provides automated \*\*pre-audit readiness tools\*\* and continuous monitoring insights.

Reports are designed to support internal teams and prepare organizations for compliance and certification processes.

\*\*QubitGrid™ does not issue certifications — it equips you to pass them.\*\*



---



\## Update — 2025-Sep-09

\- Added docs for POST `/report` (API-key gated) and POST `/feedback` (label capture to datasets/scanner.jsonl).

\- Confirmed `/scan` remains public (no key).

\- Data files are \*\*not\*\* committed (see `.gitignore`).



\### Endpoints

\*\*GET\*\* `/scan?text=...`  

\*\*POST\*\* `/report`  (Header: `X-API-Key` when `API\_KEY` env var is set)  

\*\*POST\*\* `/feedback` (Header: `X-API-Key`; body: `{"text":"...","label":"safe|unsafe","reason":"optional"}`)

## cURL examples 
### Environment
- `API_KEY` — if set, required as `X-API-Key` on POST /report and POST /feedback
- `SLACK_WEBHOOK` — optional Slack Incoming Webhook URL for alerts
- `SLACK_THRESHOLD` — optional; one of `low|medium|high` (default `high`)

### Quickstart (local)
```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
export API_KEY="dev-key-123"                         # optional for local
uvicorn app:app --reload --port 8000



\*\*Data (local only):\*\* `datasets/scanner.jsonl`  

\*\*Disclaimer:\*\* QubitGrid™ provides pre-audit readiness tools only; not a certified audit.

## Update — 2025-Sep-10
MVP1 live on Render at https://quantumedge-scanner.onrender.com
Endpoints: /scan, /report, /feedback



