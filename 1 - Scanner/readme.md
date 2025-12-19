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

#==============10/05/2025===============#
## Pricing model & UI (vision)

- The backend loads the authoritative tier model from `PRICING_MODEL_CONTEXT.json` at startup.
- `GET /pricing` returns the model plus the resolved Free daily limit (env `FREE_DAILY_LIMIT` overrides).
- `roadmap.html` fetches `/pricing` and decorates tier badges with **daily scan limits** (e.g., Free 15/day, Pro 5000/day).
- Enterprise/Team display “custom”.
- Disclaimer: “QubitGrid™ provides pre-audit readiness tools only; not a certified audit.”

### Usage (local)
1. Start: `uvicorn app:app --reload --port 8000`
2. Open: `http://127.0.0.1:8000/roadmap` (don’t use `file://`).
3. Inspect JSON: `http://127.0.0.1:8000/pricing`

### Notes
- UI reads the model; no hard-coded numbers in HTML.
- Compatible with future Stripe/Gumroad mapping.

#==============10/05/2025===============#

<!-- 2025-10-06: START ROADMAP + PRICING INTEGRATION UPDATE -->

### QubitGrid™ Roadmap UI Refresh — October 6 2025
This update introduces the new roadmap interface and ties it directly to live `/pricing` data.

**What’s new**
- Fully responsive 3-phase roadmap (plus hidden Phase 4 backlog)
- Dynamic plan limits pulled from `/pricing`
- Accessibility/ARIA improvements
- Cleaner typography and spacing (CSS Grid layout)
- Unified call-to-action structure across all cards
- Footer updated with `hello@qubitgrid.ai` contact
- Added future stub for Phase 4 (Automation & Marketplace)
- Synced version comments for audit traceability

**Test checklist**
1. Run server: `uvicorn app:app --reload --port 8000`
2. Visit: `http://127.0.0.1:8000/roadmap`
3. Confirm pricing chips populate from `/pricing`
4. Verify no console errors (CORS, JS, etc.)
5. Check responsive layout on desktop and mobile

<!-- 2025-10-06: END ROADMAP + PRICING INTEGRATION UPDATE -->


\*\*Data (local only):\*\* `datasets/scanner.jsonl`  

\*\*Disclaimer:\*\* QubitGrid™ provides pre-audit readiness tools only; not a certified audit.

## Update — 2025-Sep-10
MVP1 live at https://qubitgrid.ai
Endpoints: /scan, /report, /feedback



