"""
QubitGrid™ Prompt Injection Scanner (MVP1)

What this app does:
  1) GET  /scan      → quick scan of a single text (via query string)
  2) POST /report    → batch scan (JSON body), optional API-key gate
  3) POST /feedback  → save human labels to a local JSONL dataset
  4) GET  /          → tiny HTML page so humans can try it
  5) GET  /__version → quick version string (for deploy checks)
  6) GET  /__rules   → shows rule count + sample regex patterns

Key terms:
- "payload": the JSON body you POST to an endpoint.
- "flags":   which rules matched in the text (short tags + regex).
- "severity": low/medium/high based on the worst matching rule.
"""

# -------------------------
# Imports & basic plumbing
# -------------------------
from fastapi import FastAPI, Query, Header, HTTPException         # web app + query/header parsing
from fastapi.responses import JSONResponse, HTMLResponse, PlainTextResponse
from pydantic import BaseModel, Field                              # validated request/response models
from typing import List, Optional, Dict, Any, Tuple                # type hints to keep things clear
from datetime import datetime                                      # timestamps for logs/dataset
import os, json, pathlib, re                                       # env vars, file I/O, regex patterns
from fastapi import __version__ as fastapi_version                 # for /__version

# -------------------------
# App instance + branding
# -------------------------
app = FastAPI(title="QubitGrid Prompt Injection Scanner")

# Clear, consistent legal posture (advisory utilities, not certification)
DISCLAIMER = "QubitGrid™ provides pre-audit readiness tools only; not a certified audit."

# -------------------------
# Rule engine (regex-based)
# -------------------------
# Each tuple: (regex_pattern, severity, tag_for_reporting)
_RULES: List[Tuple[str, str, str]] = [
    (r"\bignore (?:all|previous) instructions\b",    "medium", "ignore_instructions"),
    (r"\bdisregard (?:all|previous) instructions\b", "medium", "disregard_instructions"),
    (r"\breveal (?:the )?system prompt\b",           "high",   "reveal_system_prompt"),
    (r"\bact as (?:dan|developer mode)\b",           "medium", "act_as_dan"),
    (r"\bjailbreak\b",                               "medium", "jailbreak"),
    (r"\bsudo\b",                                    "medium", "sudo"),
    (r"\bexfiltrat(?:e|ion)\b",                      "high",   "exfiltrate"),
    (r"\bchmod\s+\+x\b",                             "medium", "chmod_exec"),
    (r"\brm\s+-rf\b",                                "high",   "rm_rf"),
    (r"\bcurl\s+https?://|\bwget\s+https?://",       "medium", "remote_fetch"),
    (r"\bbase64\b",                                  "low",    "base64"),
]

# Precompile once (faster than compiling on every request)
_COMPILED: List[Tuple[re.Pattern, str, str]] = [
    (re.compile(pat, re.IGNORECASE), sev, tag) for (pat, sev, tag) in _RULES
]

# Severity ladder: worst match "wins"
_SEV_ORDER = {"low": 0, "medium": 1, "high": 2}
def _worst(a: str, b: str) -> str:
    """Pick the worse of two severities (high > medium > low)."""
    return a if _SEV_ORDER[a] >= _SEV_ORDER[b] else b

def scan_text_rules(text: str) -> Tuple[List[Dict[str, Any]], str]:
    """
    Run all compiled rules against the text.

    Returns:
      flags:    list of dicts like {"tag": "ignore_instructions", "regex": "<pattern>"}
      severity: "low" | "medium" | "high" (worst rule that matched)
    """
    t = text or ""
    flags: List[Dict[str, Any]] = []
    severity = "low"
    for rx, sev, tag in _COMPILED:
        if rx.search(t):
            flags.append({"tag": tag, "regex": rx.pattern})
            severity = _worst(severity, sev)
    return flags, severity

# -------------------------
# Tiny analytics helper
# -------------------------
def log_event(event_name: str, props: Dict[str, Any]) -> None:
    """Print-only analytics so you can see usage in Render logs."""
    ts = datetime.utcnow().isoformat() + "Z"
    print(f"[analytics] {{'ts':'{ts}','event':'{event_name}','props':{props}}}")

# -------------------------
# GET /scan  (single text)
# -------------------------
@app.get("/scan")
def scan(text: str = Query(..., description="Text to scan for prompt injection")) -> JSONResponse:
    """
    Quick single-text check from a GET query param.
    Example: /scan?text=Ignore%20previous%20instructions
    """
    flags, severity = scan_text_rules(text)
    result = {
        "flagged": bool(flags),
        "severity": severity,
        "flags": flags,
        "disclaimer": DISCLAIMER,
    }
    return JSONResponse(result)

# -------------------------------------------------
# POST /report (batch texts; optional API key gate)
# -------------------------------------------------
# "payload" here just means the JSON body you POST to /report.

class BatchReportInput(BaseModel):
    """Request body for batch scans."""
    texts: List[str] = Field(..., description="Batch of texts to scan")

class BatchReportItem(BaseModel):
    """Per-text result returned by /report."""
    index: int
    flags: List[Dict[str, Any]]
    severity: str  # "low" | "medium" | "high"

class BatchReportOut(BaseModel):
    """Full /report response."""
    items: List[BatchReportItem]
    summary: Dict[str, int]   # {"low": n, "medium": n, "high": n}
    disclaimer: str

def _check_api_key(provided_key: Optional[str]) -> None:
    """
    Simple paywall/abuse gate:
      - Set env var API_KEY="your_secret"
      - Clients must send header: X-API-Key: your_secret
      - If API_KEY is NOT set, endpoint is open (handy for local dev)
    """
    expected = os.getenv("API_KEY")
    if expected and provided_key != expected:
        raise HTTPException(status_code=403, detail="Forbidden. Valid API key required.")

@app.post("/report", response_model=BatchReportOut)
def report(payload: BatchReportInput, x_api_key: Optional[str] = Header(None)) -> Dict[str, Any]:
    """
    Batch scan using the SAME rule engine as /scan (consistent behavior).
    """
    _check_api_key(x_api_key)  # only blocks if API_KEY is set and doesn’t match

    items: List[BatchReportItem] = []
    counts = {"low": 0, "medium": 0, "high": 0}

    for i, t in enumerate(payload.texts):
        flags, severity = scan_text_rules(t)  # unified scanner
        items.append(BatchReportItem(index=i, flags=flags, severity=severity))
        counts[severity] += 1

    try:
        log_event("batch_scan_performed", {"batch_size": len(payload.texts)})
    except Exception:
        pass  # logging should never break requests

    return {"items": items, "summary": counts, "disclaimer": DISCLAIMER}

# ---------------------------------------------
# POST /feedback (label to dataset, JSON Lines)
# ---------------------------------------------
# This builds your future training set (one JSON object per line).

DATASETS_DIR = pathlib.Path(__file__).parent / "datasets"
DATASETS_DIR.mkdir(exist_ok=True)

class FeedbackInput(BaseModel):
    """Request body to record a label for a text."""
    text: str
    label: str                      # "safe" or "unsafe"
    reason: Optional[str] = None    # optional note

@app.post("/feedback")
def feedback(item: FeedbackInput, x_api_key: Optional[str] = Header(None)) -> Dict[str, Any]:
    """
    Save a labeled example to datasets/scanner.jsonl.
    On Render free tier, the filesystem is ephemeral (fine for a demo).
    For persistence later, we’ll wire SQLite/Postgres.
    """
    _check_api_key(x_api_key)
    if item.label not in ("safe", "unsafe"):
        raise HTTPException(status_code=400, detail="label must be 'safe' or 'unsafe'")

    record = {
        "ts": datetime.utcnow().isoformat() + "Z",
        "text": item.text,
        "label": item.label,
        "reason": item.reason,
        "source": "feedback",
    }

    with open(DATASETS_DIR / "scanner.jsonl", "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")

    try:
        log_event("feedback_saved", {"label": item.label})
    except Exception:
        pass

    return {"ok": True, "disclaimer": DISCLAIMER}

# -------------------------
# GET /  (tiny demo page)
# -------------------------
@app.get("/", response_class=HTMLResponse)
def home() -> str:
    """
    Minimal HTML so humans can try the scanner without Postman/curl.
    """
    return """
    <html>
      <head>
        <title>QubitGrid Prompt Scanner</title>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <style>
          body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;max-width:720px;margin:2rem auto;line-height:1.5}
          textarea{width:100%;padding:8px}
          .btn{padding:10px 16px;border:0;border-radius:8px;background:#111;color:#fff;cursor:pointer}
          .muted{color:#666}
          .cta{background:#635bff}
        </style>
      </head>
      <body>
        <h2>QubitGrid: Prompt Injection Scanner</h2>

        <form action="/scan" method="get" style="margin: 1rem 0;">
          <textarea name="text" rows="8" placeholder="Paste a prompt to scan..."></textarea>
          <div style="margin-top:0.5rem;">
            <button class="btn" type="submit">Scan</button>
          </div>
        </form>

        <p class="muted">Advisory utilities for pre-audit readiness. Not a certification.</p>

        <p style="margin-top:1.25rem;">
          <a href="https://buy.stripe.com/test_YOUR_LINK" target="_blank" class="btn cta" style="text-decoration:none;display:inline-block">
            Buy Early Access (Test)
          </a>
        </p>
      </body>
    </html>
    """

# --- Diagnostics: quick version + rule list ---
APP_VERSION = "scanner-v0.2.0"  # bump whenever you deploy

@app.get("/__version", response_class=PlainTextResponse)
def version():
    """Used to verify a new deploy is live."""
    return f"{APP_VERSION} | FastAPI {fastapi_version}"

@app.get("/__rules")
def rules():
    """Surface rule count + a few examples for quick inspection."""
    return {
        "count": len(_COMPILED),
        "examples": [r[0].pattern for r in _COMPILED[:5]]
    }
