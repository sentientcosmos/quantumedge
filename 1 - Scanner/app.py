"""
app.py — QubitGrid™ Prompt Injection Scanner (MVP1)
Ultra-annotated: every section explains what it does and why.

Paste this whole file over your existing app.py (backup your old app.py first).
"""

# ------------------------------
# Standard library imports
# ------------------------------
import os                 # read environment variables (API_KEY, SLACK_WEBHOOK)
import re                 # regular expressions => rule engine
import json               # json encoding (feedback file, slack payload)
import pathlib            # cross-platform paths for index.html and datasets
import urllib.request     # simple HTTP POST (used for Slack webhook)
from datetime import datetime
from typing import List, Optional, Dict, Any, Tuple

# ------------------------------
# FastAPI framework + helpers
# ------------------------------
from fastapi import FastAPI, Query, Header, HTTPException
from fastapi.responses import JSONResponse, HTMLResponse, PlainTextResponse
from pydantic import BaseModel, Field
from fastapi import __version__ as fastapi_version  # show FastAPI version in /__version

# ------------------------------
# App instance + global strings
# ------------------------------
app = FastAPI(title="QubitGrid Prompt Injection Scanner")

# Default product disclaimer (appears in every response/report).
DISCLAIMER = "QubitGrid™ provides pre-audit readiness tools only; not a certified audit."

# ------------------------------
# RULE CATALOG
# ------------------------------
# Each rule entry: (rule_id, category, severity, regex_pattern, why)
# - rule_id: stable short identifier used in the flags returned
# - category: human grouping (prompt_exfiltration, exec_risk, etc.)
# - severity: "low" | "medium" | "high"
# - regex_pattern: the pattern matched (we compile these below)
# - why: short explanation (for reports/UI)
#
# =======================
# Rule set (regex-based)
# =======================
# Each tuple: (regex_pattern, severity, tag, why)
# Notes:
# - We use raw strings r"..." so backslashes are not double-escaped in Python.
# - \b = word boundary. It does NOT match punctuation like "/" — that’s why we
#   explicitly allow an optional " /" after rm -rf below.
# - Order does not matter for matching; we compute “worst” severity at the end.

_RULES = [
    # Control override / jailbreak scaffolding
    (r"\b(?:ignore|disregard)\s+(?:all|any|previous|prior)\s+(?:rules|instructions)\b",
     "medium", "ignore_instructions", "User asks the model to ignore prior safety or task instructions."),
    (r"\b(?:reset|forget|clear)\s+(?:all|previous|prior)\s+(?:rules|instructions|constraints)\b",
     "medium", "reset_rules", "Attempts to reset safety rules or system constraints."),

    # Prompt exfiltration / chain-of-thought extraction
    (r"\b(?:reveal|show|print|display)\s+(?:the\s+)?(?:hidden\s+)?(?:system|developer)\s+prompt\b",
     "high",   "reveal_system_prompt", "Tries to extract hidden system/developer instructions."),
    (r"\b(?:show|reveal|explain)\s+(?:your\s+)?(?:chain[-\s]?of[-\s]?thought|hidden\s+notes)\b",
     "high",   "show_chain_of_thought", "Tries to extract hidden reasoning or internal notes."),

    # Role / power elevation
    (r"\bact\s+as\s+(?:dan|developer\s*mode|root|sysadmin)\b",
     "medium", "act_as_role_dan", "Asks the model to assume a powerful/unsafe role."),
    (r"\bdo\s+anything\s+now\b",
     "medium", "do_anything_now", "Classic DAN jailbreak bypass normal limitations."),

    # Exec risk (dangerous commands / payload fetch)
    # IMPORTANT FIX: allow optional space+slash after -rf to catch 'rm -rf /'
    (r"\brm\s+-rf(?:\s+/)?", 
     "high",   "shell_danger_rmrf", "Dangerous shell command that deletes files/directories."),
    (r"\bchmod\s+\+x\b",
     "medium", "shell_chmod_exec", "Enables execution permission; often part of exploit chains."),
    (r"\bpowershell\s+[-\w]*\s*-e[nc]ode[d]?\s+", 
     "high",   "powershell_encoded", "Base64-encoded PowerShell often used to hide payloads."),
    (r"\b(?:curl|wget)\s+https?://", 
     "medium", "remote_fetch", "Fetches remote content; can be used to pull payloads."),
    (r"\bbase64\b",              
     "low",    "base64_indicator", "Base64 often used to conceal data or instructions."),
    (r"\b0x[0-9a-fA-F]{8,}\b",   
     "low",    "hex_obfuscation", "Hex blobs can conceal data or instructions."),
# NEW: catch "rm -rf /" even when nothing follows the slash.
# - \brm\s*-\s*rf\s*/   → matches rm -rf /
# - \s*(?:[#;]|$)       → then either whitespace + a comment/chain symbol (# or ;)
#                         OR end-of-line, so we don't accidentally match paths.
{
    "id": "shell_danger_rmrf_root",
    "category": "exec_risk",
    "severity": "high",
    "pattern": r"\brm\s*-\s*rf\s*/\s*(?:[#;]|$)",
    "why": "Dangerous shell command attempting to delete the entire filesystem root (/)."
},


    # Policy bypass / safety filters
    (r"\b(?:bypass|ignore|evade)\s+(?:policy|policies|filters|guardrails|content\s*policy)\b",
     "medium", "bypass_safety", "Asks to bypass safety policies or guardrails."),
    (r"\bignore\s+policy\s+for\s+(?:research|testing)\b",
     "medium", "ignore_policy_research", "Tries to justify a bypass as 'research/testing'."),

    # Secret / key exfiltration
    (r"\b(?:api|secret|private)\s+keys?\b",
     "high",   "exfiltrate_keys", "Attempts to obtain API or private keys."),
    (r"\b(?:ENV|environment)\s+variables?\b",
     "medium", "env_vars", "Asks about environment variables where secrets may live."),
]


# ------------------------------
# Simple stdout analytics helper
# ------------------------------
def log_event(event_name: str, props: Dict[str, Any]) -> None:
    """
    Print a small JSON-ish line to stdout for visibility in logs.
    This keeps the MVP simple (no external analytics yet).
    """
    ts = datetime.utcnow().isoformat() + "Z"
    print(f"[analytics] {{'ts':'{ts}','event':'{event_name}','props':{props}}}")

# ------------------------------
# Helper: produce a short snippet around a match
# ------------------------------
def _snippet(text: str, start: int, end: int, pad: int = 40) -> str:
    """Return a short, single-line preview for UI and alerts."""
    s = max(0, start - pad)
    e = min(len(text), end + pad)
    return text[s:e].replace("\n", " ")

# ------------------------------
# Core engine: run all rules on text
# ------------------------------
def scan_text_rules(text: str) -> Tuple[List[Dict[str, Any]], str]:
    """
    Run the full rule catalog against `text`.
    Returns:
      flags: list of dictionaries with id, category, severity, why, snippet
      overall severity: worst match severity (low/medium/high)
    """
    if not text:
        return [], "low"

    flags: List[Dict[str, Any]] = []
    overall = "low"

    for rid, cat, sev, rx, why in _COMPILED:
        for m in rx.finditer(text):
            flags.append({
                "id": rid,
                "category": cat,
                "severity": sev,
                "why": why,
                "snippet": _snippet(text, m.start(), m.end()),
            })
            overall = _worst(overall, sev)

    return flags, overall

# ------------------------------
# Optional Slack alerting (best-effort)
# ------------------------------
SLACK_WEBHOOK = os.getenv("SLACK_WEBHOOK", "").strip()  # set in Render env vars if desired
ALERT_THRESHOLD = os.getenv("SLACK_THRESHOLD", "high").lower().strip()  # default to "high"

def _sev_rank(s: str) -> int:
    return _SEV_ORDER.get(s, 0)

def _should_alert(severity: str) -> bool:
    """Return True if severity meets configured threshold."""
    return _sev_rank(severity) >= _sev_rank(ALERT_THRESHOLD)

def send_slack_alert(text: str, severity: str, flags: List[dict], origin: str = "scan") -> None:
    """
    Post a shallow alert to Slack via incoming webhook.
    This is best-effort: failures are printed and do not break endpoints.
    """
    if not SLACK_WEBHOOK:
        return

    top_flags = ", ".join(sorted({f.get("id", "?") for f in flags})) or "none"
    preview = (text or "")[:300].replace("\n", " ")
    payload = {"text": f"QubitGrid alert ({origin}): severity={severity}, flags=[{top_flags}]\n→ preview: {preview}"}
    try:
        req = urllib.request.Request(
            SLACK_WEBHOOK,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=6) as resp:
            resp.read()
    except Exception as e:
        # Slack errors should not break normal operation
        print(f"[slack] failed to send alert: {e}")

# =============================================================================
# GET /scan — single-text scan (used by the demo UI)
# - Input: query param ?text=...
# - Output: JSON with flagged (bool), severity, flags[], disclaimer
# =============================================================================
@app.get("/scan")
def scan(text: str = Query(..., description="Text to scan for prompt injection")):
    flags, severity = scan_text_rules(text)

    # Try to alert Slack if severity meets threshold. Do not crash on failure.
    try:
        if flags and _should_alert(severity):
            send_slack_alert(text=text, severity=severity, flags=flags, origin="scan")
    except Exception:
        pass

    return JSONResponse({
        "flagged": len(flags) > 0,
        "severity": severity,
        "flags": flags,
        "disclaimer": DISCLAIMER,
    })


# =============================================================================
# Pydantic models for batch endpoint (/report)
# Note: these models must be defined before the @app.post decorator uses them.
# =============================================================================
class BatchReportInput(BaseModel):
    """Request body: { "texts": ["...", "..."] }"""
    texts: List[str] = Field(..., description="Batch of texts to scan")

class BatchReportItem(BaseModel):
    """One result entry for each text in the batch."""
    index: int
    flags: List[Dict[str, Any]]
    severity: str  # low|medium|high

class BatchReportOut(BaseModel):
    """Response for POST /report: items + summary + disclaimer."""
    items: List[BatchReportItem]
    summary: Dict[str, int]
    disclaimer: str

def _check_api_key(provided_key: Optional[str]) -> None:
    """
    If API_KEY env var exists, require X-API-Key header to match.
    - This provides a simple paywall/gate for the batch API and feedback.
    - If API_KEY is not set, the endpoints are open (convenient for local dev).
    """
    expected = os.getenv("API_KEY")
    if expected and provided_key != expected:
        raise HTTPException(status_code=403, detail="Forbidden. Valid API key required.")

# =============================================================================
# POST /report — batch scan (JSON body)
# - header X-API-Key required only if API_KEY env var is set
# - returns list of items, a summary counts by severity, and the disclaimer
# =============================================================================
@app.post("/report", response_model=BatchReportOut)
def report(payload: BatchReportInput, x_api_key: Optional[str] = Header(None)):
    _check_api_key(x_api_key)

    items: List[BatchReportItem] = []
    counts = {"low": 0, "medium": 0, "high": 0}

    for i, t in enumerate(payload.texts):
        flags, severity = scan_text_rules(t)
        items.append(BatchReportItem(index=i, flags=flags, severity=severity))
        counts[severity] += 1

        # Slack per-item alert (best-effort)
        try:
            if flags and _should_alert(severity):
                send_slack_alert(text=t, severity=severity, flags=flags, origin="report")
        except Exception:
            pass

    try:
        log_event("batch_scan_performed", {"batch_size": len(payload.texts)})
    except Exception:
        pass

    return {"items": items, "summary": counts, "disclaimer": DISCLAIMER}

# =============================================================================
# POST /feedback — append labeled examples to datasets/scanner.jsonl
# - This seeds the ML dataset for future classifier training.
# - On Render free tier filesystem is ephemeral; for persistence use S3/DB later.
# =============================================================================
DATASETS_DIR = pathlib.Path(__file__).parent / "datasets"
DATASETS_DIR.mkdir(exist_ok=True)

class FeedbackInput(BaseModel):
    text: str
    label: str  # "safe" or "unsafe"
    reason: Optional[str] = None

@app.post("/feedback")
def feedback(item: FeedbackInput, x_api_key: Optional[str] = Header(None)) -> Dict[str, Any]:
    _check_api_key(x_api_key)

    if item.label not in ("safe", "unsafe"):
        raise HTTPException(status_code=400, detail="label must be 'safe' or 'unsafe'")

    rec = {
        "ts": datetime.utcnow().isoformat() + "Z",
        "text": item.text,
        "label": item.label,
        "reason": item.reason,
        "source": "feedback",
    }
    with open(DATASETS_DIR / "scanner.jsonl", "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    try:
        log_event("feedback_saved", {"label": item.label})
    except Exception:
        pass

    return {"ok": True, "disclaimer": DISCLAIMER}

# =============================================================================
# GET / — serve index.html (standalone UI) if present next to app.py
# =============================================================================
@app.get("/", response_class=HTMLResponse)
def home() -> str:
    index_file = pathlib.Path(__file__).parent / "index.html"
    if index_file.exists():
        return index_file.read_text(encoding="utf-8")
    return "<h2>QubitGrid: UI file not found</h2><p>Please add index.html next to app.py</p>"

# =============================================================================
# Diagnostics for deploy checks
# - GET /__version returns a small text string for quick verification
# - GET /rules returns the compiled rule catalog (useful for debugging/UI)
# =============================================================================
APP_VERSION = "scanner-v0.3.3"

@app.get("/__version", response_class=PlainTextResponse)
def version():
    return f"{APP_VERSION} | FastAPI {fastapi_version}"

@app.get("/rules")
def list_rules():
    out = [
        {"id": rid, "category": cat, "severity": sev, "pattern": rx.pattern, "why": why}
        for (rid, cat, sev, rx, why) in _COMPILED
    ]
    return JSONResponse({"count": len(out), "rules": out})

# End of file
