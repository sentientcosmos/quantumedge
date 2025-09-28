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
# Notes:
# - Patterns use regex word boundaries \b and are case-insensitive.
# - Add new rules here. Keep them short and explained for maintainability.
_RULES: List[Tuple[str, str, str, str, str]] = [
    # control override / ignore instructions
    ("ignore_instructions", "control_override", "medium",
     r"\b(?:ignore|disregard)\s+(?:all|any|previous|prior)\s+instructions?\b",
     "User asks the model to ignore prior safety or task instructions."),

    ("reset_rules", "control_override", "medium",
     r"\b(?:forget|clear)\s+(?:all|previous|prior)\s+(?:rules|instructions|constraints)\b",
     "Attempts to reset safety rules or system constraints."),

    # system / prompt exfiltration
    ("reveal_system_prompt", "prompt_exfiltration", "high",
     r"\b(?:reveal|show|print|display)\s+(?:the\s+)?(?:hidden\s+)?(?:system|developer)\s+prompt\b",
     "Tries to extract hidden system/developer instructions."),

    ("show_chain_of_thought", "prompt_exfiltration", "high",
     r"\b(?:show|reveal|explain)\s+(?:your\s+)?(?:chain[-\s]?of[-\s]?thought|reasoning)\b",
     "Tries to extract hidden reasoning or internal notes."),

    # role impersonation / DAN style
    ("act_as_role_dan", "role_impersonation", "medium",
     r"\bact\s+as\s+(?:dan|developer\s*mode|root|sysadmin)\b",
     "Asks the model to assume a powerful/unsafe role."),

    ("do_anything_now", "role_impersonation", "medium",
     r"\bdo\s+anything\s+now\b",
     "Classic DAN jailbreak asking to bypass limitations."),

    # shell / exec / remote fetch patterns
    ("shell_danger_rmrf", "exec_risk", "high",
     r"\brm\s+-rf\s+/?\b",
     "Dangerous shell command that deletes files/directories."),

    ("shell_chmod_exec", "exec_risk", "medium",
     r"\bchmod\s+\+x\b",
     "Enables execution permission; often part of exploit chains."),

    ("remote_fetch", "exec_risk", "medium",
     r"\b(?:curl|wget)\s+https?://",
     "Fetches remote content; can be used to pull payloads."),

    ("powershell_download", "exec_risk", "high",
     r"powershell\.exe.+(?:downloadstring|invoke[-\s]?webrequest)",
     "PowerShell download/execute pattern (common in malware)."),

    # obfuscation indicators
    ("base64_indicator", "obfuscation", "low",
     r"\bbase64\b",
     "Base64 often used to conceal payloads or secrets."),

    ("hex_obfuscation", "obfuscation", "low",
     r"\b0x[0-9a-fA-F]{8,}\b",
     "Hex blobs can conceal data or instructions."),

    # policy bypass language
    ("bypass_safety", "policy_bypass", "medium",
     r"\bbypass\s+(?:safety|filters|guardrails|content\s+policy)\b",
     "Asks to bypass safety policies or guardrails."),

    ("ignore_policy_for_research", "policy_bypass", "medium",
     r"\b(?:for\s+research|for\s+testing)\s*,?\s+(?:ignore|bypass)\s+(?:policy|safety)\b",
     "Tries to justify a bypass as 'research/testing'."),

    # secret exfiltration attempts
    ("exfiltrate_keys", "secret_exfiltration", "high",
     r"\b(?:api|secret|private)\s+keys?\b.*\b(?:print|reveal|show)\b",
     "Attempts to obtain API or private keys."),

    ("env_vars", "secret_exfiltration", "medium",
     r"\b(?:ENV|environment)\s+variables?\b",
     "Asks about environment variables where secrets may live."),
]

# Map severity strings to numeric rank so we can choose the worst quickly
_SEV_ORDER = {"low": 0, "medium": 1, "high": 2}

def _worst(a: str, b: str) -> str:
    """Return the worst (highest priority) severity between a and b."""
    return a if _SEV_ORDER[a] >= _SEV_ORDER[b] else b

# Precompile regexes once for speed; keep the compiled object with metadata
# compiled entries shape: (rule_id, category, severity, compiled_regex, why)
_COMPILED: List[Tuple[str, str, str, re.Pattern, str]] = [
    (rid, cat, sev, re.compile(pat, flags=re.IGNORECASE | re.DOTALL), why)
    for (rid, cat, sev, pat, why) in _RULES
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
