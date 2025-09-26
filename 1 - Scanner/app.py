"""
app.py — QubitGrid™ Prompt Injection Scanner (MVP1)
===================================================
Purpose
-------
This FastAPI service detects likely prompt-injection patterns in user text.
It exposes:
  • GET  /            → serves index.html (the on-page UI)
  • GET  /scan        → scan a single text via query string (used by the UI)
  • POST /report      → scan a batch of texts (JSON body), optionally API-key gated
  • POST /feedback    → collect human labels into a local JSONL dataset
  • GET  /__version   → plain-text version string for deploy checks
  • GET  /rules       → the full rule catalog (id/category/severity/regex/why)

Safety & brand:
  • All responses include an advisory disclaimer.
  • No certifications are claimed; this is pre-audit readiness tooling.

This file is intentionally *ultra annotated* for clarity.
"""

# ------------------------------
# Standard imports (Python stdlib)
# ------------------------------
import os                # read environment variables (API keys, Slack webhook, etc.)
import re                # regular expressions (the rule engine uses compiled regex)
import json              # JSON encoding (logs, Slack payloads, feedback records)
import pathlib           # safe cross-platform file paths
import urllib.request    # simple HTTP POST for Slack webhooks
from datetime import datetime  # UTC timestamps for logs / records
from typing import List, Optional, Dict, Any, Tuple  # type hints for clarity

# ------------------------------
# FastAPI & helpers
# ------------------------------
from fastapi import FastAPI, Query, Header, HTTPException  # web framework + request helpers
from fastapi.responses import JSONResponse, HTMLResponse, PlainTextResponse
from pydantic import BaseModel, Field                       # request/response models (validation)
from fastapi import __version__ as fastapi_version          # shown by /__version

# ------------------------------
# App instance & global text
# ------------------------------
app = FastAPI(title="QubitGrid Prompt Injection Scanner")

# Every API response and report carries this advisory line.
DISCLAIMER = "QubitGrid™ provides pre-audit readiness tools only; not a certified audit."

# =============================================================================
# RULE CATALOG
# -----------------------------------------------------------------------------
# Each rule is a 5-tuple:
#   (rule_id, category, severity, regex_pattern, why_explanation)
#
# • rule_id    : short stable identifier used in flags and alerts
# • category   : logical grouping (control_override, prompt_exfiltration, etc.)
# • severity   : "low" | "medium" | "high" (used for summaries + alert thresholds)
# • pattern    : case-insensitive regex the engine will match in the text
# • why        : human-readable reason we flag this pattern (customer-facing)
#
# NOTE: We *compile* these patterns once at startup for performance.
# =============================================================================
_RULES: List[Tuple[str, str, str, str, str]] = [
    # 1) Control override attempts (try to negate prior instructions)
    ("ignore_instructions", "control_override", "medium",
     r"\b(?:ignore|disregard)\s+(?:all|any|previous|prior)\s+instructions?\b",
     "User asks the model to ignore prior safety or task instructions."),
    ("reset_rules", "control_override", "medium",
     r"\b(?:forget|clear)\s+(?:all|previous|prior)\s+(?:rules|instructions|constraints)\b",
     "Attempts to reset safety rules or system constraints."),

    # 2) Prompt/system exfiltration (asks for hidden prompts / internals)
    ("reveal_system_prompt", "prompt_exfiltration", "high",
     r"\b(?:reveal|show|print|display)\s+(?:the\s+)?(?:hidden\s+)?(?:system|developer)\s+prompt\b",
     "Tries to extract hidden system/developer instructions."),
    ("show_chain_of_thought", "prompt_exfiltration", "high",
     r"\b(?:show|reveal|explain)\s+(?:your\s+)?(?:chain[-\s]?of[-\s]?thought|reasoning)\b",
     "Tries to extract hidden reasoning or internal notes."),

    # 3) Role/persona jailbreaks (DAN/dev-mode/root/etc.)
    ("act_as_role_dan", "role_impersonation", "medium",
     r"\bact\s+as\s+(?:dan|developer\s*mode|root|sysadmin)\b",
     "Asks the model to assume a powerful/unsafe role."),
    ("do_anything_now", "role_impersonation", "medium",
     r"\bdo\s+anything\s+now\b",
     "Classic DAN jailbreak: bypass normal limitations."),

    # 4) Code/command execution hints (shell, PowerShell, remote pulls)
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

    # 5) Obfuscation indicators (encoding/hex blobs)
    ("base64_indicator", "obfuscation", "low",
     r"\bbase64\b",
     "Base64 often used to conceal payloads or secrets."),
    ("hex_obfuscation", "obfuscation", "low",
     r"\b0x[0-9a-fA-F]{8,}\b",
     "Hex blobs can conceal data or instructions."),

    # 6) Policy-bypass language (explicit asks to skip protections)
    ("bypass_safety", "policy_bypass", "medium",
     r"\bbypass\s+(?:safety|filters|guardrails|content\s+policy)\b",
     "Asks to bypass safety policies or guardrails."),
    ("ignore_policy_for_research", "policy_bypass", "medium",
     r"\b(?:for\s+research|for\s+testing)\s*,?\s+(?:ignore|bypass)\s+(?:policy|safety)\b",
     "Tries to justify a bypass as 'research/testing'."),

    # 7) Secret exfiltration (API keys, env variables, etc.)
    ("exfiltrate_keys", "secret_exfiltration", "high",
     r"\b(?:api|secret|private)\s+keys?\b.*\b(?:print|reveal|show)\b",
     "Attempts to obtain API or private keys."),
    ("env_vars", "secret_exfiltration", "medium",
     r"\b(?:ENV|environment)\s+variables?\b",
     "Asks about environment variables where secrets may live."),
]

# Map severities to a numeric rank so we can compute the “worst” one quickly.
_SEV_ORDER = {"low": 0, "medium": 1, "high": 2}

def _worst(a: str, b: str) -> str:
    """Return the worst (highest rank) severity among two values."""
    return a if _SEV_ORDER[a] >= _SEV_ORDER[b] else b

# Compile all regex patterns once at startup for speed.
# Each compiled entry = (rule_id, category, severity, compiled_regex, why)
_COMPILED: List[Tuple[str, str, str, re.Pattern, str]] = [
    (rid, cat, sev, re.compile(pat, flags=re.IGNORECASE | re.DOTALL), why)
    for (rid, cat, sev, pat, why) in _RULES
]

# =============================================================================
# Light analytics (stdout only)
# =============================================================================
def log_event(event_name: str, props: Dict[str, Any]) -> None:
    """
    Print a single-line JSON-ish analytics event to server logs.
    Keeping it simple for MVP; later you can send to a real analytics backend.
    """
    ts = datetime.utcnow().isoformat() + "Z"
    print(f"[analytics] {{'ts':'{ts}','event':'{event_name}','props':{props}}}")

# =============================================================================
# Core scanning helpers
# =============================================================================
def _snippet(text: str, start: int, end: int, pad: int = 40) -> str:
    """
    Return a small, single-line preview around a match (for UI/tooling).
    We trim newlines for neat rendering in Slack and the browser.
    """
    s = max(0, start - pad)
    e = min(len(text), end + pad)
    return text[s:e].replace("\n", " ")

def scan_text_rules(text: str) -> Tuple[List[Dict[str, Any]], str]:
    """
    Run the entire rule catalog on `text`.
    Returns:
      - flags: list of dicts (id, category, severity, why, snippet)
      - overall_severity: worst of all matched rules (low|medium|high)
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

# =============================================================================
# Optional Slack alerting
# -----------------------------------------------------------------------------
# If you set a Slack Incoming Webhook URL in env var SLACK_WEBHOOK, we can
# push a short alert message whenever severity ≥ SLACK_THRESHOLD.
#   SLACK_WEBHOOK   : the full webhook URL from Slack
#   SLACK_THRESHOLD : "low" | "medium" | "high"  (default: "high")
# =============================================================================
SLACK_WEBHOOK   = os.getenv("SLACK_WEBHOOK", "").strip()
ALERT_THRESHOLD = os.getenv("SLACK_THRESHOLD", "high").lower().strip()

def _sev_rank(s: str) -> int:
    """Convert severity string to numeric rank (0..2)."""
    return _SEV_ORDER.get(s, 0)

def _should_alert(severity: str) -> bool:
    """Return True if current severity meets/exceeds the configured threshold."""
    return _sev_rank(severity) >= _sev_rank(ALERT_THRESHOLD)

def send_slack_alert(text: str, severity: str, flags: list, origin: str = "scan") -> None:
    """
    POST a simple message to Slack. This is best-effort:
    failures are logged but never break the request.
    """
    if not SLACK_WEBHOOK:
        return  # feature disabled unless webhook is present

    # Show a compact set of unique rule IDs and a trimmed preview of the text
    top_flags = ", ".join(sorted({f.get("id") or f.get("tag", "?") for f in flags})) or "no-flags"
    preview = (text or "")[:200].replace("\n", " ")
    payload = {"text": f"QubitGrid alert ({origin}): severity={severity}, flags=[{top_flags}]\n→ preview: {preview}"}

    try:
        req = urllib.request.Request(
            SLACK_WEBHOOK,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=8) as resp:
            resp.read()  # drain response; Slack returns "ok"
    except Exception as e:
        print(f"[slack] failed to send alert: {e}")

# =============================================================================
# GET /scan — single-text scan used by the on-page UI
#   • Input via query string: ?text=...
#   • Returns JSON (flagged, severity, flags[], disclaimer)
# =============================================================================
@app.get("/scan")
def scan(text: str = Query(..., description="Text to scan for prompt injection")):
    flags, severity = scan_text_rules(text)

    # Optional Slack alert (only if configured AND threshold satisfied)
    try:
        if flags and _should_alert(severity):
            send_slack_alert(text=text, severity=severity, flags=flags, origin="scan")
    except Exception:
        pass  # never let alerting break scanning

    return JSONResponse({
        "flagged": len(flags) > 0,
        "severity": severity,
        "flags": flags,
        "disclaimer": DISCLAIMER,
    })

# =============================================================================
# Pydantic models for /report (batch) and helpers
#   • These must be defined BEFORE the route decorator uses them.
# =============================================================================
class BatchReportInput(BaseModel):
    """Request body for POST /report: a list of texts to scan."""
    texts: List[str] = Field(..., description="Batch of texts to scan")

class BatchReportItem(BaseModel):
    """One item in the batch result (index → flags + severity)."""
    index: int
    flags: List[Dict[str, Any]]
    severity: str  # "low" | "medium" | "high"

class BatchReportOut(BaseModel):
    """Full response for POST /report: items + summary + disclaimer."""
    items: List[BatchReportItem]
    summary: Dict[str, int]   # e.g., {"low": 3, "medium": 1, "high": 0}
    disclaimer: str

def _check_api_key(provided_key: Optional[str]) -> None:
    """
    If env var API_KEY is set, require header X-API-Key to match.
    This gives you a simple paywall/usage gate for /report and /feedback.
    """
    expected = os.getenv("API_KEY")
    if expected and provided_key != expected:
        raise HTTPException(status_code=403, detail="Forbidden. Valid API key required.")

# =============================================================================
# POST /report — batch scan
#   • JSON body: {"texts": ["...", "...", ...]}
#   • Optional header: X-API-Key: <value> (enforced only if API_KEY env is set)
#   • Returns items[], summary{}, disclaimer
# =============================================================================
@app.post("/report", response_model=BatchReportOut)
def report(payload: BatchReportInput, x_api_key: Optional[str] = Header(None)):
    _check_api_key(x_api_key)  # paywall gate (no-op if API_KEY not set)

    items: List[BatchReportItem] = []
    counts = {"low": 0, "medium": 0, "high": 0}

    for i, t in enumerate(payload.texts):
        flags, severity = scan_text_rules(t)
        items.append(BatchReportItem(index=i, flags=flags, severity=severity))
        counts[severity] += 1

        # Optional Slack alert per batch item
        try:
            if flags and _should_alert(severity):
                send_slack_alert(text=t, severity=severity, flags=flags, origin="report")
        except Exception:
            pass

    # Lightweight analytics (visible in server logs)
    try:
        log_event("batch_scan_performed", {"batch_size": len(payload.texts)})
    except Exception:
        pass

    return {"items": items, "summary": counts, "disclaimer": DISCLAIMER}

# =============================================================================
# POST /feedback — append labeled examples to a local JSONL file
#   • This is your seed dataset for a future ML classifier.
#   • On Render free tier the filesystem is ephemeral; that's fine for demos.
# =============================================================================
DATASETS_DIR = pathlib.Path(__file__).parent / "datasets"
DATASETS_DIR.mkdir(exist_ok=True)

class FeedbackInput(BaseModel):
    """Request body for POST /feedback."""
    text: str
    label: str                    # must be "safe" or "unsafe"
    reason: Optional[str] = None  # optional human note

@app.post("/feedback")
def feedback(item: FeedbackInput, x_api_key: Optional[str] = Header(None)) -> Dict[str, Any]:
    _check_api_key(x_api_key)  # require API key if configured

    # Strict label validation keeps the dataset consistent.
    if item.label not in ("safe", "unsafe"):
        raise HTTPException(status_code=400, detail="label must be 'safe' or 'unsafe'")

    # One JSON object per line (JSONL format). Easy to train on later.
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
# GET / — serve the standalone UI (index.html) next to this file
#   • If index.html is missing, we return a small placeholder message.
# =============================================================================
@app.get("/", response_class=HTMLResponse)
def home() -> str:
    index_file = pathlib.Path(__file__).parent / "index.html"
    if index_file.exists():
        return index_file.read_text(encoding="utf-8")
    return "<h2>QubitGrid: UI file not found</h2><p>Please add index.html next to app.py</p>"

# =============================================================================
# Diagnostics endpoints
#   • /__version : simple text to verify deployments quickly
#   • /rules     : full catalog (useful for UI or debugging)
# =============================================================================
APP_VERSION = "scanner-v0.3.3"  # bump this when you deploy

@app.get("/__version", response_class=PlainTextResponse)
def version():
    """Return app version and FastAPI version (helpful in Render logs)."""
    return f"{APP_VERSION} | FastAPI {fastapi_version}"

@app.get("/rules")
def list_rules():
    """Return the complete rule list (id, category, severity, pattern, why)."""
    out = [
        {"id": rid, "category": cat, "severity": sev, "pattern": rx.pattern, "why": why}
        for (rid, cat, sev, rx, why) in _COMPILED
    ]
    return JSONResponse({"count": len(out), "rules": out})
