# app.py — QubitGrid™ Prompt Injection Scanner (MVP1)
# -----------------------------------------------
# What this app exposes:
#   1) GET  /scan        → quick scan of a single text (via query string)
#   2) POST /report      → batch scan (JSON body), optional API-key gate
#   3) POST /feedback    → save human labels to a local JSONL dataset
#   4) GET  /            → serve standalone index.html (keeps results on-page)
#   5) GET  /__version   → quick version string (for deploy checks)
#   6) GET  /rules       → full rule catalog (id/category/severity/regex/why)
#
# Key terms:
# - "payload": the JSON body you POST to an endpoint.
# - "flags":   which rules matched in the text (short tag + regex + reason).
# - "severity": low/medium/high based on the worst matching rule.

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

# ==================== RULE CATALOG (structured) ====================
# Each rule: (id, category, severity, regex pattern, why)
# - id: short stable tag for reporting
# - category: the kind of risky behavior
# - severity: "low" | "medium" | "high"
# - pattern: regex matched case-insensitively
# - why: short human explanation shown to users

_RULES: List[Tuple[str, str, str, str, str]] = [
    # Prompt control override
    ("ignore_instructions", "control_override", "medium",
     r"\b(?:ignore|disregard)\s+(?:all|any|previous|prior)\s+instructions?\b",
     "User asks the model to ignore prior safety or task instructions."),
    ("reset_rules", "control_override", "medium",
     r"\b(?:forget|clear)\s+(?:all|previous|prior)\s+(?:rules|instructions|constraints)\b",
     "Attempts to reset safety rules or system constraints."),

    # Prompt/system exfiltration
    ("reveal_system_prompt", "prompt_exfiltration", "high",
     r"\b(?:reveal|show|print|display)\s+(?:the\s+)?(?:hidden\s+)?(?:system|developer)\s+prompt\b",
     "Tries to extract hidden system/developer instructions."),
    ("show_chain_of_thought", "prompt_exfiltration", "high",
     r"\b(?:show|reveal|explain)\s+(?:your\s+)?(?:chain[-\s]?of[-\s]?thought|reasoning)\b",
     "Tries to extract hidden reasoning or internal notes."),

    # Persona/role jailbreaks
    ("act_as_role_dan", "role_impersonation", "medium",
     r"\bact\s+as\s+(?:dan|developer\s*mode|root|sysadmin)\b",
     "Asks the model to assume a powerful/unsafe role."),
    ("do_anything_now", "role_impersonation", "medium",
     r"\bdo\s+anything\s+now\b",
     "Classic DAN jailbreak: bypass normal limitations."),

    # Code/command execution hints (often part of data exfil)
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

    # Encoding/obfuscation hints
    ("base64_indicator", "obfuscation", "low",
     r"\bbase64\b",
     "Base64 often used to conceal payloads or secrets."),
    ("hex_obfuscation", "obfuscation", "low",
     r"\b0x[0-9a-fA-F]{8,}\b",
     "Hex blobs can conceal data or instructions."),

    # Policy bypass phrases
    ("bypass_safety", "policy_bypass", "medium",
     r"\bbypass\s+(?:safety|filters|guardrails|content\s+policy)\b",
     "Asks to bypass safety policies or guardrails."),
    ("ignore_policy_for_research", "policy_bypass", "medium",
     r"\b(?:for\s+research|for\s+testing)\s*,?\s+(?:ignore|bypass)\s+(?:policy|safety)\b",
     "Tries to justify a bypass as 'research/testing'."),

    # Secret exfiltration
    ("exfiltrate_keys", "secret_exfiltration", "high",
     r"\b(?:api|secret|private)\s+keys?\b.*\b(?:print|reveal|show)\b",
     "Attempts to obtain API or private keys."),
    ("env_vars", "secret_exfiltration", "medium",
     r"\b(?:ENV|environment)\s+variables?\b",
     "Asks about environment variables where secrets may live."),
]

# Severity ordering for reduction
_SEV_ORDER = {"low": 0, "medium": 1, "high": 2}

def _worst(a: str, b: str) -> str:
    """Pick the worst of two severities."""
    return a if _SEV_ORDER[a] >= _SEV_ORDER[b] else b

# Precompile regex for speed (case-insensitive, dot matches newlines)
_COMPILED: List[Tuple[str, str, str, re.Pattern, str]] = [
    (rid, category, severity, re.compile(pattern, flags=re.IGNORECASE | re.DOTALL), why)
    for (rid, category, severity, pattern, why) in _RULES
]

# -------------------------
# Tiny analytics helper
# -------------------------
def log_event(event_name: str, props: Dict[str, Any]) -> None:
    """Print-only analytics so you can see usage in Render logs."""
    ts = datetime.utcnow().isoformat() + "Z"
    print(f"[analytics] {{'ts':'{ts}','event':'{event_name}','props':{props}}}")

# -------------------------
# Snippet helper (for flags)
# -------------------------
def _snippet(text: str, start: int, end: int, pad: int = 40) -> str:
    """Return a short snippet around a match to help humans see context."""
    s = max(0, start - pad)
    e = min(len(text), end + pad)
    return text[s:e].replace("\n", " ")  # keep it single-line

# -------------------------
# Shared scanner function
# -------------------------
def scan_text_rules(text: str) -> Tuple[List[Dict[str, Any]], str]:
    """
    Run all rules on the given text.
    Returns:
      - flags: list of {id, category, severity, why, snippet}
      - severity: 'low' | 'medium' | 'high' (worst match)
    """
    if not text:
        return [], "low"

    flags: List[Dict[str, Any]] = []
    overall = "low"

    for rid, category, severity, rx, why in _COMPILED:
        for m in rx.finditer(text):
            flags.append({
                "id": rid,
                "category": category,
                "severity": severity,
                "why": why,
                "snippet": _snippet(text, m.start(), m.end()),
            })
            overall = _worst(overall, severity)

    return flags, overall

# -------------------------
# GET /scan  (single text)
# -------------------------
@app.get("/scan")
def scan(text: str = Query(..., description="Text to scan for prompt injection")):
    """Single-text scan; returns flags + worst severity."""
    flags, severity = scan_text_rules(text)
    return JSONResponse({
        "flagged": len(flags) > 0,
        "severity": severity,
        "flags": flags,
        "disclaimer": DISCLAIMER,
    })

# -------------------------------------------------
# POST /report (batch texts; optional API key gate)
# -------------------------------------------------
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
    """Batch scan using the SAME rule engine as /scan (consistent behavior)."""
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
# GET /  (serve standalone index.html)
# -------------------------
@app.get("/", response_class=HTMLResponse)
def home() -> str:
    """Serve the standalone index.html UI instead of embedding HTML here."""
    index_file = pathlib.Path(__file__).parent / "index.html"
    if index_file.exists():
        return index_file.read_text(encoding="utf-8")
    return "<h2>QubitGrid: UI file not found</h2><p>Please add index.html next to app.py</p>"

# --- Diagnostics: quick version + rule list ---
APP_VERSION = "scanner-v0.3.1"  # bump whenever you deploy

@app.get("/__version", response_class=PlainTextResponse)
def version():
    """Used to verify a new deploy is live."""
    return f"{APP_VERSION} | FastAPI {fastapi_version}"

@app.get("/rules")
def list_rules():
    """Expose the current rule catalog for transparency."""
    out = [
        {"id": rid, "category": cat, "severity": sev, "pattern": rx.pattern, "why": why}
        for (rid, cat, sev, rx, why) in _COMPILED
    ]
    return JSONResponse({"count": len(out), "rules": out})
