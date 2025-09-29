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
import time  # for latency analytics
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

# =======================
# RULES SECTION (QubitGrid)
# =======================

# Each rule = (regex_pattern, severity, tag, why)
# - regex_pattern: what text pattern to flag
# - severity: "low" | "medium" | "high"
# - tag: short ID for the flag
# - why: human-readable reason shown to users

_RULES = [

    # --- Python-first rule pack (ultra-annotated) ---

    # 1) Python: eval or exec usage (high risk)
    # - matches: exec("..."), eval(...), with optional whitespace
    # - why: dynamic execution of text is often the root of RCE via malicious prompt content
    (r"\b(?:exec|eval)\s*\(", "high", "py_eval_exec",
     "Uses eval/exec which executes arbitrary Python code."),

    # 2) Python: __import__ dynamic import (high)
    # - matches: __import__("os") or __import__ (open parenthesis)
    # - why: dynamic imports can be used to load dangerous modules at runtime
    (r"__import__\s*\(", "high", "py_import_dynamic",
     "Dynamic import via __import__ can be used to load modules for malicious actions."),

    # 3) Python: subprocess spawning (high)
    # - matches: subprocess.Popen( ... ) or subprocess.run( ... )
    # - why: launching processes (bash, powershell) from Python is a direct exec risk
    (r"subprocess\.(?:Popen|run|call)\s*\(", "high", "py_subprocess",
     "Spawns OS processes via subprocess which can execute shell commands."),

    # 4) Python: open(..., 'w' or 'wb') or write() pattern (medium-high)
    # - matches: open('file','w') or .write( ... )
    # - why: writing files may be used to drop payloads or exfiltrate data
    (r"open\s*\([^,]+,\s*['\"](?:w|wb|a|ab)['\"]\s*\)|\.write\s*\(", "medium", "py_file_write",
     "File write operations that may be used to drop or modify files."),

    # 5) Python: untrusted pickle load (high)
    # - matches: pickle.loads(...), pickle.load(...)
    # - why: unpickling untrusted data can execute arbitrary code
    (r"\bpickle\.(?:loads|load)\s*\(", "high", "py_pickle_untrusted",
     "Untrusted pickle loading can execute arbitrary code on deserialization."),

    # 6) Python: format string attacks using % or .format (medium)
    # - matches: "%s" % var  OR  "{}".format(...) typical patterns
    # - why: attacker-controlled format strings can leak data or exploit templates
    (r'(?:(?:%s|%r|%d)\s*%|\b\.format\s*\()', "medium", "py_unsafe_formats",
     "Unsafe template/format usage that can be abused for data exfil or injection."),

    # 7) Python: import os; os.system(...) or os.popen (high)
    # - matches: os.system("...") or os.popen
    # - why: direct shell execution from Python
    (r"\bos\.system\s*\(|\bos\.popen\s*\(", "high", "code_exec_python",
     "Direct shell execution from Python via os.system/os.popen."),

    # 8) Python: use of eval on f-strings or formatted exec (medium-high)
    # - matches patterns like f"..." where suspicious markers appear AND eval usage
    # - why: f-strings with eval-like constructs are dangerous if attacker-controlled
    (r"f?['\"]\{.*\}['\"]", "medium", "py_eval_fstring",
     "Potential dynamic f-string / expression usage that may evaluate payloads."),

    # 9) Python: requests to remote endpoints inside Python (medium)
    # - matches: requests.get("http://...") or urllib.request.urlopen
    # - why: fetching remote payloads from within Python indicates remote fetch + exec risk
    (r"(?:requests\.(?:get|post)|urllib\.request\.urlopen)\s*\(", "medium", "py_remote_fetch",
     "Fetching remote content from Python which could be used to pull payloads."),

    # --- Control override / prompt tampering ---
    (r"\bignore|disregard\s+(?:all|any|previous|prior)\s+instructions\b",
     "medium", "ignore_instructions",
     "User asks the model to ignore prior safety or task instructions."),

    (r"\bforget|clear\s+(?:all|any|previous|prior)\s+(?:rules|instructions|constraints)\b",
     "medium", "reset_rules",
     "Attempts to reset safety rules or system constraints."),

    (r"\breveal|show|print|display\s+(?:the\s+)?system\s+prompt\b",
     "high", "reveal_system_prompt",
     "Tries to extract hidden system/developer instructions."),

    (r"\bshow|reveal|explain\s+(?:your|its)?\s*(?:chain|list|of|-)?thought|reasoning\b",
     "high", "show_chain_of_thought",
     "Tries to extract hidden reasoning or internal notes."),

    (r"\bact\s+as\s+(?:dan|developer\s+mode|root|sysadmin)\b",
     "medium", "act_as_role_dan",
     "Asks the model to assume a powerful/unsafe role."),

    (r"\bdo\s+anything\s+now\b",
     "medium", "do_anything_now",
     "Classic DAN jailbreak; bypass normal limitations."),

    # --- Exec risk (dangerous commands / payload fetch) ---
    # This one catches BOTH `rm -rf /` and `rm -rf /tmp`
    (r"\brm\s*-\s*rf\s*/(?:\s*\S*)?",
     "high", "shell_danger_rmrf",
     "Dangerous shell command that deletes files/directories."),

    (r"\bchmod\s+\+x\b",
     "medium", "shell_chmod_exec",
     "Enables execution permission; often part of exploit chains."),

    (r"\bpowershell\s+[-\w]*s*e[ncodel]*\s*",
     "high", "powershell_encoded",
     "Base64-encoded PowerShell often used to hide payloads."),

    (r"\bcurl|wget\s+https?://",
     "medium", "remote_fetch",
     "Fetches remote content; can be used to pull payloads."),

    (r"\bbase64\b",
     "low", "base64_indicator",
     "Base64 often used to conceal data or instructions."),

    (r"\b0x[0-9a-fA-F]{8,}\b",
     "low", "hex_obfuscation",
     "Hex blobs can conceal data or instructions."),

    # --- Policy bypass ---
    (r"\bbypass\s+safety|filters|guardrails|content|policy\b",
     "medium", "bypass_safety",
     "Asks to bypass safety policies or guardrails."),

    (r"\bignore\s+policy\b|\bfor\s+testing\b",
     "medium", "ignore_policy_for_testing",
     "Tries to justify a bypass as ‘research/testing’."),

    # --- Secret exfiltration ---
    (r"\bapi|secret|private\b.*keys\b",
     "high", "exfiltrate_keys",
     "Attempts to obtain API or private keys."),

    (r"\bENV|environment\s+variables\b",
     "medium", "env_vars",
     "Asks about environment variables where secrets may live."),



]
# ------------------------------
# Compile rules + helpers
# ------------------------------

# Map each rule id to a high-level category for nicer reporting
CATEGORY_MAP = {
    # control override / prompt tampering
    "ignore_instructions": "control_override",
    "reset_rules": "control_override",
    "reveal_system_prompt": "prompt_exfiltration",
    "show_chain_of_thought": "prompt_exfiltration",
    "act_as_role_dan": "role_impersonation",
    "do_anything_now": "role_impersonation",

    # exec risk / payload fetch
    "shell_danger_rmrf": "exec_risk",
    "shell_chmod_exec": "exec_risk",
    "powershell_encoded": "exec_risk",
    "remote_fetch": "exec_risk",
    "base64_indicator": "obfuscation",
    "hex_obfuscation": "obfuscation",
    # New categories we will use for Python-first pack
    "code_exec_python": "exec_risk",        # python dynamic exec / subprocess usage
    "py_eval_exec": "exec_risk",            # eval/exec specific
    "py_import_dynamic": "exec_risk",       # __import__ usage
    "py_subprocess": "exec_risk",           # subprocess calls (spawn shell)
    "py_file_write": "exec_risk",           # writing files to disk via open/write
    "py_pickle_untrusted": "exec_risk",     # untrusted pickle use -> code execution risk
    "py_unsafe_formats": "obfuscation",     # template formatting attacks (format, %)

    # policy bypass
    "bypass_safety": "policy_bypass",
    "ignore_policy_for_testing": "policy_bypass",

    # secret exfiltration
    "exfiltrate_keys": "secret_exfiltration",
    "env_vars": "secret_exfiltration",
}

# Severity ordering so we can compute the "worst" overall severity
_SEV_ORDER = {"low": 0, "medium": 1, "high": 2}
def _worst(a: str, b: str) -> str:
    """Return the higher (worse) of two severities."""
    return a if _SEV_ORDER.get(a, 0) >= _SEV_ORDER.get(b, 0) else b

# Turn _RULES (pattern, severity, id, why) into 5-tuples:
# (id, category, severity, compiled_regex, why)
_COMPILED = []
for pattern, severity, rid, why in _RULES:
    cat = CATEGORY_MAP.get(rid, "misc")
    rx = re.compile(pattern, re.IGNORECASE)
    _COMPILED.append((rid, cat, severity, rx, why))


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
    """
    Single-text scan endpoint. All logic must be indented inside this function.
    We:
      1. Measure start time
      2. Run compiled regex scanner
      3. Compute latency in ms and log telemetry
      4. Attempt Slack alert (best-effort)
      5. Return structured JSONResponse
    """
    # 1) Start timer for latency (ms)
    start = time.time()

    # 2) Run the rule scanner (compiled at startup)
    flags, severity = scan_text_rules(text)

    # 3) Compute latency and include it in telemetry
    latency_ms = int((time.time() - start) * 1000)

    try:
        # Minimal telemetry printed to stdout so Render logs capture it.
        log_event("scan_performed", {
            "length": len(text or ""),
            "flags_count": len(flags),
            "severity": severity,
            "categories": sorted({f.get("category") for f in flags}),
            "latency_ms": latency_ms,
        })
    except Exception:
        # Telemetry must not break the API — swallow any errors here.
        pass

    # 4) Slack alert (best-effort, non-blocking)
    try:
        if flags and _should_alert(severity):
            send_slack_alert(text=text, severity=severity, flags=flags, origin="scan")
    except Exception:
        pass

    # 5) Final response (structured)
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

@app.get("/health")
def health():
    return {
        "ok": True,
        "version": APP_VERSION,
        "fastapi": fastapi_version,
        "rules": len(_COMPILED),
        "time": datetime.utcnow().isoformat() + "Z",
    }

@app.get("/rules")
def list_rules():
    out = [
        {"id": rid, "category": cat, "severity": sev, "pattern": rx.pattern, "why": why}
        for (rid, cat, sev, rx, why) in _COMPILED
    ]
    return JSONResponse({"count": len(out), "rules": out})

# End of file
