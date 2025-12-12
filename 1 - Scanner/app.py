"""
app.py — QubitGrid™ Prompt Injection Scanner (MVP1)
Ultra-annotated: every section explains what it does and why.

Paste this whole file over your existing app.py (backup your old app.py first).
"""

# ------------------------------
# Standard library imports
# ------------------------------
import os                 # read environment variables (API_KEY, SLACK_WEBHOOK)|ensure this import exists on the top
import re                 # regular expressions => rule engine
import json               # json encoding (feedback file, slack payload)
import pathlib            # cross-platform paths for index.html and datasets
import urllib.request     # simple HTTP POST (used for Slack webhook)
import secrets            # for generating secure API keys
import time  # for latency analytics
from datetime import datetime
from typing import List, Optional, Dict, Any, Tuple
from collections import Counter  # used to count severities & plans
from datetime import timedelta   # used to compute the N-day window
# --- Load environment from .env/ENV for local dev ----------------------------
# Why: when running locally, Stripe keys (and other settings) live in files.
# In prod (e.g., Render), you set them in the dashboard and this is harmless.
from pathlib import Path
try:
    from dotenv import load_dotenv  # pip install python-dotenv
    _BASE_DIR = Path(__file__).parent
    # Load .env if present (common convention)
    load_dotenv(_BASE_DIR / ".env", override=False)
    # Also load ENV (your file name) if present; does NOT overwrite already-loaded values
    load_dotenv(_BASE_DIR / "ENV", override=False)
except Exception as e:
    # Don't break the app if python-dotenv is not installed
    print("[dotenv] skip loading .env/ENV:", e)
# ---------------------------------------------------------------------------
# >>> INSERT: ANALYTICS — IMPORTS & ENV (BEGIN)
import os, sqlite3, hashlib, time
from datetime import datetime, timezone
from fastapi import BackgroundTasks
ANALYTICS_DB_PATH = os.getenv("ANALYTICS_DB_PATH", "analytics.db")
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "dev-local-admin")  # add to .env.example / Render
# <<< INSERT: ANALYTICS — IMPORTS & ENV (END)
from models import Base, engine, SessionLocal, init_db

# Initialize DB at startup
init_db()


# ------------------------------
# FastAPI framework + helpers
# ------------------------------
from fastapi import FastAPI, Query, Header, HTTPException
from fastapi import Form
from fastapi.responses import JSONResponse, HTMLResponse, PlainTextResponse, FileResponse
from pydantic import BaseModel, Field
from fastapi import __version__ as fastapi_version  # show FastAPI version in /__version
from fastapi.staticfiles import StaticFiles


from fastapi import Request	          # Request for client IP + headers
import hashlib                            # to hash the User-Agent (privacy + compact token)

# ANALYTICS helpers (store small recent history in memory; $0 infra)
from collections import deque, Counter



# Default product disclaimer (appears in every response/report).
DISCLAIMER = "QubitGrid™ provides pre-audit readiness tools only; not a certified audit."

# ------------------------------
# App instance + global strings
# ------------------------------
app = FastAPI(title="QubitGrid Prompt Injection Scanner")

# >>> INSERT: ANALYTICS — DB INIT (BEGIN)
def _db_connect():
    # One connection per call avoids cross-thread issues.
    # WAL improves durability and prevents full-file locks.
    conn = sqlite3.connect(ANALYTICS_DB_PATH, check_same_thread=False)
    try:
        conn.execute("PRAGMA journal_mode=WAL;")     # safer, allows concurrent reads
        conn.execute("PRAGMA synchronous=NORMAL;")   # balances durability & speed
        conn.execute("PRAGMA foreign_keys=ON;")      # keeps relational integrity
    except Exception:
        pass
    return conn


def _analytics_init():
    with _db_connect() as conn:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS scan_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            ip_masked TEXT,
            user_tier TEXT,
            status TEXT NOT NULL,
            flagged INTEGER NOT NULL,
            latency_ms INTEGER,
            prompt_hash TEXT,
            report_path TEXT,
            customer_email TEXT,
            api_key_prefix TEXT
        );
        """)
        
        # Phase 4 Migration Helper: Add columns if missing (safe idempotent check)
        # We rely on PRAGMA table_info to check existence, then ALTER TABLE.
        existing_cols = {row[1] for row in conn.execute("PRAGMA table_info(scan_logs)")}
        
        if "customer_email" not in existing_cols:
            try:
                conn.execute("ALTER TABLE scan_logs ADD COLUMN customer_email TEXT")
            except Exception as e:
                print(f"[DB] Migration warning (customer_email): {e}")

        if "api_key_prefix" not in existing_cols:
            try:
                conn.execute("ALTER TABLE scan_logs ADD COLUMN api_key_prefix TEXT")
            except Exception as e:
                print(f"[DB] Migration warning (api_key_prefix): {e}")

        # Phase 8 Migration: Ensure grace_period_start exists on customers
        try:
            cust_cols = {row[1] for row in conn.execute("PRAGMA table_info(customers)")}
            if "grace_period_start" not in cust_cols and "id" in cust_cols:
                conn.execute("ALTER TABLE customers ADD COLUMN grace_period_start TIMESTAMP")
                print("[DB] Migrated customers table: added grace_period_start")
        except Exception:
            pass

        conn.commit()

_analytics_init()
# <<< INSERT: ANALYTICS — DB INIT (END)


app.mount("/static", StaticFiles(directory="static"), name="static")

# >>> INSERT: RATE LIMIT BUCKET INITIALIZATION (BEGIN)
# In-memory ledger for free-tier usage by "client" (IP + UA hash).
# Key format: "<ip>|<ua_hash>" -> Value: {"date": "YYYY-MM-DD", "count": int}
_RATE_LIMIT_BUCKET: dict[str, dict[str, Any]] = {}

# Resolve the free daily limit from environment; .env can override this.
# Example in your .env currently sets FREE_DAILY_LIMIT=3 for testing.
FREE_DAILY_LIMIT = int(os.getenv("FREE_DAILY_LIMIT", "15"))
# <<< INSERT: RATE LIMIT BUCKET INITIALIZATION (END)

def _mask_ip(ip: str) -> str:
    """
    Privacy-friendly IP masking for logs/telemetry (keeps /24 granularity for IPv4).
    E.g., '203.0.113.42' -> '203.0.113.x'
    """
    if not ip or "." not in ip:
        return ip or "unknown"
    parts = ip.split(".")
    parts[-1] = "x"
    return ".".join(parts)

def _client_token(request: Request) -> tuple[str, str, str]:
    """
    Build a token that identifies a 'client' for rate-limiting.
    Uses: client IP + hashed User-Agent.
    Returns: (token, ip, ua_hash)
    """
    ip = request.client.host if request.client else "unknown"
    ua = (request.headers.get("user-agent") or "").strip()
    ua_hash = hashlib.sha256(ua.encode("utf-8")).hexdigest()[:8]  # short, non-reversible label
    token = f"{ip}|{ua_hash}"
    return token, ip, ua_hash

# >>> INSERT: PAID RATE LIMIT BUCKET (BEGIN)
# Ledger for paid API key usage.
# Key format: "key_hash" -> Value: {"date": "YYYY-MM-DD", "count": int}
_PAID_LIMIT_BUCKET: dict[str, dict[str, Any]] = {}

def _get_paid_usage_stats(key_hash: str, plan_name: str) -> dict:
    """
    Read-only fetch of usage stats for the dashboard.
    Does NOT increment counters.
    """
    # 1. Resolve limit
    tier_def = _tier_by_name(plan_name)
    limit = int(tier_def.get("scan_limit_per_day", FREE_DAILY_LIMIT))
    
    # 2. Check bucket
    today = datetime.utcnow().strftime("%Y-%m-%d")
    entry = _PAID_LIMIT_BUCKET.get(key_hash)
    
    count = 0
    if entry and entry.get("date") == today:
        count = entry["count"]
        
    return {
        "limit": limit,
        "count": count,
        "remaining": max(0, limit - count),
        "reset_utc": (datetime.utcnow().date() + timedelta(days=1)).isoformat()
    }

def _check_paid_limit(key_hash: str, plan_name: str) -> Tuple[bool, int, int]:
    """
    Check if the API key has exceeded its daily limit based on the plan.
    Returns: (is_allowed, limit, remaining)
    """
    # 1. Resolve limit from Pricing Model
    tier_def = _tier_by_name(plan_name)
    # Default to Free limit if plan not found (safety fallback)
    limit = int(tier_def.get("scan_limit_per_day", FREE_DAILY_LIMIT))
    
    # 2. Check bucket
    today = datetime.utcnow().strftime("%Y-%m-%d")
    entry = _PAID_LIMIT_BUCKET.get(key_hash)

    if not entry or entry.get("date") != today:
        entry = {"date": today, "count": 0}
        _PAID_LIMIT_BUCKET[key_hash] = entry
    
    # 3. Enforce
    if entry["count"] >= limit:
        return False, limit, 0
    
    # 4. Increment (optimistic; caller will proceed to scan)
    entry["count"] += 1
    return True, limit, limit - entry["count"]
# <<< INSERT: PAID RATE LIMIT BUCKET (END)

def _rate_limit_check_and_increment(request: Request) -> dict | None:
    """
    Enforce the FREE_DAILY_LIMIT for anonymous users.
    - If a valid API key is present (Authorization: Bearer <API_KEY>), we SKIP the limit.
    - Otherwise we count this request against today's bucket for (IP+UA).
    Returns None if allowed; returns a dict payload if blocked (429).
    """
    # Bypass for paid/API-key users (simple starter policy)
    if API_KEY and (request.headers.get("authorization", "") == f"Bearer {API_KEY}"):
        return None

    token, ip, ua_hash = _client_token(request)
    today = datetime.utcnow().strftime("%Y-%m-%d")

    entry = _RATE_LIMIT_BUCKET.get(token)
    if not entry or entry.get("date") != today:
        # First request today (or day rolled over) -> reset counter
        entry = {"date": today, "count": 0}
        _RATE_LIMIT_BUCKET[token] = entry

    # If already at/over limit -> block
    if entry["count"] >= FREE_DAILY_LIMIT:
        # Optional: log the event (goes to your in-memory analytics buffer too)
        try:
            log_event("rate_limited", {
                "ip_masked": _mask_ip(ip),
                "ua_hash": ua_hash,
                "limit": FREE_DAILY_LIMIT,
                "date": today
            })
        except Exception:
            pass

        # Compute a simple reset hint (next midnight UTC)
        tomorrow = (datetime.utcnow().date() + timedelta(days=1)).isoformat()
        return {
            "error": "Free tier daily limit reached.",
            "limit": FREE_DAILY_LIMIT,
            "reset_utc_date": tomorrow,
            "upgrade": "/roadmap"
        }

    # Otherwise consume one unit and allow
    entry["count"] += 1
    try:
        log_event("rate_limit_increment", {
            "ip_masked": _mask_ip(ip),
            "ua_hash": ua_hash,
            "count": entry["count"],
            "date": today
        })
    except Exception:
        pass
    return None

def _authenticate_view_only(request: Request) -> Tuple[dict | None, dict]:
    """
    Authentication for Dashboard (View-Only).
    - Checks API Key against DB.
    - Does NOT check or increment rate limits.
    - Does NOT allow Admin Token (User Dashboard is for Users).
    
    Returns:
      (error_dict, user_context)
    """
    auth_header = request.headers.get("authorization", "").strip()
    if not auth_header.startswith("Bearer "):
         return {"error": "Missing API Key", "status_code": 401}, None

    token = auth_header[len("Bearer "):].strip()
    
    # Explicitly disallow Admin Token for this user view
    if API_KEY and token == API_KEY:
        return {"error": "Admin token not allowed here. Use real user key.", "status_code": 403}, None

    from models import SessionLocal, APIKey, Customer
    
    params_hash = APIKey.hash_key(token)
    session = SessionLocal()
    try:
        api_key_record = session.query(APIKey).filter_by(key_hash=params_hash, active=True).first()
        if not api_key_record:
             return {"error": "Invalid or inactive API key.", "status_code": 401}, None
             
        # Fetch detailed status from Customer table
        customer = session.query(Customer).filter_by(email=api_key_record.user_email).first()
        status = customer.status if customer else "unknown"
        
        # --- PHASE 8: AUTH ENFORCEMENT ---
        if status == "past_due" and customer.grace_period_start:
            # Check grace window (3 days)
            deadline = customer.grace_period_start + timedelta(days=3)
            if datetime.utcnow() > deadline:
                return {"error": "Subscription expired. Please update billing.", "grace_ended": True, "status_code": 402}, None
        
        elif status in ["canceled", "unpaid"]:
             return {"error": "Subscription canceled. Please reactivate.", "status_code": 402}, None
             
        ctx = {
            "email": api_key_record.user_email,
            "plan": api_key_record.plan,
            "key_hash": params_hash,
            "masked_key": f"qg_{token[:4]}...{token[-4:]}" if len(token) > 10 else "qg_masked",
            "status": status,
            "days_left": None
        }
        
        # Pass days_left for dashboard banner logic
        if status == "past_due" and customer.grace_period_start:
             deadline = customer.grace_period_start + timedelta(days=3)
             delta = deadline - datetime.utcnow()
             ctx["days_left"] = max(0, delta.days)

        return None, ctx
    finally:
        session.close()

def _authenticate_and_limit(request: Request) -> Tuple[dict | None, str, dict]:
    """
    Unified Auth & Rate Limit Enforcer.
    
    Returns:
      (error_response_dict, tier_name, auth_context)
      
    auth_context keys: source ("free"|"admin"|"api_key"), customer_email, api_key_prefix, plan
    """
    auth_header = request.headers.get("authorization", "").strip()
    
    # --- 1. Anonymous / Free Tier ---
    if not auth_header.startswith("Bearer "):
        # Apply existing IP-based limit
        limit_error = _rate_limit_check_and_increment(request)
        if limit_error:
            return limit_error, "Free", {"source": "free"}
        return None, "Free", {"source": "free"}

    token = auth_header[len("Bearer "):].strip()

    # --- 2a. Admin / Env Var Bypass ---
    if API_KEY and token == API_KEY:
        return None, "Admin", {"source": "admin"}

    # --- 2b. DB-Backed API Key ---
    from models import SessionLocal, APIKey
    
    # Hash incoming key to lookup
    params_hash = APIKey.hash_key(token)
    
    session = SessionLocal()
    try:
        # Find active key
        api_key_record = session.query(APIKey).filter_by(key_hash=params_hash, active=True).first()
        
        if not api_key_record:
            # Invalid key
            return {"error": "Invalid or inactive API key.", "status_code": 401}, "Unknown", {"source": "error"}
            
        # --- PHASE 8: AUTH ENFORCEMENT ---
        from models import Customer
        customer = session.query(Customer).filter_by(email=api_key_record.user_email).first()
        status = customer.status if customer else "active" # Fallback if customer not found? (Shouldn't happen for paid)
        
        if status == "past_due" and customer.grace_period_start:
             deadline = customer.grace_period_start + timedelta(days=3)
             if datetime.utcnow() > deadline:
                 return {
                     "error": "Subscription expired. Please update billing.", 
                     "grace_ended": True, 
                     "status_code": 402
                 }, "Unknown", {"source": "error"}

        elif status in ["canceled", "unpaid"]:
             return {
                 "error": "Subscription canceled. Please reactivate.",
                 "status_code": 402
             }, "Unknown", {"source": "error"}
        
        # Key is valid. Check Rate Limit for this Plan.
        plan_name = api_key_record.plan
        allowed, limit, remaining = _check_paid_limit(params_hash, plan_name)
        
        if not allowed:
            return {
                "error": f"Daily limit reached for {plan_name} tier.",
                "limit": limit,
                "reset_utc_date": (datetime.utcnow().date() + timedelta(days=1)).isoformat(),
                "upgrade": "/roadmap",
                "status_code": 429
            }, plan_name, {"source": "error"}
            
        # Allowed - Return Full Context
        ctx = {
            "source": "api_key",
            "api_key_hash": params_hash,
            "api_key_prefix": params_hash[:8],
            "customer_email": api_key_record.user_email,
            "plan": plan_name
        }
        return None, plan_name, ctx

    except Exception as e:
        print(f"[AUTH ERROR] {e}")
        return {"error": "Internal auth error", "status_code": 500}, "Unknown", {"source": "error"}
    finally:
        session.close()

# ---------------------------------------------------------------------
# In-memory telemetry ring buffer (keeps recent events; survives process lifetime)
# Size choice: 5000 is tiny memory but enough for early traction.
# Each item is a dict: {"ts": "ISO", "event": "scan_performed"|"checkout_intent", "props": {...}}
ANALYTICS_EVENTS = deque(maxlen=5000)

def _analytics_push(evt: str, props: dict):
    """
    Helper: push a normalized analytics record into memory.
    Called inside log_event() so all existing calls benefit automatically.
    """
    try:
        ANALYTICS_EVENTS.append({
            "ts": datetime.utcnow().isoformat() + "Z",
            "event": evt,
            "props": props or {}
        })
    except Exception as e:
        # Non-fatal: never block scans because of analytics
        print("[analytics] in-memory push failed:", e)
# >>> INSERT: ANALYTICS — HELPERS (BEGIN)


def _sha1(text: str) -> str:
    # privacy-safe: hash of prompt content, not the raw prompt
    return hashlib.sha1((text or "").encode("utf-8")).hexdigest()

def _analytics_insert_row(row: dict):
    with _db_connect() as conn:
        conn.execute(
            """INSERT INTO scan_logs
               (timestamp, ip_masked, user_tier, status, flagged, latency_ms, prompt_hash, report_path, customer_email, api_key_prefix)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                row["timestamp"],
                row.get("ip_masked", ""),
                row.get("user_tier", "Free"),
                str(row["status"]),
                1 if row.get("flagged") else 0,
                row.get("latency_ms"),
                row.get("prompt_hash"),
                row.get("report_path"),
                row.get("customer_email"),
                row.get("api_key_prefix"),
            ),
        )
        conn.commit()
# <<< INSERT: ANALYTICS — HELPERS (END)




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
#============#
    # =========================
    # FULL RULE EXPANSION PACK
    # =========================

    # --- SHELL & UNIX ---
    # Dangerous deletion
    (r"\brm\s*-\s*rf\s+/(?:\s|$)", "high", "shell_rmrf",
     "Shell command to recursively delete from root (rm -rf /)."),
    # Privilege / perm escalation
    (r"\b(?:sudo\s+.*|chmod\s+\+x\b|chown\s+\w+:\w+)\b", "high", "shell_sudo_chmod",
     "Privilege/permission escalation via sudo/chmod/chown."),
    # Fetch & execute (curl|wget) piped to sh/bash
    (r"(?:curl|wget)\b[^\n]+?\|\s*(?:sh|bash)\b", "high", "shell_pipe_to_sh",
     "Fetch remote script and pipe directly to shell (curl|wget | sh)."),
    # Reverse TCP shells (bash /dev/tcp trick)
    (r"bash\s+-i\s+>&\s*/dev/tcp/\d{1,3}(?:\.\d{1,3}){3}/\d{2,5}\s+0>&1", "high", "shell_reverse_tcp",
     "Bash reverse shell using /dev/tcp redirection."),
    # Raw curl/wget remote fetch
    (r"\b(?:curl|wget)\s+https?://", "medium", "shell_curl_wget",
     "Remote fetch via curl/wget (possible payload retrieval)."),
    # certutil download (Windows but often via shell)
    (r"\bcertutil\.exe\b.*\b-urlcache\b.*\b-split\b.*\b-f\b", "high", "shell_certutil_fetch",
     "Windows certutil used to fetch files (T1105)."),
    # Netcat/ncat exfil/execution
    (r"\b(?:nc|ncat)\s+(?:-e|-c)\s+\w+", "high", "shell_nc_exfil",
     "Netcat used to pipe I/O for remote command execution/exfiltration."),

    # --- POWERSHELL ---
    # IEX + WebClient/DownloadString
    (r"\bIEX\b|\bInvoke-Expression\b|New-Object\s+Net\.WebClient.*DownloadString", "high", "ps_exec_iexd",
     "PowerShell execution of downloaded content (IEX / WebClient.DownloadString)."),
    # Common bypass flags and hidden windows
    (r"\bpowershell\b.*(?:-nop|-noprofile).*?(?:-w\s*hidden|-windowstyle\s*hidden).*", "high", "ps_bypass_hidden",
     "PowerShell execution with profile bypass and hidden window."),
    # Base64-encoded PS payloads (-enc / -encodedcommand)
    (r"\b(?:-enc|--encodedcommand)\s+[A-Za-z0-9+/=]{20,}", "medium", "ps_base64_enc",
     "PowerShell encoded payload supplied on command line."),
    # Invoke-WebRequest fetch
    (r"\bInvoke-WebRequest\b\s+-Uri\s+https?://", "medium", "ps_invoke_webrequest",
     "PowerShell web request likely retrieving remote script or data."),

    # --- SQL INJECTION / EXFIL ---
    (r"\bUNION\s+SELECT\b.*\bFROM\b", "high", "sqli_union",
     "SQLi UNION SELECT pattern aiming to read arbitrary columns."),
    (r"\bINFORMATION_SCHEMA\b", "high", "sqli_information_schema",
     "Probing DB schema via INFORMATION_SCHEMA tables."),
    (r"\bxp_cmdshell\b", "high", "sqli_xp_cmdshell",
     "MSSQL extended proc to execute OS commands via SQL."),

    # --- PATH TRAVERSAL & SENSITIVE PATHS ---
    (r"(?:\.\./){2,}(?:etc/passwd|etc/shadow|hosts)\b", "high", "path_traversal",
     "Directory traversal attempt to read sensitive UNIX files."),
    (r"/etc/(?:passwd|shadow|sudoers|ssh/ssh_config)\b", "high", "linux_sensitive_path",
     "Direct access to sensitive Linux files."),
    (r"(?:C:\\|%SystemRoot%\\)Windows\\System32\\", "high", "windows_sensitive_path",
     "Direct access to sensitive Windows System32 paths."),

    # --- TOKENS / SECRETS / ENV ---
    (r"Authorization:\s*Bearer\s+[A-Za-z0-9\-\._~\+\/]+=*", "high", "token_bearer",
     "Exposed Bearer token header pattern."),
    (r"\bAWS_(?:SECRET_ACCESS_KEY|ACCESS_KEY_ID)\b", "high", "token_aws",
     "AWS credentials referenced in text."),
    (r"\b(?:x-api-key|api_key|api-key)\b\s*[:=]\s*[A-Za-z0-9\-\._]{10,}", "high", "token_api_key",
     "API key material present."),
    (r"-----BEGIN (?:RSA |EC |)PRIVATE KEY-----", "high", "leak_private_key",
     "Private key material present in text."),
    (r"\b(?:^|/)\.env\b|^ENV\s*=|^SECRET\s*=", "medium", "dotenv_leak",
     "Dotenv or generic secret variable exposure."),
    (r"\b(?:env\s*\|\s*grep|printenv|Set-Item\s+Env:|Get-ChildItem\s+Env:)\b", "medium", "env_dump",
     "Environment variable enumeration likely for secret discovery."),

    # --- OBFUSCATION BLOBS ---
  # Long-ish Base64-like blobs (lower threshold to 16 to catch shorter encoded tokens)
(r"\b[A-Za-z0-9+/]{16,}={0,2}\b", "medium", "base64_blob",
 "Suspicious Base64-like blob (possible encoded payload)."),

    # Hefty hex strings
    (r"\b(?:0x)?[0-9a-fA-F]{32,}\b", "low", "hex_blob",
     "Suspicious long hex-like blob (possible encoded payload)."),
#========#

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

    # --- Full-pack categories (non-Python) ---
    "shell_rmrf": "exec_risk",
    "shell_sudo_chmod": "exec_risk",
    "shell_pipe_to_sh": "exec_risk",
    "shell_reverse_tcp": "net_exfil",
    "shell_curl_wget": "net_fetch",
    "shell_certutil_fetch": "net_fetch",
    "shell_nc_exfil": "net_exfil",
    "ps_exec_iexd": "exec_risk",              # Invoke-Expression / web download
    "ps_bypass_hidden": "exec_risk",          # -nop -w hidden -enc
    "ps_base64_enc": "obfuscation",
    "ps_invoke_webrequest": "net_fetch",
    "sqli_union": "data_exfiltration",
    "sqli_information_schema": "data_exfiltration",
    "sqli_xp_cmdshell": "exec_risk",
    "path_traversal": "fs_probe",
    "linux_sensitive_path": "fs_probe",
    "windows_sensitive_path": "fs_probe",
    "token_bearer": "secret_exfiltration",
    "token_aws": "secret_exfiltration",
    "token_api_key": "secret_exfiltration",
    "leak_private_key": "secret_exfiltration",
    "dotenv_leak": "secret_exfiltration",
    "env_dump": "secret_exfiltration",
    "base64_blob": "obfuscation",
    "hex_blob": "obfuscation",

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
    Unified analytics logger.

    What it does:
    - Prints a compact analytics line to STDOUT (so you see it in your terminal / Render logs).
    - ALSO appends a normalized record to the in-memory ring buffer (ANALYTICS_EVENTS),
      via _analytics_push(...). This enables a zero-cost /analytics summary endpoint next.

    Why this matters:
    - You keep your current simple logging flow (no infra).
    - You gain instant ability to summarize usage later without databases.
    """
    ts = datetime.utcnow().isoformat() + "Z"

    # 1) Print to logs (what you already had)
    print(f"[analytics] {{'ts':'{ts}','event':'{event_name}','props':{props}}}")

    # 2) Push into in-memory buffer for later aggregation (/analytics)
    try:
        _analytics_push(event_name, props or {})
    except Exception as e:
        # Never break app behavior because of analytics
        print("[analytics] in-memory push failed:", e)

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

    Returns
    -------
    flags : list[dict]
        Each item has: id, category, severity, why, snippet
    overall_severity : str
        "low" | "medium" | "high" (the worst severity seen)
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
# Helpers: shorten snippets and aggregate duplicate flags by rule id
# =============================================================================
def _shorten(s: str, n: int = 160) -> str:
    """
    Return a UI-friendly snippet:
    - Replace newlines with spaces (keeps layouts clean)
    - Trim to at most `n` characters and add an ellipsis if trimmed
    """
    if not s:
        return s
    s = s.replace("\n", " ")
    return (s[:n] + "…") if len(s) > n else s


def aggregate_flags(raw_flags: list) -> list:
    """
    Merge repeated matches for the same rule id.

    Parameters
    ----------
    raw_flags : list[dict]
        Items produced by scan_text_rules(), e.g.:
        { "id": "...", "category": "...", "severity": "...", "why": "...", "snippet": "..." }

    Returns
    -------
    list[dict]
        One entry per rule id, with:
        - `match_count`: total matches for that rule
        - `snippet`: shortened for readability
    """
    agg = {}
    for f in (raw_flags or []):
        rid = f.get("id", "unknown")
        if rid not in agg:
            g = dict(f)                      # copy first occurrence
            g["match_count"] = 0             # initialize counter
            if isinstance(g.get("snippet"), str):
                g["snippet"] = _shorten(g["snippet"])
            agg[rid] = g
        agg[rid]["match_count"] += 1
    return list(agg.values())



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
    payload = {"text": f"QubitGrid alert ({origin}): severity={severity}, flags=[{top_flags}]\n-> preview: {preview}"}
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

# >>> PATCH: REPLACE /scan ENDPOINT (BEGIN)
# =============================================================================
# GET /scan — single-text scan (used by the demo UI)
# - Input: query param ?text=...
# - Output: JSON with flagged (bool), severity, flags[], disclaimer
# =============================================================================
@app.get("/scan")
def scan(
        request: Request,
        text: str = Query(..., description="Text to scan for prompt injection"),
        bt: BackgroundTasks = BackgroundTasks()):
    """
    Single-text scan endpoint. All logic must be indented inside this function.
    We:
      1. Apply free-tier rate limit (returns 429 if exceeded)
      2. Enforce soft input cap (head/tail slice)
      3. Run compiled regex scanner
      4. Log telemetry + best-effort Slack alert
      5. Return structured JSON
    """

    # --- analytics timer + client info (for /admin/usage rows) ---
    start_ts = time.perf_counter()
    client_ip = request.client.host if request and request.client else ""
    
    # ---------- AUTH & RATE LIMIT ----------
    # Return context (source, email, etc.) for logging
    error_payload, tier, auth_ctx = _authenticate_and_limit(request)
    
    if error_payload:
        # Check if it's a 401/403 or 429
        status = error_payload.pop("status_code", 429)
        
        # Log the failure (optional, but good for visibility)
        if status == 429:
             bt.add_task(_analytics_insert_row, {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "ip_masked": _mask_ip(client_ip),
                "user_tier": tier,
                "status": 429,
                "flagged": False,
                "latency_ms": int((time.perf_counter() - start_ts) * 1000),
                "prompt_hash": _sha1(text or ""),
                "report_path": None,
                "customer_email": auth_ctx.get("customer_email"),
                "api_key_prefix": auth_ctx.get("api_key_prefix"),
            })
        
        return JSONResponse(error_payload, status_code=status)
    # ---------------------------------------

    # ---------- INPUT SIZE POLICY (soft cap with head/tail scan) ----------
    MAX_INPUT_CHARS = int(os.getenv("MAX_INPUT_CHARS", "50000"))   # total slice size
    HEAD_RATIO = 0.7                                               # 70% head, 30% tail

    txt = text or ""
    orig_len = len(txt)
    truncated = False

    if orig_len > MAX_INPUT_CHARS:
        head_n = int(MAX_INPUT_CHARS * HEAD_RATIO)
        tail_n = MAX_INPUT_CHARS - head_n
        head = txt[:head_n]
        tail = txt[-tail_n:] if tail_n > 0 else ""
        text = head + "\n...[TRUNCATED]...\n" + tail
        truncated = True
    else:
        text = txt
    # ---------- END INPUT SIZE POLICY ----------

    # 1) Start timer for rule-engine latency (ms)
    t0 = time.time()

    # 2) Run the rule scanner (compiled at startup)
    flags_raw, severity = scan_text_rules(text)
    # Collapse duplicates + prettify snippets for UI
    flags = aggregate_flags(flags_raw)

    # 3) Compute latency and include it in telemetry
    latency_ms = int((time.time() - t0) * 1000)
    try:
        log_event("scan_performed", {
            "length": len(text or ""),
            "severity": severity,
            "categories": sorted({f.get("category") for f in flags}),
            "latency_ms": latency_ms,
            "truncated": truncated,
            "original_length": orig_len,
            "scanned_length": len(text),
            "flags_count": len(flags),
            "matches_total": sum(f.get("match_count", 1) for f in flags),
        })
    except Exception:
        pass  # analytics should never break the API

    # 4) Slack alert (best-effort, non-blocking)
    try:
        if flags and _should_alert(severity):
            send_slack_alert(text=text, severity=severity, flags=flags, origin="scan")
    except Exception:
        pass

    # 5) Build response
    result = {
        "flagged": len(flags) > 0,
        "severity": severity,
        "flags": flags,
        "truncated": truncated,
        "original_length": orig_len,
        "scanned_length": len(text),
        "disclaimer": DISCLAIMER,
    }

    # --- analytics: record successful scan row (200) ---
    end_ms = int((time.perf_counter() - start_ts) * 1000)
    bt.add_task(_analytics_insert_row, {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "ip_masked": _mask_ip(client_ip),
        "user_tier": tier,
        "status": 200,
        "flagged": bool(result.get("flagged") or (result.get("severity","").lower() in ["high","medium"])),
        "latency_ms": end_ms,
        "prompt_hash": _sha1(text or ""),
        "report_path": result.get("report_path"),
        "customer_email": auth_ctx.get("customer_email"),
        "api_key_prefix": auth_ctx.get("api_key_prefix"),
    })

    return JSONResponse(result)
# <<< PATCH: REPLACE /scan ENDPOINT (END)


@app.get("/analytics")
def analytics_summary(days: int = 7):
    """
    JSON summary of recent usage, computed from in-memory events (ANALYTICS_EVENTS).

    Query params:
      - days (int, default 7): how many days back to include (bounded 1..30)

    Returns JSON like:
    {
      "window_days": 7,
      "totals": { "scans": 123, "checkout_intents": 5 },
      "by_severity": { "high": 10, "medium": 25, "low": 88 },
      "checkout_intents_by_plan": { "indie": 3, "lifetime": 2 },
      "series": [ {"date":"2025-10-01", "scans":3}, ..., {"date":"2025-10-07","scans":8} ]
    }

    Notes:
      - This is ZERO infra: data lives only in memory and resets on process restart.
      - Good enough for early GTM signal and local testing.
    """
    # ---- 1) Sanitize/limit the days parameter (avoid silly values) ----
    try:
        days = int(days)
    except Exception:
        days = 7
    days = max(1, min(days, 30))

    # ---- 2) Compute cutoff timestamp for the window ----
    cutoff = datetime.utcnow() - timedelta(days=days)

    # ---- 3) Filter events to the window and parse timestamps defensively ----
    recent = []  # list of tuples (ts_datetime, event_dict)
    for rec in list(ANALYTICS_EVENTS):  # copy to avoid mutation during iteration
        ts_str = rec.get("ts")
        if not ts_str:
            continue
        try:
            # Stored as "YYYY-MM-DDTHH:MM:SS.sssZ" — strip trailing 'Z' for fromisoformat
            ts = datetime.fromisoformat(ts_str.replace("Z", ""))
        except Exception:
            continue
        if ts >= cutoff:
            recent.append((ts, rec))

    # ---- 4) Aggregate into counters ----
    total_scans = 0
    severity_counter = Counter()      # e.g., {"high": 10, "medium": 5}
    checkout_counter = Counter()      # e.g., {"indie": 3, "lifetime": 2}
    daily_counter = Counter()         # e.g., {"2025-10-05": 8, ...}

    for ts, rec in recent:
        evt = (rec.get("event") or "").lower()
        props = rec.get("props", {}) or {}
        date_key = ts.strftime("%Y-%m-%d")

        if evt == "scan_performed":
            total_scans += 1
            sev = (props.get("severity") or "unknown").lower()
            severity_counter[sev] += 1
            daily_counter[date_key] += 1

        elif evt == "checkout_intent":
            plan = (props.get("plan") or "unknown").lower()
            checkout_counter[plan] += 1

        # You can extend with more events later (e.g., "feedback_received")

    # ---- 5) Build a continuous day-by-day series (even if zero scans) ----
    series = []
    # We include "days" days back up to today (inclusive)
    for i in range(days, -1, -1):
        d = (datetime.utcnow() - timedelta(days=i)).strftime("%Y-%m-%d")
        series.append({"date": d, "scans": int(daily_counter.get(d, 0))})

    # ---- 6) Return the summary JSON ----
    return JSONResponse({
        "window_days": days,
        "totals": {
            "scans": total_scans,
            "checkout_intents": int(sum(checkout_counter.values()))
        },
        "by_severity": dict(severity_counter),
        "checkout_intents_by_plan": dict(checkout_counter),
        "series": series
    })
@app.get("/analytics.html", response_class=HTMLResponse)
def analytics_html(x_admin_token: str = Header(None)):
    """
    Minimal HTML dashboard. Protected in Phase 4.
    """
    if ADMIN_TOKEN and x_admin_token != ADMIN_TOKEN:
        return HTMLResponse("<h1>401 Unauthorized</h1><p>Admin token required.</p>", status_code=401)

    return HTMLResponse("""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>QubitGrid™ — Analytics</title>
<style>
  :root{--bg:#0b1220;--fg:#e8eef6;--muted:#9aa7b8;--line:#233044;--accent:#0b5bd7}
  html,body{margin:0;background:var(--bg);color:var(--fg);font-family:Inter,system-ui,Segoe UI,Arial,sans-serif}
  .wrap{max-width:900px;margin:32px auto;padding:0 16px}
  h1{margin:0 0 12px}
  .card{background:#111827;border:1px solid var(--line);border-radius:14px;padding:16px;margin:12px 0}
  .row{display:flex;gap:12px;flex-wrap:wrap}
  .pill{display:inline-block;padding:4px 8px;border-radius:999px;border:1px solid var(--line);font-size:12px;color:#c6d1de}
  table{width:100%;border-collapse:collapse;margin-top:8px}
  th,td{border-bottom:1px solid var(--line);text-align:left;padding:8px 6px}
  a{color:#a7c5ff;text-decoration:none}
  .muted{color:var(--muted);font-size:12px}
  svg{width:100%;height:60px;background:#0d1116;border:1px solid var(--line);border-radius:8px}
</style>
</head>
<body>
  <div class="wrap">
    <h1>QubitGrid™ — Analytics</h1>
    <div class="muted">Simple live summary powered by <code>/analytics?days=7</code>. In-memory only.</div>

    <div class="card" id="totals">
      <div class="row">
        <div class="pill" id="p_scans">scans: —</div>
        <div class="pill" id="p_intents">checkout intents: —</div>
        <div class="pill" id="p_window">window: — days</div>
      </div>
      <div style="margin-top:12px">
        <svg id="spark" viewBox="0 0 300 60" preserveAspectRatio="none"></svg>
      </div>
    </div>

    <div class="card">
      <h3>Scans by severity</h3>
      <table id="sev"><thead><tr><th>severity</th><th>count</th></tr></thead><tbody></tbody></table>
    </div>

    <div class="card">
      <h3>Checkout intents by plan</h3>
      <table id="plan"><thead><tr><th>plan</th><th>count</th></tr></thead><tbody></tbody></table>
    </div>

    <div class="muted">QubitGrid™ provides pre-audit readiness tools only; not a certified audit. <a href="/roadmap">Back to Roadmap</a></div>
  </div>

<script>
(async function(){
  // 1) Fetch JSON summary
  // Need to pass the token from the parent page if possible, but for now this relies on the browser session or
  // simple unprotected generic analytics endpoint behavior (since /analytics JSON is public in Phase 4 plan, only HTML is gated).
  const res = await fetch('/analytics?days=7');
  if(!res.ok){ document.body.innerHTML = '<p style="padding:20px">Failed to load /analytics</p>'; return; }
  const data = await res.json();

  // 2) Totals / header pills
  document.getElementById('p_scans').textContent = 'scans: ' + (data.totals?.scans ?? 0);
  document.getElementById('p_intents').textContent = 'checkout intents: ' + (data.totals?.checkout_intents ?? 0);
  document.getElementById('p_window').textContent = 'window: ' + (data.window_days ?? 7) + ' days';

  // 3) Build severity table
  const sevBody = document.querySelector('#sev tbody');
  const sev = data.by_severity || {};
  const sevRows = Object.keys(sev).sort().map(k => `<tr><td>${k}</td><td>${sev[k]}</td></tr>`).join('');
  sevBody.innerHTML = sevRows || '<tr><td colspan="2">no data</td></tr>';

  // 4) Build checkout intents table
  const planBody = document.querySelector('#plan tbody');
  const plans = data.checkout_intents_by_plan || {};
  const planRows = Object.keys(plans).sort().map(k => `<tr><td>${k}</td><td>${plans[k]}</td></tr>`).join('');
  planBody.innerHTML = planRows || '<tr><td colspan="2">no data</td></tr>';

  // 5) Draw sparkline of daily scans
  // data.series = [{date:'YYYY-MM-DD', scans:n}, ...]
  const s = Array.isArray(data.series) ? data.series : [];
  const values = s.map(d => Number(d.scans||0));
  const svg = document.getElementById('spark');
  const W = 300, H = 60, P = 4; // width, height, padding
  svg.setAttribute('viewBox', `0 0 ${W} ${H}`);

  if(values.length === 0){
    svg.innerHTML = '<text x="8" y="34" fill="#9aa7b8" font-size="12">no data</text>';
    return;
  }

  const max = Math.max(1, ...values);
  const step = (W - 2*P) / Math.max(1, values.length - 1);
  let d = '';
  values.forEach((v, i) => {
    const x = P + i * step;
    const y = H - P - (v / max) * (H - 2*P);
    d += (i===0 ? 'M' : 'L') + x + ' ' + y + ' ';
  });

  svg.innerHTML = `
    <polyline fill="none" stroke="#5aa2ff" stroke-width="2" points="${
      values.map((v,i)=>{
        const x = P + i * step;
        const y = H - P - (v / max) * (H - 2*P);
        return x+','+y;
      }).join(' ')
    }"/>
  `;
})();
</script>
</body></html>""")

# >>> INSERT: ANALYTICS — ADMIN ENDPOINT (BEGIN)
from fastapi import Header, HTTPException

@app.get("/admin/usage")
def admin_usage(limit: int = 20, x_admin_token: str = Header(None)):
    """
    Admin-only: return recent scan rows from SQLite.
    Auth: send header X-Admin-Token matching ADMIN_TOKEN (from .env / Render).
    """
    # Simple header check
    if ADMIN_TOKEN and x_admin_token != ADMIN_TOKEN:
        raise HTTPException(status_code=401, detail="Unauthorized")

    # Clamp limit 1..200
    try:
        n = max(1, min(int(limit), 200))
    except Exception:
        n = 20

    with _db_connect() as conn:
        cur = conn.execute(
            "SELECT id, timestamp, ip_masked, user_tier, status, flagged, latency_ms "
            "FROM scan_logs ORDER BY id DESC LIMIT ?",
            (n,),
        )
        rows = [
            {
                "id": r[0],
                "timestamp": r[1],
                "ip_masked": r[2],
                "user_tier": r[3],
                "status": int(r[4]),
                "flagged": bool(r[5]),
                "latency_ms": int(r[6]) if r[6] is not None else None,
            }
            for r in cur.fetchall()
        ]
    return {"rows": rows, "count": len(rows)}

# --- NEW: USAGE BY KEY PREFIX ---
@app.get("/admin/key-usage")
def admin_key_usage(prefix: str, days: int = 7, x_admin_token: str = Header(None)):
    """
    Phase 4: Inspect usage for a specific API Key Prefix.
    """
    if ADMIN_TOKEN and x_admin_token != ADMIN_TOKEN:
        raise HTTPException(status_code=401, detail="Unauthorized")

    days = max(1, min(int(days), 90))
    cutoff = (datetime.utcnow() - timedelta(days=days)).isoformat()
    
    with _db_connect() as conn:
        # Aggregates
        cur = conn.execute(
            "SELECT status, user_tier, count(*) FROM scan_logs "
            "WHERE api_key_prefix = ? AND timestamp >= ? GROUP BY status, user_tier",
            (prefix, cutoff)
        )
        stats = cur.fetchall()
        
        total = 0
        by_status = Counter()
        by_tier = Counter()
        for st, tier, cnt in stats:
            total += cnt
            by_status[st] += cnt
            by_tier[tier] += cnt
            
        # Samples
        cur = conn.execute(
            "SELECT timestamp, user_tier, status, flagged, latency_ms FROM scan_logs "
            "WHERE api_key_prefix = ? AND timestamp >= ? "
            "ORDER BY id DESC LIMIT 50",
            (prefix, cutoff)
        )
        samples = [
            {
                "timestamp": r[0], 
                "user_tier": r[1], 
                "status": int(r[2]), 
                "flagged": bool(r[3]), 
                "latency_ms": r[4]
            }
            for r in cur.fetchall()
        ]

    return {
        "prefix": prefix,
        "window_days": days,
        "total_scans": total,
        "by_status": dict(by_status),
        "by_tier": dict(by_tier),
        "samples": samples
    }

# --- NEW: USAGE BY CUSTOMER EMAIL ---
@app.get("/admin/customer-usage")
def admin_customer_usage(email: str, days: int = 7, x_admin_token: str = Header(None)):
    """
    Phase 4: Inspect usage for a specific Customer Email.
    """
    if ADMIN_TOKEN and x_admin_token != ADMIN_TOKEN:
        raise HTTPException(status_code=401, detail="Unauthorized")

    days = max(1, min(int(days), 90))
    cutoff = (datetime.utcnow() - timedelta(days=days)).isoformat()
    
    with _db_connect() as conn:
        # Aggregates
        cur = conn.execute(
            "SELECT status, user_tier, api_key_prefix, count(*) FROM scan_logs "
            "WHERE customer_email = ? AND timestamp >= ? GROUP BY status, user_tier, api_key_prefix",
            (email, cutoff)
        )
        stats = cur.fetchall()
        
        total = 0
        by_status = Counter()
        by_tier = Counter()
        by_prefix = Counter()
        
        for st, tier, pfx, cnt in stats:
            total += cnt
            by_status[st] += cnt
            by_tier[tier] += cnt
            if pfx: by_prefix[pfx] += cnt
            
        # Samples
        cur = conn.execute(
            "SELECT timestamp, api_key_prefix, user_tier, status, flagged, latency_ms FROM scan_logs "
            "WHERE customer_email = ? AND timestamp >= ? "
            "ORDER BY id DESC LIMIT 50",
            (email, cutoff)
        )
        samples = [
            {
                "timestamp": r[0], 
                "api_key_prefix": r[1],
                "user_tier": r[2], 
                "status": int(r[3]), 
                "flagged": bool(r[4]), 
                "latency_ms": r[5]
            }
            for r in cur.fetchall()
        ]

    return {
        "email": email,
        "window_days": days,
        "total_scans": total,
        "by_status": dict(by_status),
        "by_tier": dict(by_tier),
        "by_key_prefix": dict(by_prefix),
        "samples": samples
    }

# <<< INSERT: ANALYTICS — ADMIN ENDPOINT (END)


# >>> SECTION A (BEGIN)
# ================================
# PDF REPORT ENDPOINT (Phase 1.5)
# ================================
from io import BytesIO                               # in-memory PDF stream
from fastapi.responses import StreamingResponse      # return PDF bytes
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas

# Ensure API_KEY exists for gating paid features
API_KEY = os.getenv("API_KEY", "").strip()

class ReportPayload(BaseModel):
    text: str = Field(..., description="Text to scan and include in PDF")
    title: Optional[str] = Field(None, description="Optional title shown on the report")
    client: Optional[str] = Field(None, description="Optional client label shown on the report")

def _auth_ok(authorization_hdr: str | None, x_api_key_hdr: str | None) -> bool:
    """
    Gatekeeper for paid endpoints.
    If API_KEY is defined, require either:
      Authorization: Bearer <API_KEY>  OR  X-API-Key: <API_KEY>
    If API_KEY is not set, allow local testing.
    """
    if not API_KEY:
        return True
    if authorization_hdr and authorization_hdr.strip() == f"Bearer {API_KEY}":
        return True
    if x_api_key_hdr and x_api_key_hdr.strip() == API_KEY:
        return True
    return False

@app.post("/report/pdf")
def create_pdf_report(
    request: Request,
    payload: ReportPayload,
    authorization: Optional[str] = Header(None),
    x_api_key: Optional[str] = Header(None),
):
    # Gate for paid tiers
    if not _auth_ok(authorization, x_api_key):
        # Keep wording clear for upgrades later
        raise HTTPException(status_code=402, detail="Paid feature. Provide a valid API key.")

    # Reuse the rule engine for a single scan
    flags_raw, severity = scan_text_rules(payload.text or "")
    flags = aggregate_flags(flags_raw)

    # Summaries for the report
    sev_counts = Counter([f.get("severity", "low") for f in flags])
    cat_counts = Counter([f.get("category", "misc") for f in flags])

    # Build PDF in memory
    buf = BytesIO()
    c = canvas.Canvas(buf, pagesize=LETTER)
    width, height = LETTER
    margin = 0.8 * inch
    y = height - margin

    def line(txt, sz=11, dy=14, bold=False):
        nonlocal y
        c.setFont("Helvetica-Bold" if bold else "Helvetica", sz)
        c.drawString(margin, y, txt)
        y -= dy

    # Header
    line("QubitGrid™ — Prompt Injection Scan Report", sz=14, dy=20, bold=True)
    if payload.title:
        line(f"Title: {payload.title}", sz=11, dy=14)
    if payload.client:
        line(f"Client: {payload.client}", sz=11, dy=14)

    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    line(f"Generated: {ts}", sz=10, dy=12)
    line(f"Overall Severity: {severity.upper()}", sz=11, dy=16, bold=True)
    line("Summary", sz=12, dy=16, bold=True)
    line(f"High: {sev_counts.get('high',0)}   Medium: {sev_counts.get('medium',0)}   Low: {sev_counts.get('low',0)}")

    # Categories
    if cat_counts:
        line("Categories", sz=12, dy=16, bold=True)
        for cat, n in cat_counts.most_common():
            line(f"• {cat}: {n}")

    # Findings table
    line("Findings", sz=12, dy=16, bold=True)
    if not flags:
        line("No rules matched in this scan.")
    else:
        for f in flags:
            rid = f.get("id","?")
            sev = f.get("severity","?")
            why = f.get("why","")
            snip = f.get("snippet","")
            # Item
            line(f"[{sev.upper()}] {rid}", sz=11, dy=14, bold=True)
            line(f"Reason: {why}", sz=10, dy=12)
            line(f"Snippet: {snip}", sz=10, dy=14)
            # New page if we run out of space
            if y < margin + 60:
                c.showPage()
                y = height - margin

    # Disclaimer footer
    c.setFont("Helvetica-Oblique", 9)
    c.drawString(margin, margin, DISCLAIMER)
    c.showPage()
    c.save()

    # Telemetry
    try:
        log_event("report_pdf_generated", {
            "severity": severity,
            "length": len(payload.text or ""),
            "flags": len(flags),
        })
    except Exception:
        pass

    buf.seek(0)
    filename = f"qubitgrid_report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pdf"
    return StreamingResponse(
        buf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )
# <<< INSERT: SECTION A (END)


# >>> INSERT: STRIPE CHECKOUT ENDPOINTS (BEGIN)
# =======================================
# STRIPE TEST CHECKOUT (Phase 1.5 revenue)
# - Uses two prices for Indie: ONE-TIME ($19.99) and SUBSCRIPTION ($9.99/mo)
# - Lifetime is a one-time ($199)
# =======================================
import stripe

# Read Stripe env vars (test mode)
STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY", "").strip()
STRIPE_PRICE_INDIE_ONE = os.getenv("STRIPE_PRICE_INDIE_ONE", "").strip()   # one-time $19.99
STRIPE_PRICE_INDIE_SUB = os.getenv("STRIPE_PRICE_INDIE_SUB", "").strip()   # monthly $9.99
STRIPE_PRICE_PRO = os.getenv("STRIPE_PRICE_PRO", "").strip()               # monthly $29.99
STRIPE_PRICE_LIFETIME  = os.getenv("STRIPE_PRICE_LIFETIME", "").strip()    # one-time $199
STRIPE_SUCCESS_URL = os.getenv("STRIPE_SUCCESS_URL", "http://127.0.0.1:8000/pricing").strip()
STRIPE_CANCEL_URL  = os.getenv("STRIPE_CANCEL_URL",  "http://127.0.0.1:8000/pricing").strip()


if STRIPE_SECRET_KEY:
    stripe.api_key = STRIPE_SECRET_KEY

class CheckoutReq(BaseModel):
    """Optional quantity for future multi-seat scenarios."""
    quantity: int | None = 1

def _stripe_ready(kind: str) -> tuple[bool, str]:
    """Ensure required env vars exist for the requested checkout flow."""
    if not STRIPE_SECRET_KEY:
        return False, "Missing STRIPE_SECRET_KEY"
    if kind == "indie_one" and not STRIPE_PRICE_INDIE_ONE:
        return False, "Missing STRIPE_PRICE_INDIE_ONE"
    if kind == "indie_sub" and not STRIPE_PRICE_INDIE_SUB:
        return False, "Missing STRIPE_PRICE_INDIE_SUB"
    if kind == "lifetime" and not STRIPE_PRICE_LIFETIME:
        return False, "Missing STRIPE_PRICE_LIFETIME"
    return True, ""

def _create_checkout(price_id: str, quantity: int, mode: str = "payment", metadata: dict = None) -> dict:
    """
    Create hosted Checkout Session in Stripe Test Mode.
    - mode='payment'      -> one-time (Indie ONE, Lifetime)
    - mode='subscription' -> recurring (Indie SUB)
    """
    session = stripe.checkout.Session.create(
        mode=mode,
        line_items=[{"price": price_id, "quantity": quantity or 1}],
        success_url=STRIPE_SUCCESS_URL + "?success=true&session_id={CHECKOUT_SESSION_ID}",
        cancel_url=STRIPE_CANCEL_URL + "?canceled=true",
        allow_promotion_codes=True,
        metadata=metadata or {},
    )
    # lightweight telemetry
    try:
        log_event("stripe_checkout_created", {"price": price_id, "qty": quantity or 1, "mode": mode, "meta": metadata})
    except Exception:
        pass
    return {"url": session.url}

# Indie ONE-TIME ($19.99)
@app.post("/buy/indie")
def buy_indie(body: CheckoutReq | None = None):
    ok, reason = _stripe_ready("indie_one")
    if not ok:
        raise HTTPException(status_code=501, detail=f"Stripe not configured: {reason}")
    try:
        return _create_checkout(
            STRIPE_PRICE_INDIE_ONE, 
            (body.quantity if body else 1), 
            mode="payment",
            metadata={"qg_tier": "Indie"}
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Stripe error: {str(e)}")

# Indie SUBSCRIPTION ($9.99/mo)
@app.post("/buy/indie-sub")
def buy_indie_sub(body: CheckoutReq | None = None):
    ok, reason = _stripe_ready("indie_sub")
    if not ok:
        raise HTTPException(status_code=501, detail=f"Stripe not configured: {reason}")
    try:
        return _create_checkout(
            STRIPE_PRICE_INDIE_SUB, 
            (body.quantity if body else 1), 
            mode="subscription",
            metadata={"qg_tier": "Indie"}
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Stripe error: {str(e)}")

# ==============================================
# STRIPE — PRO PLAN CHECKOUT
# ==============================================
@app.post("/buy/pro")
async def buy_pro():
    """Create Stripe checkout for Pro plan."""
    try:
        session = stripe.checkout.Session.create(
            payment_method_types=["card"],
            mode="subscription",
            line_items=[{
                "price": STRIPE_PRICE_PRO,  # make sure this exists in your .env
                "quantity": 1,
            }],
            success_url=STRIPE_SUCCESS_URL,
            cancel_url=STRIPE_CANCEL_URL,
            metadata={"qg_tier": "Pro"},
        )
        return {"url": session.url}
    except Exception as e:
        return JSONResponse({"detail": str(e)}, status_code=400)



# Lifetime ONE-TIME ($199)
@app.post("/buy/lifetime")
def buy_lifetime(body: CheckoutReq | None = None):
    ok, reason = _stripe_ready("lifetime")
    if not ok:
        raise HTTPException(status_code=501, detail=f"Stripe not configured: {reason}")
    try:
        return _create_checkout(
            STRIPE_PRICE_LIFETIME, 
            (body.quantity if body else 1), 
            mode="payment",
            metadata={"qg_tier": "Lifetime"}
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Stripe error: {str(e)}")
# <<< INSERT: STRIPE CHECKOUT ENDPOINTS (END)

# >>> INSERT: STRIPE WEBHOOK SKELETON (BEGIN)
# This route listens for Stripe's automatic event notifications (webhooks).
# It verifies authenticity, logs the raw event to SQLite for observability,
# and applies simple business updates to your Customer table.

from fastapi import Request, HTTPException
import stripe
import os

# Decide whether you're running locally or on Render
ENV = os.getenv("ENV", "DEV")  # defaults to DEV if ENV not set
if ENV.upper() == "DEV":
    STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET_LOCAL")
else:
    STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET")

def _log_webhook_event(event_type: str, customer_id: str, email: str, payload: dict):
    """Log raw Stripe webhook to DB for debugging/audit."""
    with _db_connect() as conn:
        try:
            conn.execute(
                "INSERT INTO webhook_events (ts, event_type, customer_id, email, payload) VALUES (?, ?, ?, ?, ?)",
                (
                    datetime.utcnow().isoformat() + "Z",
                    event_type,
                    customer_id,
                    email,
                    json.dumps(payload, ensure_ascii=False)[:5000],
                ),
            )
            conn.commit()
        except Exception as e:
            print("[STRIPE LOGGING ERROR]", e)

@app.post("/stripe/webhook")
async def stripe_webhook_listener(request: Request, background_tasks: BackgroundTasks):
    # 1) Verify signature
    payload = await request.body()
    sig_header = request.headers.get("stripe-signature")
    try:
        event = stripe.Webhook.construct_event(
            payload=payload,
            sig_header=sig_header,
            secret=STRIPE_WEBHOOK_SECRET,
        )
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid payload")
    except stripe.error.SignatureVerificationError:
        raise HTTPException(status_code=400, detail="Invalid signature")

    # 2) Basic fields
    event_type = event.get("type", "")
    data = (event.get("data") or {}).get("object") or {}

    # 3) Log every event to SQLite for observability
    try:
        customer_info = {}
        if isinstance(data, dict):
            customer_info = data.get("customer_details") or {}
        email = (
            customer_info.get("email")
            or data.get("receipt_email")
            or (data.get("billing_details") or {}).get("email")
            or ""
        )
        _log_webhook_event(
            event_type=event_type,
            customer_id=data.get("customer"),
            email=email,
            payload=event,
        )
        print(f"[DB] Logged Stripe event -> {event_type}")
    except Exception as e:
        print("[STRIPE LOGGING ERROR] Could not insert event:", repr(e))

    # 4) Lightweight business logic updates
    from models import SessionLocal, Customer, APIKey
    session = SessionLocal()
    try:
        if event_type == "checkout.session.completed":
            email = (data.get("customer_details") or {}).get("email")
            stripe_customer_id = data.get("customer")
            plan_mode = data.get("mode")  # "payment" or "subscription"
            
            # --- TIER RESOLUTION LOGIC ---
            # 1. Try server-controlled metadata
            meta = data.get("metadata") or {}
            tier_hint = meta.get("qg_tier")
            
            # 2. Canonical Tier List (must match PRICING_MODEL_CONTEXT.json)
            CANONICAL_TIERS = {"Indie", "Pro", "Lifetime", "Team", "Enterprise"}
            
            # 3. Resolve
            if tier_hint and tier_hint in CANONICAL_TIERS:
                canonical_tier = tier_hint
            else:
                # Fallback for legacy/unknown sessions
                if plan_mode == "subscription":
                    canonical_tier = "Indie"
                elif plan_mode == "payment":
                    canonical_tier = "Lifetime"
                else:
                    canonical_tier = "Free" # Should rarely happen in checkout flow

            if email:
                # Idempotent Upsert: Update if exists, else create.
                cust = session.query(Customer).filter_by(email=email).first()
                if not cust:
                    cust = Customer(
                        email=email,
                        tier=canonical_tier,
                        status="active",
                        stripe_customer_id=stripe_customer_id,
                    )
                    session.add(cust)
                else:
                    cust.status = "active"
                    cust.tier = canonical_tier
                    cust.stripe_customer_id = stripe_customer_id
                session.commit()
                # Note: This upsert is idempotent under Stripe retries because we always update the same Customer row by email.
                print(f"[DB] Customer {email} recorded as {cust.status} (Tier: {canonical_tier})")
                
                # --- API KEY GENERATION ---
                # 3.2 Idempotent API Key Creation
                PAID_TIERS = {"Indie", "Pro", "Lifetime", "Team", "Enterprise"}
                if canonical_tier in PAID_TIERS:
                    # Check if active key already exists for this email+plan
                    existing_key = session.query(APIKey).filter_by(
                        user_email=email, 
                        plan=canonical_tier, 
                        active=True
                    ).first()
                    
                    if not existing_key:
                        # Generate new key
                        plain_key = "qg_" + secrets.token_urlsafe(32)
                        key_hash = APIKey.hash_key(plain_key)
                        
                        new_key = APIKey(
                            user_email=email,
                            key_hash=key_hash,
                            plan=canonical_tier,
                            active=True,
                        )
                        session.add(new_key)
                        session.commit()
                        print(f"[APIKEY] Issued new key for {email} (tier={canonical_tier}, id={new_key.id})")
                        
                        # --- PHASE 7: EMAIL DELIVERY ---
                        # Send the PLAINTEXT key to the user immediately.
                        # This is the ONLY time we have access to it.
                        from utils.emailer import send_onboarding_email
                        background_tasks.add_task(send_onboarding_email, email, plain_key, canonical_tier)
                        print(f"[EMAIL] Queued onboarding email for {email}")
                        
                    else:
                        print(f"[APIKEY] Key already exists for {email} (tier={canonical_tier}) - skipping generation")

        elif event_type == "invoice.payment_failed":
            stripe_customer_id = data.get("customer")
            cust = session.query(Customer).filter_by(stripe_customer_id=stripe_customer_id).first()
            if cust:
                cust.status = "past_due"
                cust.grace_period_start = datetime.utcnow()
                session.commit()
                print(f"[DB] Customer {cust.email} marked past_due (Grace Period Started)")

        elif event_type == "invoice.payment_succeeded":
            stripe_customer_id = data.get("customer")
            cust = session.query(Customer).filter_by(stripe_customer_id=stripe_customer_id).first()
            if cust:
                cust.status = "active"
                cust.grace_period_start = None
                session.commit()
                print(f"[DB] Customer {cust.email} marked active (Grace Period Cleared)")

        elif event_type == "customer.subscription.deleted":
            stripe_customer_id = data.get("customer")
            cust = session.query(Customer).filter_by(stripe_customer_id=stripe_customer_id).first()
            if cust:
                cust.status = "canceled"
                cust.grace_period_start = None
                session.commit()
                print(f"[DB] Customer {cust.email} marked canceled")

        else:
            print(f"[STRIPE WEBHOOK] Ignored event type: {event_type}")

    except Exception as e:
        session.rollback()
        print("[STRIPE WEBHOOK ERROR]", e)
    finally:
        session.close()

    # 5) Always acknowledge receipt
    return {"status": "received", "event_type": event_type}
# <<< INSERT: STRIPE WEBHOOK SKELETON (END)

# -------------------------- BUY PAGES (TEST CHECKOUT) --------------------------
# Purpose:
# - Let interested users leave their email for two plans WITHOUT taking payment.
# - We capture intent -> log_event("checkout_intent", {...}), optionally Slack notify,
#   and also store via your feedback pipeline for later ML training / follow-up.

def _buy_page_html(plan_label: str, plan_code: str) -> str:
    """
    Helper that returns a small self-contained HTML page for the "buy" flow.
    Why a helper?
      - Keeps the two GET pages (indie/lifetime) tiny and consistent.
      - No external templates needed; $0 cost, easy to edit inline.
    """
    return f"""<!doctype html>
<html lang='en'>
<head>
<meta charset='utf-8'/><meta name='viewport' content='width=device-width, initial-scale=1'/>
<title>QubitGrid™ — {plan_label}</title>
<style>
  :root{{--bg:#0b1220;--fg:#e8eef6;--muted:#9aa7b8;--line:#233044;--accent:#0b5bd7}}
  html,body{{margin:0;background:var(--bg);color:var(--fg);font-family:Inter,system-ui,Segoe UI,Arial,sans-serif}}
  .wrap{{max-width:720px;margin:40px auto;padding:0 16px}}
  .card{{background:#111827;border:1px solid var(--line);border-radius:14px;padding:20px}}
  h1{{margin:4px 0 10px}} p{{color:var(--muted)}}
  label{{display:block;margin:12px 0 6px;font-size:13px;color:#c6d1de}}
  input{{width:100%;padding:10px;border-radius:10px;border:1px solid var(--line);background:#0d1116;color:var(--fg)}}
  .row{{display:flex;gap:10px;margin-top:14px;flex-wrap:wrap}}
  .btn{{padding:10px 14px;border-radius:10px;border:1px solid var(--line);font-weight:700;cursor:pointer;text-decoration:none;display:inline-block}}
  .primary{{background:var(--accent);color:#06121f}}
  .ghost{{background:#10151b;color:var(--fg)}}
  a{{color:#a7c5ff}}
  .foot{{margin-top:18px;font-size:12px;color:var(--muted)}}
</style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      <h1>{plan_label}</h1>
      <p>This is a <strong>non-charging test checkout</strong>. Enter your email and we’ll notify you when payment opens. Your interest helps prioritize the roadmap.</p>

      <!-- We POST to /buy/intent with a hidden plan code and the user's email -->
      <form method="post" action="/buy/intent">
        <input type="hidden" name="plan" value="{plan_code}">
        <label for="email">Email</label>
        <input id="email" name="email" type="email" required placeholder="you@company.com" autocomplete="email" />
        <div class="row">
          <button class="btn primary" type="submit">Notify me</button>
          <a class="btn ghost" href="/roadmap">Back to Roadmap</a>
        </div>
      </form>

      <div class="foot">QubitGrid™ provides pre-audit readiness tools only; not a certified audit.</div>
    </div>
  </div>
</body>
</html>"""

@app.get("/buy/lifetime", response_class=HTMLResponse)
def buy_lifetime_page():
    """GET page for Limited-Time Lifetime Access (test; no payments)."""
    return HTMLResponse(_buy_page_html("Limited-Time Lifetime Access — Test Checkout", "lifetime"))

@app.get("/buy/indie", response_class=HTMLResponse)
def buy_indie_page():
    """GET page for Indie Plan (test; no payments)."""
    return HTMLResponse(_buy_page_html("Indie Plan (2000 scans/day) — Test Checkout", "indie"))

@app.post("/buy/intent")
def buy_intent(plan: str = Form(...), email: str = Form(...)):
    """
    Form POST target. Captures interest (plan + email).
    We DO NOT charge here. We only log and notify so you can validate demand on $0 infra.
    """
    # 1) Minimal validation / normalization
    plan = (plan or "").strip().lower()
    email = (email or "").strip()

    # 2) Log analytics (this also pushes into the in-memory buffer via log_event)
    try:
        log_event("checkout_intent", {
            "plan": plan,
            "email": email,
            "source": "roadmap"
        })
    except Exception as e:
        print("[analytics] checkout_intent log failed:", e)

    # 3) Best-effort Slack alert (so you see it instantly in your Slack channel)
    try:
        send_slack_alert(
            text=f"🛒 checkout_intent • plan={plan} • email={email}",
            severity="info",
            flags=[],
            origin="checkout"
        )
    except Exception as e:
        print("slack alert error:", e)

    # 4) Save via your feedback dataset pipeline (reuses existing storage path)
    try:
        save_feedback_to_dataset({
            "email": email,
            "message": f"checkout_intent:{plan}",
            "meta": {"source": "checkout_widget", "ts": datetime.utcnow().isoformat() + "Z"}
        })
    except Exception as e:
        print("feedback save error:", e)

    # 5) Thank-you response (simple HTML)
    return HTMLResponse(f"""<!doctype html><html><head><meta charset="utf-8"><title>Thanks — QubitGrid</title></head>
    <body style="background:#0b1220;color:#e8eef6;font-family:Inter,system-ui,Segoe UI,Arial,sans-serif">
      <div style="max-width:720px;margin:40px auto;padding:20px;border-radius:14px;border:1px solid #233044;background:#111827">
        <h1>Thanks!</h1>
        <p>We recorded your interest for <strong>{plan}</strong>. We’ll email <strong>{email}</strong> when checkout opens.</p>
        <p><a href="/roadmap" style="color:#a7c5ff">Back to Roadmap</a></p>
        <p style="color:#9aa7b8;font-size:12px">QubitGrid™ provides pre-audit readiness tools only; not a certified audit.</p>
      </div>
    </body></html>""")
# ----------------------- END BUY PAGES (TEST CHECKOUT) ------------------------



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

@app.get("/roadmap", response_class=HTMLResponse)
def roadmap_page():
    """
    Serve the static Roadmap page.

    Why FileResponse/HTMLResponse?
    - We return the exact contents of roadmap.html from disk.
    - Keeping it as a plain file makes it easy to edit without touching Python.
    """
    file_path = pathlib.Path(__file__).parent / "roadmap.html"
    if file_path.exists():
        # FileResponse streams the file with correct headers; read_text also works,
        # but FileResponse is efficient and avoids manual content-type handling.
        return FileResponse(file_path)
    # Fallback message if the file is missing (helps in local dev)
    return HTMLResponse(
        "<h2>Roadmap not found</h2><p>Add <code>roadmap.html</code> next to <code>app.py</code>.</p>",
        status_code=404
    )


# =============================================================================
# Diagnostics for deploy checks
# - GET /__version returns a small text string for quick verification
# - GET /rules returns the compiled rule catalog (useful for debugging/UI)
# =============================================================================
APP_VERSION = "scanner-v0.3.3"




# --------------------- PRICING MODEL (authoritative source) -------------------
PRICING_MODEL_PATH = pathlib.Path(__file__).parent / "PRICING_MODEL_CONTEXT.json"

def _load_pricing_model() -> Dict[str, Any]:
    """
    Load the pricing/tier model from JSON on disk.
    This is the SINGLE SOURCE OF TRUTH for:
      - tier names, limits, feature flags
      - UI rendering notes (later)
      - upgrade gating (later)
      - Stripe/Gumroad product mapping (later)
    """
    try:
        with open(PRICING_MODEL_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
            # Light sanity checks (defensive)
            assert "tiers" in data and isinstance(data["tiers"], list)
            return data
    except Exception as e:
        # Fail-soft: if missing or invalid, run with empty model (but log loudly)
        print("[pricing] failed to load model:", e)
        return {"meta": {"version": "unknown"}, "tiers": []}

PRICING_MODEL = _load_pricing_model()

def _tier_by_name(name: str) -> Dict[str, Any]:
    """
    Helper: fetch a tier dict by its name (case-insensitive).
    Returns {} if not found.
    """
    name = (name or "").strip().lower()
    for t in PRICING_MODEL.get("tiers", []):
        if t.get("name", "").strip().lower() == name:
            return t
    return {}

def _free_daily_limit_from_model(default: int = 15) -> int:
    """
    Pull 'scan_limit_per_day' from the 'Free' tier in the pricing model.
    If absent or invalid, fall back to DEFAULT or env override.
    Env override: if FREE_DAILY_LIMIT is set, that wins (ops control).
    """
    # 1) Ops override wins
    env_override = os.getenv("FREE_DAILY_LIMIT")
    if env_override:
        try:
            return int(env_override)
        except Exception:
            pass

    # 2) Model value from 'Free' tier
    free = _tier_by_name("Free")
    try:
        val = int(free.get("scan_limit_per_day"))
        return max(1, val)
    except Exception:
        return default


# ----------------------------------------------------------------------------- 




@app.post("/rotate-key")
def rotate_api_key(request: Request):
    """
    Rotate API Key: Invalidate current key, issue new one.
    Auth: Bearer <OLD_API_KEY>
    """
    # 1. Authenticate (View-Only is sufficient to prove identity)
    error, ctx = _authenticate_view_only(request)
    if error:
        return JSONResponse(error, status_code=error.get("status_code", 401))

    old_hash = ctx["key_hash"]
    email = ctx["email"]
    plan = ctx["plan"]

    from models import SessionLocal, APIKey
    session = SessionLocal()
    try:
        # 2. Atomic Rotation
        # A. Invalidate old key
        old_record = session.query(APIKey).filter_by(key_hash=old_hash).first()
        if old_record:
            old_record.active = False
        
        # B. Generate new key
        new_raw = "qg_" + secrets.token_urlsafe(32)
        new_hash = APIKey.hash_key(new_raw)
        
        new_key = APIKey(
            user_email=email,
            key_hash=new_hash,
            plan=plan,
            active=True
        )
        session.add(new_key)
        session.commit()
        
        # 3. Clear Rate Limit Bucket for old key
        _PAID_LIMIT_BUCKET.pop(old_hash, None)
        
        # 4. Return new key (once)
        return {
            "new_key": new_raw,
            "masked": f"qg_{new_raw[:4]}...{new_raw[-4:]}",
            "plan": plan,
            "email": email
        }
    except Exception as e:
        session.rollback()
        return JSONResponse({"error": str(e)}, status_code=500)
    finally:
        session.close()

# >>> INSERT: USER DASHBOARD (BEGIN)
@app.get("/dashboard", response_class=HTMLResponse)
def user_dashboard(request: Request):
    """
    User Dashboard: View API Key stats, tier, and billing status.
    Auth: Bearer <API_KEY>
    """
    error, ctx = _authenticate_view_only(request)
    if error:
        # Simple error page
        return HTMLResponse(f"""
        <html><body style='background:#0b1220;color:#e8eef6;font-family:sans-serif;padding:40px;text-align:center'>
        <h2>Access Denied</h2>
        <p>{error.get('error')}</p>
        </body></html>
        """, status_code=error.get("status_code", 401))
    
    # Fetch usage stats (no side-effects)
    stats = _get_paid_usage_stats(ctx["key_hash"], ctx["plan"])
    
    # Render Dashboard
    return HTMLResponse(f"""<!doctype html>
<html lang='en'>
<head>
<meta charset='utf-8'/><meta name='viewport' content='width=device-width, initial-scale=1'/>
<title>QubitGrid™ — Dashboard</title>
<style>
  :root{{--bg:#0b1220;--fg:#e8eef6;--muted:#9aa7b8;--line:#233044;--accent:#0b5bd7;--success:#10b981;--danger:#ef4444}}
  html,body{{margin:0;background:var(--bg);color:var(--fg);font-family:Inter,system-ui,Segoe UI,Arial,sans-serif}}
  .wrap{{max-width:600px;margin:40px auto;padding:0 16px}}
  .card{{background:#111827;border:1px solid var(--line);border-radius:14px;padding:24px}}
  h1{{margin:0 0 4px;font-size:20px}} h2{{margin:0 0 16px;font-size:14px;color:var(--muted);font-weight:400}}
  .stat-row{{display:flex;justify-content:space-between;border-bottom:1px solid var(--line);padding:12px 0}}
  .stat-row:last-child{{border-bottom:none}}
  .label{{color:var(--muted);font-size:13px}}
  .value{{font-weight:600;font-size:14px}}
  .badge{{display:inline-block;padding:2px 8px;border-radius:99px;font-size:11px;font-weight:700;text-transform:uppercase}}
  .status-active{{background:rgba(16,185,129,0.2);color:var(--success)}}
  .status-inactive{{background:rgba(239,68,68,0.2);color:var(--danger)}}
  .key-box{{background:#0d1116;border:1px solid var(--line);padding:10px;border-radius:8px;font-family:monospace;font-size:13px;margin-bottom:20px;word-break:break-all;color:var(--accent)}}
  .links{{margin-top:20px;text-align:center;font-size:13px}}
  .btn-rotate{{background:var(--line);color:var(--fg);border:none;padding:8px 16px;border-radius:6px;cursor:pointer;font-size:12px;margin-top:10px;width:100%}}
  .btn-rotate:hover{{background:#2d3b4f}}
  .banner{{padding:12px;margin-bottom:16px;border-radius:6px;font-weight:600;text-align:center}}
  .banner.warning{{background:rgba(234,179,8,0.2);color:#fbbf24;border:1px solid rgba(234,179,8,0.3)}}
  .banner.danger{{background:rgba(239,68,68,0.2);color:#f87171;border:1px solid rgba(239,68,68,0.3)}}
  a{{color:var(--muted)}}
</style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      <h1>My Subscription</h1>
      <h2>{ctx['email']}</h2>
      
      <!-- PHASE 8: DASHBOARD BANNERS -->
      {'<div class="banner warning">⚠️ Payment Issue — You have ' + str(ctx["days_left"]) + ' days remaining before access pauses.</div>' if ctx["status"] == "past_due" and ctx["days_left"] is not None else ""}
      
      {'<div class="banner danger">⛔ Access Paused — Update billing to restore your API key.</div>' if ctx["status"] == "past_due" and ctx["days_left"] is None else ""}
      
      {'<div class="banner danger">❌ Subscription Canceled.</div>' if ctx["status"] == "canceled" else ""}
      
      <div id="key-box" class="key-box">{ctx['masked_key']}</div>
      <button id="rotate-btn" class="btn-rotate">🔄 Rotate API Key</button>
      
      <div class="stat-row" style="margin-top:20px">
        <span class="label">Plan Tier</span>
        <span class="value">{ctx['plan']}</span>
      </div>
      <div class="stat-row">
        <span class="label">Status</span>
        <span class="value"><span class="badge status-{ctx['status']}">{ctx['status']}</span></span>
      </div>
      <div class="stat-row">
        <span class="label">Daily Usage</span>
        <span class="value">{stats['count']} / {stats['limit']} scans</span>
      </div>
      <div class="stat-row">
        <span class="label">Remaining Today</span>
        <span class="value">{stats['remaining']}</span>
      </div>
      <div class="stat-row">
        <span class="label">Resets At</span>
        <span class="value">{stats['reset_utc']} UTC</span>
      </div>
    </div>
    <div class="links">
       <a href="/">Home</a> • <a href="/roadmap">Roadmap</a>
    </div>
  </div>
  <script>
    const btn = document.getElementById('rotate-btn');
    const keyBox = document.getElementById('key-box');
    
    // Simplest possible extraction of current Bearer token from browser logic?
    // Actually, we can't extract it from headers easily in JS if we just visited the page.
    // The USER has to provide it? No, if we visited via ?key=... or Header, the browser doesn't expose it.
    // WAIT: The spec says "Authenticated using existing valid API key".
    // If the user visited /dashboard via browser, how did they authenticate? 
    // They passed Authorization: Bearer <key> via a tool like Postman or a custom client?
    // A standard browser visit to /dashboard would prompt for Basic Auth or fail if we demand Bearer.
    // LIMITATION: HTML Dashboard currently assumes we can set headers.
    // FOR MVP: We assume the user creates a script or modifies headers.
    // But for the JS to work, it needs the key.
    // We will Prompt the user for their current key to confirm rotation?
    // OR we inject the key into the HTML (Risk!).
    // Spec says: "Dash rendering is read-only... Mod /dash HTML to include... fetch('/rotate-key', headers: {{Auth: Bearer + currentKey}})".
    // To satisfy spec without injecting plaintext, we prompt.
    
    btn.addEventListener('click', async () => {{
        const currentKey = prompt("Please confirm your CURRENT API Key to rotate it:");
        if (!currentKey) return;
        
        btn.disabled = true;
        btn.innerText = "Rotating...";
        
        try {{
            const res = await fetch('/rotate-key', {{
                method: 'POST',
                headers: {{ 'Authorization': 'Bearer ' + currentKey }}
            }});
            const data = await res.json();
            
            if (res.ok) {{
                keyBox.innerText = data.masked;
                alert("SUCCESS! \\n\\nYour NEW API Key is:\\n" + data.new_key + "\\n\\nSAVE THIS NOW. It will not be shown again.");
            }} else {{
                alert("Error: " + (data.error || res.statusText));
            }}
        }} catch (e) {{
            alert("Network Error");
        }}
        btn.disabled = false;
        btn.innerText = "🔄 Rotate API Key";
    }});
  </script>
</body>
</html>""")
# <<< INSERT: USER DASHBOARD (END)

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
# ---- Public pricing model (read-only) ----------------------------------------
# >>> INSERT: SERVE PRICING PAGE (BEGIN)
@app.get("/pricing", response_class=HTMLResponse)
async def serve_pricing_page(request: Request):
    """
    Serve the main index.html when user returns from Stripe.
    The frontend script reads ?status=success|cancel and shows the banner.
    """
    index_path = os.path.join(os.path.dirname(__file__), "index.html")
    with open(index_path, "r", encoding="utf-8") as f:
        html_content = f.read()
    return HTMLResponse(content=html_content, status_code=200)
# <<< INSERT: SERVE PRICING PAGE (END)





@app.get("/rules")
def list_rules():
    out = [
        {"id": rid, "category": cat, "severity": sev, "pattern": rx.pattern, "why": why}
        for (rid, cat, sev, rx, why) in _COMPILED
    ]
    return JSONResponse({"count": len(out), "rules": out})

# End of file
