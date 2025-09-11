from fastapi import Header, HTTPException  # add to your FastAPI imports
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any, Tuple
from datetime import datetime
import os, json, pathlib

from fastapi import FastAPI, Query
from fastapi.responses import JSONResponse

app = FastAPI(title="QubitGrid Prompt Injection Scanner")

# very simple rule set to start
BLOCKLIST = [
    "ignore all instructions",
    "disregard previous instructions",
    "reveal system prompt",
    "act as developer mode",
    "jailbreak",
    "sudo",
]

DISCLAIMER = "QubitGrid™ provides pre-audit readiness tools only; not a certified audit."

def log_event(event_name: str, props: Dict[str, Any]) -> None:
    ts = datetime.utcnow().isoformat() + "Z"
    print(f"[analytics] {{'ts':'{ts}','event':'{event_name}','props':{props}}}")

@app.get("/scan")
def scan(text: str = Query(..., description="Text to scan for prompt injection")):
    lowered = text.lower()
    hits = [p for p in BLOCKLIST if p in lowered]
    result = {
        "flagged": len(hits) > 0,
        "matches": hits,
        "disclaimer": DISCLAIMER,
    }
    return JSONResponse(result)

class BatchReportInput(BaseModel):
    texts: List[str] = Field(..., description="Batch of texts to scan")

class BatchReportItem(BaseModel):
    index: int
    flags: List[Dict[str, Any]]
    severity: str

class BatchReportOut(BaseModel):
    items: List[BatchReportItem]
    summary: Dict[str, int]
    disclaimer: str

def _check_api_key(provided_key: Optional[str]) -> None:
    expected = os.getenv("API_KEY")
    if expected and provided_key != expected:
        raise HTTPException(status_code=403, detail="Forbidden. Valid API key required.")

@app.post("/report", response_model=BatchReportOut)
def report(payload: BatchReportInput, x_api_key: Optional[str] = Header(None)):
    _check_api_key(x_api_key)

    def scan_text(t: str) -> Tuple[List[Dict[str, Any]], str]:
        lowered = (t or "").lower()
        flags = []
        # reuse your existing patterns in a simple way
        for p in [
            "ignore all instructions",
            "disregard previous instructions",
            "reveal system prompt",
            "act as developer mode",
            "jailbreak",
            "sudo",
        ]:
            if p in lowered:
                flags.append({"pattern": p})
        severity = "high" if any("reveal system prompt" in f["pattern"] for f in flags) else ("medium" if flags else "low")
        return flags, severity

    items: List[BatchReportItem] = []
    counts = {"low": 0, "medium": 0, "high": 0}

    for i, t in enumerate(payload.texts):
        flags, severity = scan_text(t)
        items.append(BatchReportItem(index=i, flags=flags, severity=severity))
        counts[severity] += 1

    try:
        log_event("batch_scan_performed", {"batch_size": len(payload.texts)})
    except Exception:
        pass

    return {"items": items, "summary": counts, "disclaimer": DISCLAIMER}

DATASETS_DIR = pathlib.Path(__file__).parent / "datasets"
DATASETS_DIR.mkdir(exist_ok=True)

class FeedbackInput(BaseModel):
    text: str
    label: str  # "safe" | "unsafe"
    reason: Optional[str] = None

@app.post("/feedback")
def feedback(item: FeedbackInput, x_api_key: Optional[str] = Header(None)):
    _check_api_key(x_api_key)
    if item.label not in ("safe", "unsafe"):
        raise HTTPException(status_code=400, detail="label must be 'safe' or 'unsafe'")

    rec = {
        "text": item.text,
        "label": item.label,
        "reason": item.reason,
        "source": "feedback",
        "ts": datetime.utcnow().isoformat() + "Z",
    }
    with open(DATASETS_DIR / "scanner.jsonl", "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    try:
        log_event("feedback_received", {"label": item.label})
    except Exception:
        pass

    return {"ok": True, "disclaimer": DISCLAIMER}

from fastapi.responses import HTMLResponse  # <-- this is safe to repeat; FastAPI ignores duplicates

@app.get("/", response_class=HTMLResponse)
def home():
    # A minimal HTML page with a textarea and a Scan button
    return """
    <html>
      <head>
        <title>QuantumEdge Prompt Scanner</title>
        <meta charset="utf-8" />
      </head>
      <body style="font-family: sans-serif; max-width: 720px; margin: 2rem auto;">
        <h2>QuantumEdge: Prompt Injection Scanner</h2>
        <form action="/scan" method="get">
          <textarea name="text" rows="8" style="width:100%;" placeholder="Paste a prompt to scan..."></textarea>
          <br><br>
          <button type="submit">Scan</button>
        </form>
        <p style="margin-top:1rem; color:#666;">
          Automated pre-audit readiness tool. Advisory insights only. Not a certification.
        </p>
<p style="margin-top:1.5rem;">
  <a href="https://buy.stripe.com/test_YOUR_LINK" target="_blank"
     style="background:#635bff;color:white;padding:10px 16px;border-radius:6px;text-decoration:none;">
     Buy Early Access (Test)
  </a>
</p>
      </body>
    </html>
    """
