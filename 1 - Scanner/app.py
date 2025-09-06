from fastapi import FastAPI, Query
from fastapi.responses import JSONResponse

app = FastAPI(title="QuantumEdge Prompt Injection Scanner")

# very simple rule set to start
BLOCKLIST = [
    "ignore all instructions",
    "disregard previous instructions",
    "reveal system prompt",
    "act as developer mode",
    "jailbreak",
    "sudo",
]

DISCLAIMER = "Automated pre-audit readiness tool. Advisory insights only. Not a certification."

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
