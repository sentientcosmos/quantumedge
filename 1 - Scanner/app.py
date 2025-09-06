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
      </body>
    </html>
    """
