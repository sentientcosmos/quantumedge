import requests
import json
import sqlite3
import os
import time
from datetime import datetime

# Configuration
WEBHOOK_URL = "http://127.0.0.1:8000/stripe/webhook"
DB_PATH = "analytics.db"

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def get_customer(email):
    conn = get_db_connection()
    cursor = conn.execute("SELECT * FROM customers WHERE email = ?", (email,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

def send_webhook(event_type, data):
    payload = {
        "id": "evt_test_" + os.urandom(4).hex(),
        "object": "event",
        "type": event_type,
        "data": {
            "object": data
        }
    }
    # In a real scenario, we'd need to sign this. 
    # For now, we assume the local dev environment might bypass signature checks 
    # or we need to mock the signature verification if we can't easily sign it.
    # However, the app verifies signatures. 
    # To bypass signature verification for this TEST script, we might usually mock it in the app code
    # OR we just rely on "stripe trigger" if we had the CLI.
    # Since we don't have the CLI installed in this environment, 
    # we might need to temporarily disable signature verification in app.py or use a mock library.
    
    # WAIT - The user prompt said: "Use Stripe CLI to forward webhooks: stripe listen..."
    # But I am an agent, I cannot install the CLI or run it if not there.
    # The prompt says: "Run the app locally: uvicorn app:app --reload"
    
    # If I cannot sign the request properly, the app will reject it (400 Invalid signature).
    # I will modify the script to Try interacting with the DB directly to simulate the logic 
    # OR I can try to use `stripe-python` to generate a signature if the secret is known.
    
    # Let's try sending it. If it fails, I might need to temporarily tweak `app.py` to allow unsigned webhooks ONLY for localhost/testing.
    # Actually, let's just create a test that IMPORTS the logic from app.py instead of making an HTTP request?
    # That avoids the networking/signature complexity entirely.
    pass

# BETTER APPROACH: Unit Test style verification by importing the logic.
# This avoids needing a running server and valid Stripe signatures.

import sys
sys.path.append(os.getcwd())
# We need to mock 'stripe' and 'models' behavior if we run this as a standalone script
# But we can just import the relevant parts or simpler: 
# We can use the 'client' from FastAPI TestClient!

from fastapi.testclient import TestClient

# PATCH: Ensure stripe.error exists BEFORE importing app
import stripe
import sys
from unittest.mock import MagicMock

# Create a mock for stripe.error if it doesn't exist
if not hasattr(stripe, "error"):
    stripe.error = MagicMock()
    stripe.error.SignatureVerificationError = Exception

# Mock Webhook construction to bypass verification
def mock_construct_event(*args, **kwargs):
    # Determine payload from args or kwargs
    payload = kwargs.get("payload")
    if not payload and len(args) > 0:
        payload = args[0]
    return json.loads(payload)

stripe.Webhook.construct_event = MagicMock(side_effect=mock_construct_event)

from app import app
from models import init_db, SessionLocal, Customer

# Initialize DB
init_db()

client = TestClient(app)

def run_test():
    print("--- Starting Verification ---")
    
    # Test 1: Indie via Metadata
    email_indie = f"test_indie_{os.urandom(4).hex()}@example.com"
    cust_indie = f"cus_indie_{os.urandom(4).hex()}"
    print(f"Testing Indie upsert for {email_indie}...")
    
    payload_indie = {
        "id": "evt_test_1",
        "type": "checkout.session.completed",
        "data": {
            "object": {
                "customer_details": {"email": email_indie},
                "customer": cust_indie,
                "mode": "subscription",
                "metadata": {"qg_tier": "Indie"} 
            }
        }
    }
    
    resp = client.post("/stripe/webhook", json=payload_indie, headers={"stripe-signature": "test"})
    if resp.status_code != 200:
        print(f"[FAIL] Webhook returned {resp.status_code}: {resp.text}")
        return

    # Check DB
    cust = get_customer(email_indie)
    if cust and cust['tier'] == 'Indie' and cust['status'] == 'active':
        print("[PASS] Indie Test Passed")
    else:
        print(f"[FAIL] Indie Test Failed: {cust}")

    # Test 2: Pro via Metadata
    email_pro = f"test_pro_{os.urandom(4).hex()}@example.com"
    cust_pro = f"cus_pro_{os.urandom(4).hex()}"
    print(f"Testing Pro upsert for {email_pro}...")
    
    payload_pro = {
        "id": "evt_test_2",
        "type": "checkout.session.completed",
        "data": {
            "object": {
                "customer_details": {"email": email_pro},
                "customer": cust_pro,
                "mode": "subscription",
                "metadata": {"qg_tier": "Pro"} 
            }
        }
    }
    
    resp = client.post("/stripe/webhook", json=payload_pro, headers={"stripe-signature": "test"})
    cust = get_customer(email_pro)
    if cust and cust['tier'] == 'Pro' and cust['status'] == 'active':
        print("[PASS] Pro Test Passed")
    else:
        print(f"[FAIL] Pro Test Failed: {cust}")

    # Test 3: Fallback Logic (Legacy Subscription -> Indie)
    email_legacy = f"test_legacy_{os.urandom(4).hex()}@example.com"
    cust_legacy = f"cus_legacy_{os.urandom(4).hex()}"
    print(f"Testing Fallback upsert for {email_legacy}...")
    
    payload_legacy = {
        "id": "evt_test_3",
        "type": "checkout.session.completed",
        "data": {
            "object": {
                "customer_details": {"email": email_legacy},
                "customer": cust_legacy,
                "mode": "subscription",
                "metadata": {} # NO METADATA
            }
        }
    }
    
    resp = client.post("/stripe/webhook", json=payload_legacy, headers={"stripe-signature": "test"})
    cust = get_customer(email_legacy)
    if cust and cust['tier'] == 'Indie': # Should normalize to "Indie" (Title Case)
        print("[PASS] Fallback Test Passed (normalized to Indie)")
    else:
        print(f"[FAIL] Fallback Test Failed: {cust}")

    # Test 4: Idempotency (Repeat Pro Test)
    print("Testing Idempotency (repeating Pro webhook)...")
    resp = client.post("/stripe/webhook", json=payload_pro, headers={"stripe-signature": "test"})
    cust = get_customer(email_pro)
    
    # We can check row count to be sure no duplicates
    conn = get_db_connection()
    count = conn.execute("SELECT COUNT(*) FROM customers WHERE email = ?", (email_pro,)).fetchone()[0]
    conn.close()
    
    if count == 1 and cust['tier'] == 'Pro':
        print("[PASS] Idempotency Test Passed")
    else:
        tier_actual = cust.get('tier') if cust else 'None'
        print(f"[FAIL] Idempotency Test Failed. Count={count}, Tier={tier_actual}")

if __name__ == "__main__":
    try:
        run_test()
    except Exception as e:
        print(f"Test crashed: {e}")
