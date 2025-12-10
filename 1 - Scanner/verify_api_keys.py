import json
import sqlite3
import os
import sys
from fastapi.testclient import TestClient
from unittest.mock import MagicMock
import stripe

# PATCH: Ensure stripe.error exists BEFORE importing app
if not hasattr(stripe, "error"):
    stripe.error = MagicMock()
    stripe.error.SignatureVerificationError = Exception

# Mock Webhook construction to bypass verification
def mock_construct_event(*args, **kwargs):
    payload = kwargs.get("payload")
    if not payload and len(args) > 0:
        payload = args[0]
    return json.loads(payload)

stripe.Webhook.construct_event = MagicMock(side_effect=mock_construct_event)

from app import app
from models import init_db, SessionLocal, Customer, APIKey

# Initialize DB
init_db()

client = TestClient(app)

def get_api_key(email, plan):
    session = SessionLocal()
    key = session.query(APIKey).filter_by(user_email=email, plan=plan).first()
    session.close()
    return key

def run_test():
    print("--- Starting API Key Verification ---")
    
    # Test 1: Indie Tier (Expect Key)
    email_indie = f"apikey_indie_{os.urandom(4).hex()}@example.com"
    cust_indie = f"cus_indie_{os.urandom(4).hex()}"
    print(f"Testing Indie Key Gen for {email_indie}...")
    
    payload_indie = {
        "id": "evt_test_indie",
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
    print(f"Response ({resp.status_code}): {resp.text}", flush=True)
    
    key = get_api_key(email_indie, "Indie")
    if key and key.active and key.key_hash:
        print(f"[PASS] Indie Key Generated: ID={key.id}")
    else:
        print(f"[FAIL] Indie Key Failed: {key}")

    # Test 2: Idempotency (Repeat Indie Webhook - Expect NO new key)
    print("Testing Idempotency (Repeat Indie)...")
    # Capture current ID
    original_id = key.id if key else None
    
    client.post("/stripe/webhook", json=payload_indie, headers={"stripe-signature": "test"})
    
    session = SessionLocal()
    count = session.query(APIKey).filter_by(user_email=email_indie, plan="Indie").count()
    key_again = session.query(APIKey).filter_by(user_email=email_indie, plan="Indie").first()
    session.close()

    if count == 1 and key_again.id == original_id:
        print("[PASS] Idempotency Passed: Count is 1, ID is same")
    else:
        new_id = key_again.id if key_again else 'None'
        print(f"[FAIL] Idempotency Failed: Count={count}, NewID={new_id} (Old={original_id})")

    # Test 3: Free Tier (Expect NO Key)
    email_free = f"apikey_free_{os.urandom(4).hex()}@example.com"
    cust_free = f"cus_free_{os.urandom(4).hex()}"
    print(f"Testing Free Tier (No Key) for {email_free}...")
    
    payload_free = {
        "id": "evt_test_free",
        "type": "checkout.session.completed",
        "data": {
            "object": {
                "customer_details": {"email": email_free},
                "customer": cust_free,
                "mode": "payment",
                "metadata": {"qg_tier": "Free"} 
            }
        }
    }
    
    client.post("/stripe/webhook", json=payload_free, headers={"stripe-signature": "test"})
    
    key_free = get_api_key(email_free, "Free")
    if key_free is None:
        print("[PASS] Free Tier Passed (No Key)")
    else:
        print(f"[FAIL] Free Tier Failed: Key found {key_free}")

    # Test 4: Pro Tier (Expect Key)
    email_pro = f"apikey_pro_{os.urandom(4).hex()}@example.com"
    cust_pro = f"cus_pro_{os.urandom(4).hex()}"
    print(f"Testing Pro Key Gen for {email_pro}...")

    payload_pro = {
        "id": "evt_test_pro",
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
    
    client.post("/stripe/webhook", json=payload_pro, headers={"stripe-signature": "test"})
    key_pro = get_api_key(email_pro, "Pro")
    if key_pro and key_pro.active:
         print(f"[PASS] Pro Key Generated: ID={key_pro.id}")
    else:
         print(f"[FAIL] Pro Key Failed: {key_pro}")

if __name__ == "__main__":
    try:
        run_test()
    except Exception as e:
        print(f"Test crashed: {e}")
