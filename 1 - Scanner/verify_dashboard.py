import os
import sys
import secrets
import hashlib
from fastapi.testclient import TestClient
from app import app, _PAID_LIMIT_BUCKET
from models import SessionLocal, APIKey, Customer

client = TestClient(app)

def verify_dashboard():
    print("--- Starting User Dashboard Verification ---\n")
    
    # 1. Setup: Create a paid user and API key
    session = SessionLocal()
    email = f"dash_test_{secrets.token_hex(4)}@example.com"
    raw_key = "qg_" + secrets.token_hex(16)
    key_hash = APIKey.hash_key(raw_key)
    
    print(f"1. Setting up test user: {email}")
    try:
        # Create Customer
        cust = Customer(email=email, stripe_customer_id="cus_dash_test", tier="Pro", status="active")
        session.add(cust)
        session.commit()
        
        # Create API Key
        new_key = APIKey(
            user_email=email,
            key_hash=key_hash,
            plan="Pro",
            active=True
        )
        session.add(new_key)
        session.commit()
        
        # Determine Limit (Pro = 100 by default, check your PRICING_MODEL_CONTEXT or app fallback)
        # Using app logic directly or assuming defaults.
        
    except Exception as e:
        print(f"❌ Setup failed: {e}")
        return
    finally:
        session.close()

    # 2. Test: Access Dashboard (Should see 200 OK and HTML)
    print("2. GET /dashboard with valid key")
    resp = client.get("/dashboard", headers={"Authorization": f"Bearer {raw_key}"})
    if resp.status_code == 200:
        if "My Subscription" in resp.text and email in resp.text:
            print("✅ Dashboard loaded successfully (Found email and headers)")
        else:
            print(f"❌ Dashboard loaded but content missing: {resp.text[:100]}...")
    else:
        print(f"❌ Dashboard failed: {resp.status_code} {resp.text}")

    # 3. Test: View-Only Check (Should NOT increment usage)
    # Check internal bucket BEFORE
    entry = _PAID_LIMIT_BUCKET.get(key_hash)
    count_before = entry["count"] if entry else 0
    print(f"3. Usage check: Count before = {count_before}")
    
    # Reload dashboard
    client.get("/dashboard", headers={"Authorization": f"Bearer {raw_key}"})
    
    entry_after = _PAID_LIMIT_BUCKET.get(key_hash)
    count_after = entry_after["count"] if entry_after else 0
    print(f"   Usage check: Count after  = {count_after}")
    
    if count_after == count_before:
        print("✅ Dashboard did NOT increment usage count.")
    else:
        print(f"❌ Dashboard INCREMENTED usage count! ({count_before} -> {count_after})")

    # 4. Test: Admin Token Rejection
    print("4. Testing Admin Token Rejection")
    admin_token = os.getenv("ADMIN_TOKEN", "dev-local-admin")
    resp = client.get("/dashboard", headers={"Authorization": f"Bearer {admin_token}"})
    if resp.status_code == 403 or resp.status_code == 401:
        print(f"✅ Admin token correctly rejected (Status {resp.status_code})")
    else:
        print(f"❌ Admin token was ALLOWED? Status {resp.status_code}")

    print("\n--- Dashboard Verification Complete ---")

if __name__ == "__main__":
    verify_dashboard()
