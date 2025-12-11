import secrets
import sys
from fastapi.testclient import TestClient
from app import app, _PAID_LIMIT_BUCKET
from models import SessionLocal, APIKey, Customer

# Setup client
client = TestClient(app)

def run():
    print("--- Starting Rotation Verification ---")
    
    # Generate unique test data
    suffix = secrets.token_hex(4)
    email = f"rot_{suffix}@test.com"
    raw_key = "qg_" + secrets.token_hex(16)
    key_hash = APIKey.hash_key(raw_key)

    # Database Setup
    session = SessionLocal()
    try:
        # Create Customer
        cust = Customer(email=email, stripe_customer_id=f"cus_{suffix}", tier="Pro", status="active")
        session.add(cust)
        
        # Create APIKey
        ak = APIKey(user_email=email, key_hash=key_hash, plan="Pro", active=True)
        session.add(ak)
        
        session.commit()
    except Exception as e:
        print(f"Setup Error: {e}")
        return
    finally:
        session.close()

    # Test Rotation
    print(f"1. Rotating key for {email}...")
    resp = client.post("/rotate-key", headers={"Authorization": f"Bearer {raw_key}"})
    
    if resp.status_code != 200:
        print(f"FAILED to rotate: {resp.status_code} {resp.text}")
        return
    
    data = resp.json()
    new_key = data.get("new_key")
    if not new_key:
        print("FAILED: No new_key in response")
        return
        
    print(f"   Success. New key: {new_key[:8]}...")

    # Verification 1: Old key dead?
    print("2. Checking OLD key is dead...")
    resp_old = client.get("/dashboard", headers={"Authorization": f"Bearer {raw_key}"})
    if resp_old.status_code == 401:
        print("   PASS: Old key rejected.")
    else:
        print(f"   FAIL: Old key returned {resp_old.status_code}")

    # Verification 2: New key works?
    print("3. Checking NEW key is alive...")
    resp_new = client.get("/dashboard", headers={"Authorization": f"Bearer {new_key}"})
    if resp_new.status_code == 200:
         print("   PASS: New key accepted.")
    else:
         print(f"   FAIL: New key returned {resp_new.status_code}")

    print("--- Verification Complete ---")

if __name__ == "__main__":
    run()
