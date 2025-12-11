import os
import secrets
import time
from datetime import datetime
from fastapi.testclient import TestClient
from app import app, _PAID_LIMIT_BUCKET
from models import init_db, SessionLocal, APIKey

client = TestClient(app)

def setup_keys():
    init_db()
    session = SessionLocal()
    
    # Clean up old test data
    session.query(APIKey).filter(APIKey.user_email.like("test_auth_%")).delete()
    session.commit()
    
    # 1. Create Indie Key (Limit 1000)
    indie_raw = "qg_" + secrets.token_urlsafe(32)
    indie_key = APIKey(
        user_email="test_auth_indie@example.com",
        key_hash=APIKey.hash_key(indie_raw),
        plan="Indie",
        active=True
    )
    
    # 2. Create Revoked Key
    revoked_raw = "qg_" + secrets.token_urlsafe(32)
    revoked_key = APIKey(
        user_email="test_auth_revoked@example.com",
        key_hash=APIKey.hash_key(revoked_raw),
        plan="Pro",
        active=False
    )
    
    session.add_all([indie_key, revoked_key])
    session.commit()
    session.close()
    
    return indie_raw, revoked_raw

def run_tests():
    print("--- Starting /scan Auth Verification ---")
    indie_token, revoked_token = setup_keys()
    
    # Test 1: Anonymous (Free Tier IP Limit)
    print("\nTest 1: Anonymous (Free Tier)")
    # Reset bucket for this test context if possible or just rely on high limit
    # We expect 200 OK and "Free" tier analytics (we can't easily check analytics here without mocking)
    # Just check status code.
    resp = client.get("/scan?text=hello_world")
    if resp.status_code == 200:
        print("PASS: Anonymous allowed")
    else:
        print(f"FAIL: Anonymous blocked {resp.status_code}")

    # Test 2: Admin Bypass
    print("\nTest 2: Admin Bypass")
    # We need to know the API_KEY from env.
    admin_key = os.getenv("API_KEY")
    if admin_key:
        resp = client.get("/scan?text=admin_test", headers={"Authorization": f"Bearer {admin_key}"})
        if resp.status_code == 200:
            print("PASS: Admin allowed")
        else:
            print(f"FAIL: Admin blocked {resp.status_code}")
    else:
        print("SKIP: API_KEY env var not set")

    # Test 3: Valid Indie Key
    print("\nTest 3: Valid Paid Key (Indie)")
    resp = client.get("/scan?text=indie_test", headers={"Authorization": f"Bearer {indie_token}"})
    if resp.status_code == 200:
        print("PASS: Indie Key allowed")
    elif resp.status_code == 429:
        print("FAIL: Indie Key Rate Limited prematurely")
    else:
        print(f"FAIL: Indie Key Error {resp.status_code} {resp.text}")

    # Test 4: Revoked Key
    print("\nTest 4: Revoked Key")
    resp = client.get("/scan?text=revoked", headers={"Authorization": f"Bearer {revoked_token}"})
    if resp.status_code == 401:
        print("PASS: Revoked Key blocked (401)")
    else:
        print(f"FAIL: Revoked Key yielded {resp.status_code}")

    # Test 5: Invalid Key
    print("\nTest 5: Invalid Key")
    resp = client.get("/scan?text=invalid", headers={"Authorization": "Bearer qg_invalid_token_123"})
    if resp.status_code == 401:
        print("PASS: Invalid Key blocked (401)")
    else:
        print(f"FAIL: Invalid Key yielded {resp.status_code}")
        
    print("\n--- Verification Complete ---")

if __name__ == "__main__":
    run_tests()
