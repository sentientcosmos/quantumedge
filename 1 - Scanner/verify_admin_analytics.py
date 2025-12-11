import os
import secrets
import time
from datetime import datetime, timedelta
from fastapi.testclient import TestClient
from app import app, _analytics_init, _db_connect
from models import init_db, SessionLocal, APIKey, Customer

client = TestClient(app)

def setup_db_and_keys():
    # Force schema update
    _analytics_init()
    
    # Clean previous test data from SQLite
    with _db_connect() as conn:
        conn.execute("DELETE FROM scan_logs WHERE customer_email LIKE 'test_admin_%'")
        conn.commit()
        
    session = SessionLocal()
    # Clean up models
    session.query(APIKey).filter(APIKey.user_email.like("test_admin_%")).delete()
    session.query(Customer).filter(Customer.email.like("test_admin_%")).delete()
    session.commit()
    
    # Create Indie Key
    indie_raw = "qg_" + secrets.token_urlsafe(32)
    indie_key = APIKey(
        user_email="test_admin_indie@example.com",
        key_hash=APIKey.hash_key(indie_raw),
        plan="Indie",
        active=True
    )
    
    # Create Pro Key
    pro_raw = "qg_" + secrets.token_urlsafe(32)
    pro_key = APIKey(
        user_email="test_admin_pro@example.com",
        key_hash=APIKey.hash_key(pro_raw),
        plan="Pro",
        active=True
    )
    
    session.add_all([indie_key, pro_key])
    session.commit()
    session.close()
    
    return indie_raw, pro_raw

def run_tests():
    print("--- Starting Admin Analytics verification ---")
    indie_token, pro_token = setup_db_and_keys()
    admin_token = os.getenv("ADMIN_TOKEN", "dev-local-admin")
    
    # 1. Generate Traffic
    # Free
    client.get("/scan?text=free_scan_1")
    # Admin via Env
    env_key = os.getenv("API_KEY")
    if env_key:
        client.get("/scan?text=admin_scan_1", headers={"Authorization": f"Bearer {env_key}"})
    # Paid Indie
    client.get("/scan?text=indie_scan_1", headers={"Authorization": f"Bearer {indie_token}"})
    client.get("/scan?text=indie_scan_2", headers={"Authorization": f"Bearer {indie_token}"})
    # Paid Pro
    client.get("/scan?text=pro_scan_1", headers={"Authorization": f"Bearer {pro_token}"})
    
    # Sleep briefly to ensure async write
    time.sleep(1.0)
    
    # 2. Verify /admin/usage (Generic)
    print("\n[Test] /admin/usage")
    resp = client.get("/admin/usage", headers={"X-Admin-Token": admin_token})
    if resp.status_code == 200:
        data = resp.json()
        print(f"PASS: Got {data['count']} rows")
    else:
        print(f"FAIL: {resp.status_code}")

    # 3. Verify /admin/key-usage
    print("\n[Test] /admin/key-usage (Indie Key)")
    # Get hash prefix from token
    # We need to replicate the hashing logic validly or just query DB to get prefix
    from models import APIKey
    indie_hash = APIKey.hash_key(indie_token)
    prefix = indie_hash[:8]
    
    resp = client.get(f"/admin/key-usage?prefix={prefix}", headers={"X-Admin-Token": admin_token})
    if resp.status_code == 200:
        data = resp.json()
        print(f"PASS: Stats: {data['total_scans']} scans (Expected ~2)")
        if data['total_scans'] >= 2 and data['by_tier'].get('Indie', 0) >= 2:
             print("PASS: Tier counts correct")
        else:
             print(f"FAIL: Data mismatch {data}")
    else:
        print(f"FAIL: {resp.status_code}")

    # 4. Verify /admin/customer-usage
    print("\n[Test] /admin/customer-usage (test_admin_indie@example.com)")
    resp = client.get("/admin/customer-usage?email=test_admin_indie@example.com", headers={"X-Admin-Token": admin_token})
    if resp.status_code == 200:
        data = resp.json()
        print(f"PASS: Stats: {data['total_scans']} scans")
        if "Indie" in data['by_tier']:
            print("PASS: Correct Tier")
        else:
            print(f"FAIL: Tier missing in {data}")
    else:
        print(f"FAIL: {resp.status_code}")

    # 5. Verify /analytics.html Protection
    print("\n[Test] /analytics.html Protection")
    resp = client.get("/analytics.html")
    if resp.status_code == 401:
        print("PASS: Public access blocked (401)")
    else:
        print(f"FAIL: Public access allowed ({resp.status_code})")
        
    resp = client.get("/analytics.html", headers={"X-Admin-Token": admin_token})
    if resp.status_code == 200 and "<polyline" in resp.text: # check for sparkline or html structure
        print("PASS: Admin access allowed")
    else:
        print(f"FAIL: Admin access issues ({resp.status_code})")

    print("\n--- Verification Complete ---")

if __name__ == "__main__":
    run_tests()
