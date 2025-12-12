import os
import sqlite3
from datetime import datetime, timedelta
from fastapi.testclient import TestClient
from models import sessionmaker, create_engine, Customer, APIKey, Base
from app import app

# Setup Client
DB_PATH = os.getenv("DB_PATH", "analytics.db")
DATABASE_URL = f"sqlite:///{DB_PATH}"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)
client = TestClient(app)

def init_db_migration():
    """Manual migration ensuring grace_period_start exists for tests."""
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT grace_period_start FROM customers LIMIT 1")
        except sqlite3.OperationalError:
            print("[TEST MIGRATION] Adding grace_period_start column...")
            try:
                cursor.execute("ALTER TABLE customers ADD COLUMN grace_period_start TIMESTAMP")
                conn.commit()
            except Exception as e:
                print(f"[TEST MIGRATION IGNORING] {e}")

def cleanup(email):
    """Remove test data."""
    session = SessionLocal()
    try:
        session.query(APIKey).filter_by(user_email=email).delete()
        session.query(Customer).filter_by(email=email).delete()
        session.commit()
    finally:
        session.close()

def run_tests():
    init_db_migration()
    email = "phase8_test@qubitgrid.com"
    stripe_id = "cus_phase8"
    print(f"--- Verification: Phase 8 Expiration for {email} ---")
    
    cleanup(email)
    
    session = SessionLocal()
    
    # 1. Create Active Customer & Key
    print("1. Creating Active Customer & Key...")
    c = Customer(email=email, stripe_customer_id=stripe_id, tier="Pro", status="active")
    k = APIKey(
        user_email=email, 
        key_hash=APIKey.hash_key("test_key_phase8"), 
        plan="Pro", 
        active=True
    )
    session.add(c)
    session.add(k)
    session.commit()
    session.close()
    
    headers = {"Authorization": "Bearer test_key_phase8"}
    
    # Check Scan (Should be 200)
    resp = client.get("/scan", params={"text": "smoke_test"}, headers=headers)
    if resp.status_code == 200:
        print("✅ [Active] Scan Allowed (200)")
    else:
        print(f"❌ [Active] Scan Failed: {resp.status_code} {resp.text}")

    # 2. Simulate Payment Failed (Grace Period Start)
    print("\n2. Simulating Payment Failed (Grace Period)...")
    session = SessionLocal()
    c = session.query(Customer).filter_by(email=email).first()
    c.status = "past_due"
    c.grace_period_start = datetime.utcnow() # Just started
    session.commit()
    session.close()
    
    resp = client.get("/scan", params={"text": "smoke_test"}, headers=headers)
    if resp.status_code == 200:
        print("✅ [Grace] Scan Allowed (200)")
    else:
        print(f"❌ [Grace] Scan Failed: {resp.status_code} {resp.text}")

    # 3. Simulate Grace Period Expiry (4 Days later)
    print("\n3. Simulating Grace Expiry...")
    session = SessionLocal()
    c = session.query(Customer).filter_by(email=email).first()
    c.grace_period_start = datetime.utcnow() - timedelta(days=4)
    session.commit()
    session.close()
    
    resp = client.get("/scan", params={"text": "smoke_test"}, headers=headers)
    if resp.status_code == 402:
        print("✅ [Expired] Scan Blocked (402)")
        if resp.json().get("grace_ended"):
            print("✅ [Expired] Error message correct.")
        else:
             print("⚠️ [Expired] Error message mismatch: " + str(resp.json()))
    else:
        print(f"❌ [Expired] Expected 402, got {resp.status_code} {resp.text}")

    # 4. Simulate Payment Success (Restore)
    print("\n4. Simulating Payment Success...")
    session = SessionLocal()
    c = session.query(Customer).filter_by(email=email).first()
    c.status = "active"
    c.grace_period_start = None
    session.commit()
    session.close()

    resp = client.get("/scan", params={"text": "smoke_test"}, headers=headers)
    if resp.status_code == 200:
        print("✅ [Restored] Scan Allowed (200)")
    else:
        print(f"❌ [Restored] Expected 200, got {resp.status_code} {resp.text}")

    # 5. Simulate Cancellation
    print("\n5. Simulating Cancellation...")
    session = SessionLocal()
    c = session.query(Customer).filter_by(email=email).first()
    c.status = "canceled"
    session.commit()
    session.close()

    resp = client.get("/scan", params={"text": "smoke_test"}, headers=headers)
    if resp.status_code == 402:
        print("✅ [Canceled] Scan Blocked (402)")
    else:
        print(f"❌ [Canceled] Expected 402, got {resp.status_code} {resp.text}")

    cleanup(email)
    print("\n--- Phase 8 Verification Complete ---")

if __name__ == "__main__":
    run_tests()
