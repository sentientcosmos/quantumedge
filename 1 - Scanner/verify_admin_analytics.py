import os
import sys
from fastapi.testclient import TestClient
from app import app

# Initialize TestClient
client = TestClient(app)

def run_smoke_tests():
    print("--- Starting Admin Analytics Smoke Tests ---\n")
    
    # Defaults
    ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "dev-local-admin")
    
    # Test 1: GET /health
    try:
        resp = client.get("/health")
        if resp.status_code == 200 and resp.json().get("ok") is True:
            print("✅ Test 1 /health passed")
        else:
            print(f"❌ Test 1 /health failed: Status {resp.status_code}, Body {resp.text}")
    except Exception as e:
        print(f"❌ Test 1 /health failed with exception: {e}")

    # Test 2: Trigger a few scans (Free tier)
    try:
        scans_ok = True
        for i in range(3):
            resp = client.get(f"/scan?text=smoke_test_{i}")
            if resp.status_code != 200:
                print(f"❌ Test 2 /scan iteration {i} failed: Status {resp.status_code}")
                scans_ok = False
                break
            data = resp.json()
            if "severity" not in data or "flags" not in data:
                print(f"❌ Test 2 /scan iteration {i} failed: Missing keys in {data}")
                scans_ok = False
                break
        if scans_ok:
            print("✅ Test 2 /scan (x3) passed")
    except Exception as e:
        print(f"❌ Test 2 /scan failed with exception: {e}")

    # Test 3: Admin usage endpoint
    try:
        resp = client.get("/admin/usage?limit=5", headers={"X-Admin-Token": ADMIN_TOKEN})
        if resp.status_code == 200:
            data = resp.json()
            if "rows" in data and isinstance(data["rows"], list):
                print("✅ Test 3 /admin/usage passed")
            else:
                print(f"❌ Test 3 /admin/usage failed: Missing 'rows' array in {data}")
        else:
            print(f"❌ Test 3 /admin/usage failed: Status {resp.status_code}")
    except Exception as e:
        print(f"❌ Test 3 /admin/usage failed with exception: {e}")

    # Test 4: Public analytics
    try:
        resp = client.get("/analytics")
        if resp.status_code == 200:
            data = resp.json()
            required_keys = {"window_days", "totals", "by_severity"}
            if required_keys.issubset(data.keys()):
                print("✅ Test 4 /analytics passed")
            else:
                print(f"❌ Test 4 /analytics failed: Missing keys. Got {list(data.keys())}")
        else:
            print(f"❌ Test 4 /analytics failed: Status {resp.status_code}")
    except Exception as e:
        print(f"❌ Test 4 /analytics failed with exception: {e}")

    # Test 5: HTML dashboard
    # Note: Requires Auth in Phase 4. Using token to expect 200 OK.
    try:
        resp = client.get("/analytics.html", headers={"X-Admin-Token": ADMIN_TOKEN})
        if resp.status_code == 200:
            if "QubitGrid" in resp.text:
                print("✅ Test 5 /analytics.html passed")
            else:
                print("❌ Test 5 /analytics.html failed: 'QubitGrid' not found in response text")
        else:
            print(f"❌ Test 5 /analytics.html failed: Status {resp.status_code}")
    except Exception as e:
        print(f"❌ Test 5 /analytics.html failed with exception: {e}")

    print("\n--- Smoke Tests Complete ---")

if __name__ == "__main__":
    run_smoke_tests()
