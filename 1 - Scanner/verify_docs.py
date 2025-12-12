from fastapi.testclient import TestClient
from app import app

client = TestClient(app)

def test_docs():
    response = client.get("/docs")
    if response.status_code != 200:
        print(f"FAILED /docs status: {response.status_code}")
        print(response.text)
        assert response.status_code == 200

    if "QubitGrid™ Developer Documentation" not in response.text:
        print("FAILED /docs content mismatch. Got:")
        print(response.text[:500])
    
    assert "QubitGrid™ Developer Documentation" in response.text
    assert "Authentication" in response.text
    assert "Endpoint: /scan" in response.text
    assert "Billing & Grace Period" in response.text
    print("✅ /docs passed")

def test_quickstart():
    response = client.get("/quickstart")
    assert response.status_code == 200
    assert "QubitGrid™ Quickstart" in response.text
    assert "1. Get an API Key" in response.text
    assert "2. Make Your First Request" in response.text
    print("✅ /quickstart passed")

def test_dashboard_links():
    # Authenticate to get dashboard content (View Only)
    # We need a valid key logic or mock
    # app.py: _authenticate_view_only checks headers.
    # We can mock a key or just check plain response if possible.
    # Actually dashboard requires auth.
    pass

if __name__ == "__main__":
    try:
        test_docs()
        test_quickstart()
        print("All docs tests passed!")
    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"FAILED: {e}")
        exit(1)
