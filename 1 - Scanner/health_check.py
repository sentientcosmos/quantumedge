from fastapi.testclient import TestClient
from app import app
import sys

# Suppress prints from app startup if any
# (optional, but keeps output clean)

client = TestClient(app)

def check_endpoint(path):
    print(f"Checking {path}...")
    try:
        response = client.get(path)
        print(f"Status: {response.status_code}")
        print(f"Response: {response.text}")
        if response.status_code == 200:
            print(f"PASS: {path}")
        else:
            print(f"FAIL: {path} - Unexpected status code")
    except Exception as e:
        print(f"FAIL: {path} with error {e}")

if __name__ == "__main__":
    check_endpoint("/health")
    check_endpoint("/__version")
