"""
Test script for the Agentic AI Honeypot API.
Uses httpx for async testing of the new Pydantic-based API.
"""

import asyncio
import json
import time
import httpx


BASE_URL = "http://127.0.0.1:8000"
API_KEY = "test_key_for_ci"


async def test_valid_request():
    """Test a valid scam message with correct API key."""
    print("\n" + "="*60)
    print("TEST 1: Valid Request with Correct API Key")
    print("="*60)
    
    url = f"{BASE_URL}/"
    headers = {
        "x-api-key": API_KEY,
        "Content-Type": "application/json"
    }
    
    payload = {
        "sessionId": f"test-session-{int(time.time())}",
        "message": {
            "sender": "scammer",
            "text": "CONGRATULATIONS! You have been selected for a Work-From-Home job with Amazon. Earn 5000 daily. Just pay a 500 registration fee to our HR UPI: jobhero@paytm. Contact +91 9988776655 for details.",
            "timestamp": int(time.time() * 1000)
        },
        "conversationHistory": [],
        "metadata": {
            "channel": "SMS",
            "language": "English",
            "locale": "IN"
        }
    }
    
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.post(url, headers=headers, json=payload)
    
    print(f"Status Code: {response.status_code}")
    print(f"Response Body: {json.dumps(response.json(), indent=2)}")
    
    # Verify response structure
    data = response.json()
    assert response.status_code == 200, f"Expected 200, got {response.status_code}"
    assert "status" in data, "Missing 'status' in response"
    assert data["status"] == "success", f"Expected 'success', got {data['status']}"
    assert "reply" in data, "Missing 'reply' in response"
    
    print("\n[PASS] Test 1 PASSED: Valid request processed successfully")
    return data


async def test_missing_api_key():
    """Test request without API key - should return 403 with clean JSON error."""
    print("\n" + "="*60)
    print("TEST 2: Missing API Key (Global Error Handler)")
    print("="*60)
    
    url = f"{BASE_URL}/"
    headers = {
        "Content-Type": "application/json"
        # Intentionally missing x-api-key
    }
    
    payload = {
        "sessionId": "test-session-no-key",
        "message": {
            "sender": "scammer",
            "text": "Your account is blocked. Pay 5000 now to unlock.",
            "timestamp": int(time.time() * 1000)
        },
        "conversationHistory": [],
        "metadata": {
            "channel": "SMS",
            "language": "English",
            "locale": "IN"
        }
    }
    
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.post(url, headers=headers, json=payload)
    
    print(f"Status Code: {response.status_code}")
    print(f"Response Body: {json.dumps(response.json(), indent=2)}")
    
    # Verify error structure
    data = response.json()
    assert response.status_code == 403, f"Expected 403, got {response.status_code}"
    assert "detail" in data, "Missing 'detail' in error response"
    assert data["detail"] == "Invalid API Key", f"Unexpected error message: {data['detail']}"
    
    print("\n[PASS] Test 2 PASSED: Missing API key returns 403 with JSON error")


async def test_invalid_api_key():
    """Test request with invalid API key - should return 403."""
    print("\n" + "="*60)
    print("TEST 3: Invalid API Key")
    print("="*60)
    
    url = f"{BASE_URL}/"
    headers = {
        "x-api-key": "invalid-key-12345",  # Wrong key
        "Content-Type": "application/json"
    }
    
    payload = {
        "sessionId": "test-session-invalid-key",
        "message": {
            "sender": "scammer",
            "text": "Your account is blocked.",
            "timestamp": int(time.time() * 1000)
        },
        "conversationHistory": [],
        "metadata": {}
    }
    
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.post(url, headers=headers, json=payload)
    
    print(f"Status Code: {response.status_code}")
    print(f"Response Body: {json.dumps(response.json(), indent=2)}")
    
    data = response.json()
    assert response.status_code == 403, f"Expected 403, got {response.status_code}"
    assert "detail" in data, "Missing 'detail' in error response"
    
    print("\n[PASS] Test 3 PASSED: Invalid API key returns 403")


async def test_validation_error():
    """Test request with invalid data - should return 422 with validation errors."""
    print("\n" + "="*60)
    print("TEST 4: Validation Error (Pydantic)")
    print("="*60)
    
    url = f"{BASE_URL}/"
    headers = {
        "x-api-key": API_KEY,
        "Content-Type": "application/json"
    }
    
    # Missing required 'message' field
    payload = {
        "sessionId": "test-session-validation",
        "conversationHistory": []
    }
    
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.post(url, headers=headers, json=payload)
    
    print(f"Status Code: {response.status_code}")
    print(f"Response Body: {json.dumps(response.json(), indent=2)}")
    
    data = response.json()
    assert response.status_code == 422, f"Expected 422, got {response.status_code}"
    assert data["status"] == "error", "Expected error status"
    assert "error" in data, "Missing 'error' in response"
    assert "details" in data, "Missing 'details' in response"
    
    print("\n[PASS] Test 4 PASSED: Validation error returns 422 with structured error")


async def test_health_check():
    """Test the root health check endpoint."""
    print("\n" + "="*60)
    print("TEST 5: Health Check")
    print("="*60)
    
    url = f"{BASE_URL}/"
    
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.get(url)
    
    print(f"Status Code: {response.status_code}")
    print(f"Response Body: {json.dumps(response.json(), indent=2)}")
    
    data = response.json()
    assert response.status_code == 200, f"Expected 200, got {response.status_code}"
    assert "status" in data
    
    print("\n[PASS] Test 5 PASSED: Health check working")


async def test_backward_compatibility():
    """Test the /message endpoint for backward compatibility."""
    print("\n" + "="*60)
    print("TEST 6: Backward Compatibility (/message endpoint)")
    print("="*60)
    
    url = f"{BASE_URL}/message"
    headers = {
        "x-api-key": API_KEY,
        "Content-Type": "application/json"
    }
    
    payload = {
        "sessionId": f"test-backward-{int(time.time())}",
        "message": {
            "sender": "scammer",
            "text": "URGENT: Your bank account will be blocked. Verify now: https://fake-bank.com",
            "timestamp": int(time.time() * 1000)
        },
        "conversationHistory": [],
        "metadata": {
            "channel": "WhatsApp",
            "language": "English",
            "locale": "IN"
        }
    }
    
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.post(url, headers=headers, json=payload)
    
    print(f"Status Code: {response.status_code}")
    print(f"Response Body: {json.dumps(response.json(), indent=2)}")
    
    data = response.json()
    assert response.status_code == 200, f"Expected 200, got {response.status_code}"
    assert "status" in data and data["status"] == "success"
    assert "reply" in data
    
    print("\n[PASS] Test 6 PASSED: Backward compatibility maintained")


async def main():
    """Run all tests."""
    print("\n" + "="*60)
    print("AGENTIC AI HONEYPOT - API TESTS")
    print("="*60)
    
    try:
        # Test health check first
        await test_health_check()
        
        # Test authentication
        await test_missing_api_key()
        await test_invalid_api_key()
        
        # Test validation
        await test_validation_error()
        
        # Test valid requests
        await test_valid_request()
        await test_backward_compatibility()
        
        print("\n" + "="*60)
        print("ALL TESTS PASSED ✅")
        print("="*60)
        
    except AssertionError as e:
        print(f"\n[ERROR] TEST FAILED: {e}")
    except httpx.ConnectError:
        print("\n[ERROR] Cannot connect to server. Is the server running?")
        print("   Run: python main.py")
    except Exception as e:
        print(f"\n[ERROR] UNEXPECTED ERROR: {e}")


if __name__ == "__main__":
    asyncio.run(main())
