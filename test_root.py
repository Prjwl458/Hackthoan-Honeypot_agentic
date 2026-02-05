import requests
import json
import time

url = "http://127.0.0.1:8000/"
headers = {
    "x-api-key": "prajwal_hackathon_key_2310",
    "Content-Type": "application/json"
}

payload = {
  "sessionId": "test-session-123",
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

try:
    print(f"Sending request to {url}...")
    response = requests.post(url, headers=headers, json=payload)
    print(f"Status Code: {response.status_code}")
    print(f"Response Body: {json.dumps(response.json(), indent=2)}")
except Exception as e:
    print(f"Error: {e}")
