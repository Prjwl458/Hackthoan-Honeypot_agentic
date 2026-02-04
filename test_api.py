import requests
import json
import time

url = "http://127.0.0.1:8000/message"
headers = {
    "x-api-key": "prajwal_hackathon_key_2310",
    "Content-Type": "application/json"
}

payload = {
  "sessionId": "wertyu-dfghj-ertyui",
  "message": {
    "sender": "scammer",
    "text": "Your bank account will be blocked today. Verify immediately at http://scam-bank.com. Contact us at +91-9876543210.",
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
    response = requests.post(url, headers=headers, json=payload)
    print(f"Status Code: {response.status_code}")
    print(f"Response Body: {json.dumps(response.json(), indent=2)}")
except Exception as e:
    print(f"Error: {e}")
