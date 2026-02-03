import requests
import json

url = "http://127.0.0.1:8000/message"
headers = {
    "x-api-key": "prajwal_hackathon_key_2310",
    "Content-Type": "application/json"
}

payload = {
  "message": {
  "sender": "scammer",
  "text": "Pay the verification fee now",
  "timestamp": "2026-01-21T10:15:30Z"
},
  "conversationHistory": [
  {
    "sender": "scammer",
    "text": "Your account is blocked",
    "timestamp": "2026-01-21T10:10:00Z"
  },
  {
    "sender": "user",
    "text": "Why is it blocked?",
    "timestamp": "2026-01-21T10:12:00Z"
  }
]
,
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