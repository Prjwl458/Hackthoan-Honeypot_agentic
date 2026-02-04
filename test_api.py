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

try:
    response = requests.post(url, headers=headers, json=payload)
    print(f"Status Code: {response.status_code}")
    print(f"Response Body: {json.dumps(response.json(), indent=2)}")
except Exception as e:
    print(f"Error: {e}")
