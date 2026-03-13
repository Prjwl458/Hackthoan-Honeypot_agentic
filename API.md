# API Reference - Agentic AI Honeypot v2.0.0

**Base URL:** `https://your-production-domain.com` (or `http://localhost:8000` for development)

---

## Overview

The Agentic AI Honeypot API provides real-time scam detection and intelligence extraction. It uses a three-tier defense system:

1. **Tier 1:** Sovereign Shields (Whitelists) - Early return for known-safe patterns
2. **Tier 2:** Deterministic Traps (Blacklists) - Early return for known-scam patterns  
3. **Tier 3:** LLM Heuristics - AI-based detection when Tier 1/2 don't match

---

## Authentication

All endpoints require API key authentication via the `X-API-Key` header.

### Headers

| Header | Required | Description |
|--------|----------|-------------|
| `X-API-Key` | Yes | Your API key (e.g., `prajwal_hackathon_key_2310`) |
| `Content-Type` | Yes | Must be `application/json` |

---

## Endpoints

### 1. Health Check

Check if the service is online.

**Endpoint:** `GET /health`

**Response:**

```json
{
  "status": "online",
  "version": "2.0.0",
  "timestamp": "2024-01-15T10:30:00.000000"
}
```

---

### 2. Message Analysis

Analyze a message for scam detection.

**Endpoint:** `POST /message`

**Rate Limit:** 10 requests per minute per IP address

---

## Request Schema

### HoneypotRequest

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `session_id` | string | No | Unique session identifier (snake_case) |
| `sessionId` | string | No | Unique session identifier (camelCase) |
| `message` | object | Yes | Current incoming message object |
| `conversation_history` | array | No | Array of previous messages (snake_case) |
| `conversationHistory` | array | No | Array of previous messages (camelCase) |
| `metadata` | object | No | Optional metadata for future use |

### Message Object

The message object can be provided in two formats:

**Format 1 (Direct text):**
```json
{
  "text": "Your OTP is 123456. Do not share it with anyone."
}
```

**Format 2 (Full message structure):**
```json
{
  "text": "Your OTP is 123456. Do not share it with anyone.",
  "type": "text",
  "timestamp": 1705315800000,
  "sender": "user",
  "sender_id": "+919876543210"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `text` | string | Yes* | Message text content (*if content not provided) |
| `content` | string | Yes* | Message text content (*if text not provided) |
| `type` | string | No | Message type (default: "text") |
| `timestamp` | integer | Yes | Unix timestamp in milliseconds |
| `sender` | string | No | Message sender (default: "user") |
| `sender_id` | string | No | Sender's phone number or ID (snake_case) |
| `senderId` | string | No | Sender's phone number or ID (camelCase) |

---

## Response Schema

### HoneypotResponse

| Field | Type | Description |
|-------|------|-------------|
| `status` | string | Response status: "success" or "error" |
| `reply` | string | AI-generated response to engage the scammer |
| `intelligence` | object | Extracted intelligence from the message |
| `version` | string | API version (e.g., "2.0.0") |
| `timestamp` | string | ISO-8601 UTC timestamp |
| `latency_ms` | integer | Request processing time in milliseconds |

### Intelligence Data

| Field | Type | Description |
|-------|------|-------------|
| `isPhishing` | boolean | True if any suspicious pattern detected |
| `riskScore` | integer | 0-100 risk score (70+ = phishing) |
| `scamType` | string | Classification type (e.g., "Safe/Transactional", "Credential Theft") |
| `urgencyLevel` | string | Urgency level: "Low", "Medium", "High" |
| `agentNotes` | string | Internal notes about detection logic |
| `phishingLinks` | array | List of detected phishing URLs |
| `upiIds` | array | List of detected UPI IDs |
| `bankAccounts` | array | List of detected bank account numbers |
| `phoneNumbers` | array | List of detected phone numbers |
| `suspiciousKeywords` | array | List of suspicious keywords found |
| `extractedEntities` | array | Flat list of all extracted entities |
| `aadhaarNumbers` | array | List of detected Aadhaar numbers |
| `panNumbers` | array | List of detected PAN numbers |
| `threatSource` | string | Sender's phone number/ID |

---

## Example Requests and Responses

### Example 1: Legitimate OTP (Tier 1 - Whitelist Match)

**Request:**
```json
{
  "message": {
    "text": "Your OTP is 123456. Do not share with anyone. Valid for 5 minutes.",
    "timestamp": 1705315800000
  },
  "sessionId": "user123"
}
```

**Response:**
```json
{
  "status": "success",
  "reply": "✅ Safe: Legitimate OTP message with security warning",
  "intelligence": {
    "isPhishing": false,
    "riskScore": 5,
    "scamType": "Safe/Transactional",
    "urgencyLevel": "Low",
    "agentNotes": "[TIER1] Official OTP Delivery - Security warning present",
    "phishingLinks": [],
    "upiIds": [],
    "bankAccounts": [],
    "phoneNumbers": [],
    "suspiciousKeywords": [],
    "extractedEntities": ["123456"],
    "aadhaarNumbers": [],
    "panNumbers": [],
    "threatSource": ""
  },
  "version": "2.0.0",
  "timestamp": "2024-01-15T10:30:00.000000",
  "latency_ms": 3
}
```

---

### Example 2: PIN Theft Attempt (Tier 2 - Blacklist Match)

**Request:**
```json
{
  "message": {
    "text": "Your UPI account has been locked. Please share your UPI PIN to verify your identity.",
    "timestamp": 1705315800000
  },
  "sessionId": "user123"
}
```

**Response:**
```json
{
  "status": "success",
  "reply": "❌ Danger: PIN/Credential theft attempt detected",
  "intelligence": {
    "isPhishing": true,
    "riskScore": 98,
    "scamType": "Credential Theft",
    "urgencyLevel": "High",
    "agentNotes": "[TIER2] PIN Trap Detected - UPI credential request",
    "phishingLinks": [],
    "upiIds": [],
    "bankAccounts": [],
    "phoneNumbers": [],
    "suspiciousKeywords": ["upi pin", "verify"],
    "extractedEntities": ["upi pin"],
    "aadhaarNumbers": [],
    "panNumbers": [],
    "threatSource": ""
  },
  "version": "2.0.0",
  "timestamp": "2024-01-15T10:30:00.000000",
  "latency_ms": 4
}
```

---

### Example 3: Phishing Link (Tier 3 - LLM Analysis)

**Request:**
```json
{
  "message": {
    "text": "Your bank account has been compromised. Click here to verify: http://evil-bank.fake.com/verify",
    "timestamp": 1705315800000
  },
  "sessionId": "user123"
}
```

**Response:**
```json
{
  "status": "success",
  "reply": "❌ Danger: Evidence Found: evil-bank.fake.com",
  "intelligence": {
    "isPhishing": true,
    "riskScore": 75,
    "scamType": "Confirmed Phishing/Scam",
    "urgencyLevel": "High",
    "agentNotes": "Evidence Found: evil-bank.fake.com",
    "phishingLinks": ["evil-bank.fake.com"],
    "upiIds": [],
    "bankAccounts": [],
    "phoneNumbers": [],
    "suspiciousKeywords": ["compromised", "verify", "bank"],
    "extractedEntities": ["evil-bank.fake.com"],
    "aadhaarNumbers": [],
    "panNumbers": [],
    "threatSource": ""
  },
  "version": "2.0.0",
  "timestamp": "2024-01-15T10:30:00.000000",
  "latency_ms": 1847
}
```

---

### Example 4: Short Input (Tier 1 - Early Return)

**Request:**
```json
{
  "message": {
    "text": "Hi",
    "timestamp": 1705315800000
  },
  "sessionId": "user123"
}
```

**Response:**
```json
{
  "status": "success",
  "reply": "✅ Safe: Input too short for analysis",
  "intelligence": {
    "isPhishing": false,
    "riskScore": 0,
    "scamType": "Safe/Transactional",
    "urgencyLevel": "Low",
    "agentNotes": "Input too short for analysis",
    "phishingLinks": [],
    "upiIds": [],
    "bankAccounts": [],
    "phoneNumbers": [],
    "suspiciousKeywords": [],
    "extractedEntities": [],
    "aadhaarNumbers": [],
    "panNumbers": [],
    "threatSource": ""
  },
  "version": "2.0.0",
  "timestamp": "2024-01-15T10:30:00.000000",
  "latency_ms": 2
}
```

---

## Error Responses

### 401 - Unauthorized

Invalid or missing API key.

```json
{
  "status": "error",
  "error": "Unauthorized",
  "message": "Invalid or missing API Key"
}
```

---

### 422 - Validation Error

Request validation failed.

```json
{
  "status": "error",
  "error": "Validation Error",
  "message": "Request validation failed: field 'message' is required"
}
```

---

### 429 - Too Many Requests

Rate limit exceeded.

```json
{
  "status": "error",
  "error": "Too Many Requests",
  "message": "Rate limit exceeded: 10 per minute"
}
```

---

### 504 - Gateway Timeout

AI analysis timed out (15 second limit).

```json
{
  "status": "error",
  "error": "Gateway Timeout",
  "message": "AI analysis timed out"
}
```

---

## Risk Score Classification

| Risk Score | Classification | isPhishing | Action |
|------------|----------------|------------|--------|
| 0-69 | Safe | false | None |
| 70-100 | Danger | true | Block |

---

## Tier Detection Logic

The API automatically determines which tier matched:

### Tier Detection in Response

The `agentNotes` field indicates which tier was triggered:

| Tier | Prefix | Description |
|------|--------|-------------|
| Tier 1 | `[TIER1]` | Whitelist match (safe) |
| Tier 2 | `[TIER2]` | Blacklist match (danger) |
| Tier 3 | No prefix | LLM analysis |

---

## Rate Limiting

- **Limit:** 10 requests per minute per IP address
- **Headers:** 
  - `X-RateLimit-Limit`: Maximum requests allowed
  - `X-RateLimit-Remaining`: Remaining requests in window

---

## SDK Examples

### JavaScript/TypeScript

```javascript
const response = await fetch('https://your-domain.com/message', {
  method: 'POST',
  headers: {
    'X-API-Key': 'your_api_key',
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({
    message: {
      text: 'Your OTP is 123456',
      timestamp: Date.now()
    },
    sessionId: 'user123'
  })
});

const data = await response.json();
console.log(data.intelligence.riskScore);
```

### Python

```python
import requests

response = requests.post(
    'https://your-domain.com/message',
    headers={
        'X-API-Key': 'your_api_key',
        'Content-Type': 'application/json'
    },
    json={
        'message': {
            'text': 'Your OTP is 123456',
            'timestamp': 1705315800000
        },
        'sessionId': 'user123'
    }
)

data = response.json()
print(data['intelligence']['riskScore'])
```

### cURL

```bash
curl -X POST https://your-domain.com/message \
  -H "X-API-Key: your_api_key" \
  -H "Content-Type: application/json" \
  -d '{
    "message": {
      "text": "Your OTP is 123456",
      "timestamp": 1705315800000
    },
    "sessionId": "user123"
  }'
```

---

## Changelog

### v2.0.0 (Current)
- Added Tiered Defense System with 3-tier detection
- Tier 1: Sovereign Shields (Whitelists) - Official OTP, Government Confirmation, Domain Reputation
- Tier 2: Deterministic Traps (Blacklists) - PIN Trap, Micro-Payment Trap, Identity Theft
- Tier 3: LLM Heuristics - AI detection only when Tier 1/2 don't match

### v1.2.0 (Previous)
- Initial production release with basic scam detection
- Triple-Threat Logic implementation
