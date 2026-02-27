# 🏗️ Agentic AI Honeypot - Technical Blueprint

## Overview

The Agentic AI Honeypot is a cyber-intelligence engine that intercepts scam messages, analyzes them using LLM technology, and extracts actionable intelligence. This document outlines the technical architecture, data structures, and future expansion plans.

---

## 1. The Logic: Sender vs Content Mismatch Detection

### Weighted Analysis System

The system uses a multi-layered approach to detect scams by analyzing mismatches between the sender's claimed identity and the message content:

| Factor | Weight | Description |
|--------|--------|-------------|
| Sender Identity Mismatch | 30% | Does sender phone match claimed entity? |
| Urgency Language | 25% | Contains threats, deadlines, "act now" |
| Suspicious Keywords | 20% | Bank, OTP, account suspended, verify |
| Link Analysis | 15% | Shortened URLs, suspicious domains |
| Request Type | 10% | Money request, credentials, OTPs |

### Scoring Algorithm

```
Risk Score = Σ(factor_score × weight) / 100
```

- **0-30**: Low Risk - Legitimate message
- **31-60**: Medium Risk - Requires verification
- **61-100**: High Risk - Confirmed scam

### Example Mismatch Detection

```
Input: Message from +91-9876543210 claiming to be Netflix Support
       Content: "Your account suspended. Click netflix-verify.com to restore"

Analysis:
├── Sender: +91-9876543210 (not Netflix official number) → MISMATCH
├── Keywords: "account suspended", "verify" → HIGH
├── Link: netflix-verify.com (not netflix.com) → PHISHING
└── Urgency: "suspended" creates false urgency → HIGH

Result: Risk Score = 85 → PHISHING SCAM DETECTED
```

---

## 2. Data Storage: MongoDB Intelligence Structure

### Collection: `scam_logs`

Each incoming message creates a document in the `scam_logs` collection:

```json
{
  "_id": "ObjectId('...')",
  "sessionId": "session_abc123",
  "timestamp": "2024-01-15T10:30:00Z",
  
  "message": {
    "content": "Your Netflix account has been suspended...",
    "senderId": "+1-555-0123",
    "direction": "incoming"
  },
  
  "analysis": {
    "scamType": "Phishing",
    "urgencyLevel": "High",
    "riskScore": 85,
    "verdict": "Threat Detected: Phishing attempt"
  },
  
  "intelligence": {
    "extractedEntities": {
      "phishingLinks": ["netflix-verify.com"],
      "phoneNumbers": ["+1-555-0123"],
      "bankAccounts": [],
      "upiIds": [],
      "suspiciousKeywords": ["suspended", "verify", "restore"]
    },
    "threatSource": "sms",
    "senderVerified": false,
    "senderClaimed": "Netflix Support"
  },
  
  "metadata": {
    "model": "meta-llama/Llama-3.1-8B-Instruct",
    "processingTime": 1.2,
    "apiVersion": "2.0.0"
  }
}
```

### Indexes

```javascript
// Index for session-based queries
db.scam_logs.createIndex({ "sessionId": 1 })

// Index for time-based analytics
db.scam_logs.createIndex({ "timestamp": -1 })

// Index for scam type analysis
db.scam_logs.createIndex({ "analysis.scamType": 1 })

// Compound index for dashboard queries
db.scam_logs.createIndex({ "analysis.riskScore": 1, "timestamp": -1 })
```

### In-Memory Fallback

If MongoDB is unavailable, the system uses an in-memory dictionary:

```python
conversations = {
    "session_abc123": {
        "sessionId": "session_abc123",
        "createdAt": datetime,
        "messages": [],
        "intelligence": {
            "bankAccounts": [],
            "upiIds": [],
            "phishingLinks": [],
            "phoneNumbers": [],
            "suspiciousKeywords": [],
            "scamType": "Unknown",
            "urgencyLevel": "Low",
            "riskScore": 10
        }
    }
}
```

**Warning**: In-memory storage is NOT persistent across restarts.

---

## 3. Rate Limiting: API Protection

### Implementation

The system uses an in-memory token bucket algorithm:

```python
rate_limit_store = defaultdict(list)

def check_rate_limit(session_id: str, max_requests: int = 10, window_seconds: int = 60) -> bool:
    now = time()
    # Clean old entries (older than 60 seconds)
    rate_limit_store[session_id] = [t for t in rate_limit_store[session_id] if now - t < window_seconds]
    
    if len(rate_limit_store[session_id]) >= max_requests:
        return False  # Rate limit exceeded
    
    rate_limit_store[session_id].append(now)
    return True
```

### Limits

| Endpoint | Limit | Window |
|----------|-------|--------|
| `/message` | 10 requests | 60 seconds |
| `/health` | Unlimited | - |
| `/intelligence` | 10 requests | 60 seconds |

### Response on Rate Limit

```json
{
  "status": "error",
  "error": "Rate limit exceeded",
  "message": "Maximum 10 requests per minute"
}
```

### Production Enhancements (Future)

- Redis-based distributed rate limiting
- Per-IP and per-API-key limits
- Different limits for authenticated vs anonymous users

---

## 4. Future Frontend: Expo Mobile App Integration

### API-First Design

The backend is designed as a pure REST API, ready for mobile consumption:

```
┌─────────────────┐         ┌──────────────────┐         ┌─────────────────┐
│   Expo Mobile   │────────▶│   FastAPI API    │────────▶│   MongoDB      │
│      App        │◀────────│   (Port 9000)    │◀────────│   Atlas        │
└─────────────────┘         └──────────────────┘         └─────────────────┘
```

### API Endpoints for Mobile

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Server status check |
| `/message` | POST | Send message for analysis |
| `/intelligence/{sessionId}` | GET | Get session intelligence |
| `/intelligence` | GET | Get all intelligence (admin) |

### Expected Mobile App Features

1. **Message Input Screen**
   - Text input for scam messages
   - Sender ID field
   - Send button with loading state

2. **Results Screen**
   - Risk score gauge (0-100)
   - Scam type badge
   - Extracted entities list
   - Verdict text

3. **History Screen**
   - List of past scans
   - Filter by scam type
   - Sort by date/risk score

4. **Dashboard (Admin)**
   - Total scans count
   - Scam type distribution
   - Recent activity feed
   - Export functionality

### CORS Configuration

For production, restrict CORS to your mobile app domain:

```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://your-expo-app.expo.dev"],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "X-API-Key"],
)
```

### Mobile App Data Flow

```javascript
// Example Expo/React Native code
const scanMessage = async (message, senderId) => {
  const response = await fetch('https://your-api.com/message', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-API-Key': 'your_api_key'
    },
    body: JSON.stringify({
      message,
      senderId,
      sessionId: getSessionId()
    })
  });
  
  const data = await response.json();
  return data; // Contains verdict, riskScore, intelligence
};
```

---

## 5. Security Considerations

### Environment Variables

All secrets are loaded from `.env`:

```
API_KEY=your_secure_api_key
OPENROUTER_API_KEY=sk-or-v1-...
MONGODB_URI=mongodb+srv://...
GUVI_CALLBACK_URL=https://...
DEBUG=false
```

### API Key Authentication

Every request must include the `X-API-Key` header:

```bash
curl -H "X-API-Key: your_api_key" ...
```

### Error Handling

All exceptions return clean JSON:

```json
{
  "status": "error",
  "error": "Service temporarily unavailable"
}
```

---

## 6. Technology Stack

| Layer | Technology | Version |
|-------|------------|---------|
| Web Framework | FastAPI | 0.109.0 |
| ASGI Server | Uvicorn | 0.27.0 |
| Data Validation | Pydantic | 2.5.3 |
| Database Driver | Motor | 3.3.2 |
| HTTP Client | httpx | 0.26.0 |
| LLM Model | Llama 3.1 8B | Instruct |

---

## 7. Future Enhancements

- [ ] Voice message analysis
- [ ] Image/attachment scam detection
- [ ] Multi-language support
- [ ] Real-time WebSocket notifications
- [ ] Redis-based distributed caching
- [ ] Docker containerization
- [ ] CI/CD pipeline
- [ ] OAuth2 authentication
