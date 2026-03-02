# 🏗️ Agentic AI Honeypot - Technical Blueprint

## Overview

The Agentic AI Honeypot is a cyber-intelligence engine that intercepts scam messages, analyzes them using LLM technology, and extracts actionable intelligence. This document outlines the technical architecture, data structures, and future expansion plans.

---

## 1. The Safety Sandwich: Logic Over Bias

Our architecture follows a **three-layer validation pipeline** that prioritizes evidence over assumptions:

### The Pipeline Flow

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  PRE-PROCESS    │────▶│     PROCESS     │────▶│  POST-PROCESS   │
│   (Whitelist)   │     │  (AI Analysis)  │     │ (Evidence Guard)│
└─────────────────┘     └─────────────────┘     └─────────────────┘
```

#### Layer 1: Pre-Process (Whitelist)
**Purpose**: Fast-path legitimate messages to avoid LLM costs and latency

| Pattern | Detection | Result |
|---------|-----------|--------|
| OTP | `[0-9]{4,6}` + "verification/code" keywords | Risk: 5, Type: Safe/Transactional |
| Bank Update | "A/C XX" + "debited/credited" + balance | Risk: 10, Type: Bank Update |

If matched, the request returns immediately with a standardized safe classification.

#### Layer 2: Process (AI Analysis)
**Purpose**: Deep analysis for non-whitelist messages

The LLM performs evidence-based scoring:
- Extracts physical artifacts: URLs, UPI IDs, bank accounts
- Analyzes intent without assuming malicious behavior
- Returns structured intelligence with riskScore

#### Layer 3: Post-Process (Evidence Guard)
**Purpose**: Prevent false positives from urgency language alone

**The Evidence Requirement Rule**:
```
IF riskScore > 70 
   AND phishingLinks == [] 
   AND upiIds == [] 
   AND bankAccounts == []:
       riskScore = 40 (HARD CAP)
       scamType = "Unverified/Suspicious"
```

A message CANNOT exceed Risk 40 without at least one physical artifact.

### Artifact-Based Scoring Matrix

| Evidence Present | Max Risk | Classification |
|------------------|----------|----------------|
| None | 40 | Unverified/Suspicious |
| Links only | 60 | Potential Phishing |
| UPI/Bank + Links | 80 | High Risk Scam |
| All artifacts + PII request | 100 | Critical Threat |

### Example: Evidence-Based Detection

```
Input: "URGENT: Your account will be suspended in 24 hours! Call now!"

Analysis:
├── No phishing links extracted → No physical evidence
├── Urgency keywords detected → AI suggests Risk: 85
└── EVIDENCE GUARD triggers → Caps Risk: 40

Result: Risk Score = 40 → Unverified/Suspicious (not confirmed scam)
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

## 4. Data Integrity Protocol: The Guardian of the Schema

### The `ensure_list` Sanitization Helper

LLMs are probabilistic and may return data in unexpected formats. The `ensure_list` function acts as a **schema guardian**, preventing 400 Bad Request errors by forcing AI-generated dictionaries into Pydantic-compliant lists.

```python
def ensure_list(val):
    if isinstance(val, dict):
        return list(val.values())  # Extract values from dict
    return val if isinstance(val, list) else []
```

**Applied to all array fields:**
- `bankAccounts` - Account numbers (may come as {"account": "123456"})
- `upiIds` - Payment addresses (may come as {"upi": "user@upi"})
- `phishingLinks` - Malicious URLs
- `phoneNumbers` - Contact numbers (may come as {"sender": "PowerCorp"})
- `suspiciousKeywords` - Risk indicators
- `extractedEntities` - Combined entities

**Why this matters:**
The AI might return `phoneNumbers: {"sender": "PowerCorp"}` instead of `phoneNumbers: ["PowerCorp"]`. Without sanitization, Pydantic validation fails with:
```
ValidationError: Input should be a valid list
```

### MongoDB Update Strategy: The $each Array Contract

MongoDB's `$addToSet` operator requires arrays for the `$each` modifier. Our update operations strictly enforce this:

```python
# CORRECT - Array passed to $each
{"$addToSet": {"intelligence.phishingLinks": {"$each": ["link1.com", "link2.com"]}}}

# INCORRECT - Dict passed to $each (causes MongoDB error)
{"$addToSet": {"intelligence.phishingLinks": {"$each": {"0": "link1.com"}}}}
```

**Database Reliability Rules:**
1. All `$addToSet` operations use `ensure_list` before passing to `$each`
2. Arrays are validated to be actual lists (not dictionaries with numeric keys)
3. Empty or invalid data defaults to `[]` to maintain schema consistency

This ensures MongoDB updates never fail due to type mismatches, maintaining database integrity across all scam intelligence records.

---

## 5. Future Frontend: Expo Mobile App Integration

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
