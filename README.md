# 🔐 Agentic AI Honeypot - Cyber-Intelligence Engine

A production-grade FastAPI application that intercepts scam messages, analyzes them using LLMs, and extracts actionable intelligence for law enforcement and security research.

## 🚀 Features

- **Evidence-Based Scoring** - No message exceeds Risk 40 without physical artifacts (links, UPI, bank accounts)
- **Safety Sandwich Pipeline** - Three-layer validation: Whitelist → AI Analysis → Evidence Guard
- **Real-time Scam Detection** - AI-powered analysis using Llama 3.1 with objective scoring
- **Intelligence Extraction** - Bank accounts, UPI IDs, phone numbers, phishing links
- **MongoDB Persistence** - Cloud database with in-memory fallback
- **Rate Limiting** - 10 requests/minute per session
- **Production Ready** - Global error handling, health checks, CORS enabled

## 🔒 Security Features

### The Deterministic Decision Matrix

The system implements **three immutable validation rules** in strict priority order:

```
┌─────────────────────────────────────────────────────────────────┐
│  1. OTP Transactional Safeguard (Rule 2)                        │
│     └── Force Safe (riskScore=5) if OTP without artifacts       │
├─────────────────────────────────────────────────────────────────┤
│  2. Evidence Mandate (Rule 1) [OVERRIDES Rule 2]                │
│     └── Force High Risk (riskScore≥75) if artifacts found       │
├─────────────────────────────────────────────────────────────────┤
│  3. Master Boolean Sync (Rule 3)                                │
│     └── isPhishing = (riskScore >= 30)                          │
└─────────────────────────────────────────────────────────────────┘
```

**Override Logic:** Rule 1 (Evidence) overrides Rule 2 (OTP Safeguard) if a phishing link is detected in an OTP message.

### Social Engineering Detection

Detects sophisticated **OTP forwarding scams** - attacks using legitimate-looking OTPs with dangerous forwarding instructions:

| Message | Detection | Result |
|---------|-----------|--------|
| "Your OTP is 1234" | No danger keywords | ✅ Safe (Risk 5) |
| "Your OTP is 1234. Forward to agent" | "forward" detected | ⚠️ Warning (Risk 30+) |
| "Your OTP is 1234. Click evil.com" | Link detected | ❌ Danger (Risk 75+) |

**Danger Keywords:** `forward`, `share`, `send to`, `share this`, `send this`

### The 'Zero-Null' Policy

All artifact fields are guaranteed to return an empty list `[]` and **never null**, ensuring frontend stability:

```python
# Implementation
intel["phishingLinks"] = intel.get("phishingLinks") or []
intel["upiIds"] = intel.get("upiIds") or []
intel["bankAccounts"] = intel.get("bankAccounts") or []
```

| Input | Output |
|-------|--------|
| `null` | `[]` |
| `undefined` | `[]` |
| `['evil.com']` | `['evil.com']` |

This prevents React Native crashes when iterating over arrays.

### Data Sanitization (The Flattener)

The `flatten_to_strings()` function recursively sanitizes AI output to ensure `extractedEntities` is always `List[str]`:

```python
# Handles nested structures
[['url1', 'url2']]           → ['url1', 'url2']
[{'link': 'url1'}]           → ['url1']
{'0': 'url1', '1': 'url2'}   → ['url1', 'url2']
None                         → []
```

**Frontend Compatibility:**
```javascript
// Safe iteration - always works
intel.extractedEntities.map(item => <Text>{item}</Text>)
```

### Visual Legend for Frontend

The API returns prefixed replies for direct UI rendering:

| Risk Score | Prefix | Category | Color | Icon | Action |
|------------|--------|----------|-------|------|--------|
| 0-29 | `✅ Safe:` | Safe/Transactional | Green | Checkmark | None |
| 30-74 | `⚠️ Warning:` | Suspicious/Unverified | Amber | Triangle | Review |
| 75-100 | `❌ Danger:` | Confirmed Phishing/Scam | Red | X-Circle | Block |

**Example Responses:**
```json
{"reply": "✅ Safe: Transactional OTP message"}
{"reply": "⚠️ Warning: Suspicious pattern detected"}
{"reply": "❌ Danger: Evidence Found: evil.com"}
```

### Evidence-Based Risk Capping

To prevent **"Honeypot Bias"**, the system implements a **hard risk cap**:

| Evidence Present | Max Risk | Classification |
|------------------|----------|----------------|
| None | 40 | Unverified/Suspicious |
| Links only | 60 | Potential Phishing |
| UPI/Bank + Links | 80 | High Risk Scam |
| All artifacts + PII request | 100 | Critical Threat |

A message cannot exceed Risk 40 without at least one physical artifact (phishingLinks, upiIds, bankAccounts).

## 🏗️ System Architecture (The Safety Sandwich)

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   Mobile App    │────▶│   PRE-PROCESS   │────▶│     PROCESS     │────▶│  POST-PROCESS   │
│   (Expo/React)  │     │   (Whitelist)   │     │  (AI Analysis)  │     │ (Evidence Guard)│
└─────────────────┘     └─────────────────┘     └─────────────────┘     └─────────────────┘
                                                                │
                                                                ▼
                         ┌──────────────────┐             ┌──────────────────┐
                         │   MongoDB Atlas  │◀────────────│   Response API   │
                         │   (scam_logs)    │             │   (Risk Score)   │
                         └──────────────────┘             └──────────────────┘
```

### The Three-Layer Validation Pipeline

| Layer | Purpose | Key Logic |
|-------|---------|-----------|
| **Pre-Process** | Fast-path legitimate messages | OTP/Banking patterns → immediate safe classification |
| **Process** | Deep AI analysis of non-whitelist messages | Evidence-based scoring with LLM |
| **Post-Process** | Prevent false positives from urgency alone | **Hard cap at Risk 40** without physical artifacts |

### Evidence Requirement Rule
A message **CANNOT** exceed **Risk 40** unless at least one physical artifact is extracted:
- `phishingLinks` (suspicious URLs)
- `upiIds` (payment addresses)
- `bankAccounts` (account numbers)

This prevents the "Honeypot Bias" where urgency language alone triggers false high-risk classifications.

### Components

| Component | Technology | Purpose |
|-----------|------------|---------|
| Web Framework | FastAPI 0.109.0 | Async API server |
| LLM Engine | Llama 3.1 8B | Evidence-based scam analysis |
| Database | MongoDB Atlas | Persistent intelligence storage |
| HTTP Client | httpx | Non-blocking API calls |
| Validation | Pydantic 2.5.3 | Schema enforcement with `ensure_list` |
| Data Integrity | `ensure_list` helper | Converts AI dicts to Pydantic-compliant lists |

## 📦 Setup

### 1. Clone & Install

```bash
# Clone the repository
git clone <repository-url>
cd honeypot-ai

# Create virtual environment
python -m venv venv
venv\Scripts\activate  # Windows
# source venv/bin/activate  # Linux/Mac

# Install dependencies
pip install -r requirements.txt
```

### 2. Configure Environment

```bash
# Copy the template
copy .env.example .env

# Edit .env with your keys:
# - API_KEY: Your secure API key
# - OPENROUTER_API_KEY: Get from https://openrouter.ai/
# - MONGODB_URI: Get from MongoDB Atlas (optional)
```

### 3. Run the Server

```bash
# Development
python -m uvicorn main:app --host 127.0.0.1 --port 9000 --reload

# Production
python -m uvicorn main:app --host 0.0.0.0 --port 9000
```

### 4. Health Check

```bash
curl http://127.0.0.1:9000/health
# Response: {"status":"online"}
```

## 📡 Sample API Request

### POST /message

```bash
curl -X POST http://127.0.0.1:9000/message \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your_api_key_here" \
  -d '{
    "message": "Your Netflix account has been suspended. Verify now to restore: netflix-verify.com/restore",
    "senderId": "+1-555-0123",
    "sessionId": "session_001"
  }'
```

### Response

```json
{
  "status": "success",
  "response": "Threat Detected: Phishing attempt - Suspicious Netflix impersonation scam",
  "intelligence": {
    "scamType": "Phishing",
    "urgencyLevel": "High",
    "riskScore": 85,
    "extractedEntities": {
      "phishingLinks": ["netflix-verify.com"],
      "phoneNumbers": ["+1-555-0123"],
      "bankAccounts": [],
      "upiIds": []
    }
  }
}
```

## 🔒 Security

- All secrets loaded from environment variables (`.env`)
- API key required for all endpoints
- Rate limited: 10 requests/minute per session
- CORS configured for production deployment

## 📄 License

MIT License 
