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

### Social Engineering Detection
The system detects sophisticated **OTP forwarding scams** - attacks that use legitimate-looking OTPs as bait but include dangerous forwarding instructions:

```python
# Example: Social Engineering Detection
Message: "Your OTP is 1234. Forward this to our agent to verify."
Result: Risk 100 (Critical) - Social Engineering detected

Message: "Your OTP is 5678. Do not share with anyone."
Result: Risk 5 (Safe) - Transactional message
```

**Keywords monitored:** `forward`, `share with`, `send to`, `share this`, `send this`

### Evidence-Based Risk Capping
To prevent **"Honeypot Bias"** (where urgency language alone triggers false high-risk classifications), the system implements a **hard risk cap**:

| Evidence Present | Max Risk | Classification |
|------------------|----------|----------------|
| None | 40 | Unverified/Suspicious |
| Links only | 60 | Potential Phishing |
| UPI/Bank + Links | 80 | High Risk Scam |
| All artifacts + PII request | 100 | Critical Threat |

**Logic:** A message cannot exceed Risk 40 without at least one physical artifact (phishingLinks, upiIds, bankAccounts).

### Recursive Data Flattening (React Native/Expo Compatible)
The `ensure_list()` helper function ensures **100% compatibility** with React Native/Expo frontends by recursively sanitizing AI output:

```python
# Problem: AI returns nested structures that cause Pydantic validation errors
Input: [['url1', 'url2']] or [{'link': 'url1'}] or {'0': 'link1'}

# Solution: Deep Flat Sanitizer
Output: ['url1', 'url2']  # Always a flat list of strings
```

**Applied to all array fields:**
- `phishingLinks` - URLs extracted from nested AI responses
- `upiIds` - Payment addresses from dict-wrapped outputs
- `bankAccounts` - Account numbers from object formats
- `extractedEntities` - Combined entities (most commonly nested)

This ensures the API never returns `400 Bad Request` errors due to schema mismatches, maintaining seamless mobile app integration.

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
