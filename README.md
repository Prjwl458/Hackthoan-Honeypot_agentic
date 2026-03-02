# 🔐 Agentic AI Honeypot - Cyber-Intelligence Engine

A production-grade FastAPI application that intercepts scam messages, analyzes them using LLMs, and extracts actionable intelligence for law enforcement and security research.

## 🚀 Features

- **Real-time Scam Detection** - AI-powered analysis using Llama 3.1
- **Intelligence Extraction** - Bank accounts, UPI IDs, phone numbers, phishing links
- **Sender Verification** - Cross-references sender claims with message content
- **Risk Scoring** - Urgency level and threat assessment
- **MongoDB Persistence** - Cloud database with in-memory fallback
- **Rate Limiting** - 10 requests/minute per session
- **Production Ready** - Global error handling, health checks, CORS enabled

## 🏗️ System Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│   Mobile App    │────▶│   FastAPI API    │────▶│   Llama 3.1    │
│   (Expo/React)  │     │   (Port 9000)    │     │   (OpenRouter) │
└─────────────────┘     └──────────────────┘     └─────────────────┘
                               │
                               ▼
                        ┌──────────────────┐
                        │   MongoDB Atlas  │
                        │   (scam_logs)    │
                        └──────────────────┘
```

### Components

| Component | Technology | Purpose |
|-----------|------------|---------|
| Web Framework | FastAPI 0.109.0 | Async API server |
| LLM Engine | Llama 3.1 8B | Scam detection & analysis |
| Database | MongoDB Atlas | Persistent intelligence storage |
| HTTP Client | httpx | Non-blocking API calls |
| Validation | Pydantic 2.5.3 | Schema enforcement |

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
