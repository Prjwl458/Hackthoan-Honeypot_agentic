# 🛡️ Agentic AI Honeypot - Complete Documentation

## 📋 Project Overview

This is a **high-performance, asynchronous AI honeypot system** designed to:
- Engage with scammers in real-time conversations
- Detect scam intent using LLM and keyword-based fallback mechanisms
- Extract actionable intelligence (UPI IDs, Bank Accounts, Phishing Links, Phone Numbers)
- Report captured data to external security platforms via secure webhooks

---

## 📁 Project Structure

```
Honepot ai/
├── main.py           # FastAPI application entry point
├── agent.py          # ScamAgent class (async LLM integration & intelligence extraction)
├── models.py         # Pydantic request/response schemas
├── database.py       # MongoDB integration with in-memory fallback
├── test_api.py       # Test script for /message endpoint
├── test_root.py      # Test script for / (root) endpoint
├── requirements.txt  # Python dependencies
├── .env.example      # Environment variable template
├── .gitignore        # Git ignore rules
└── plans/           # Architecture planning documents
```

---

## 🔧 Technical Stack

| Component | Technology |
|-----------|------------|
| **Python** | Python 3.11+ |
| **Framework** | FastAPI (Python 3.10+) |
| **AI/LLM** | OpenRouter API (Mistral 7B Instruct) |
| **Concurrency** | FastAPI BackgroundTasks + asyncio |
| **HTTP Client** | httpx (async) library |
| **Database** | MongoDB Atlas with in-memory fallback |
| **Validation** | Pydantic v2 |
| **Deployment** | Render-ready (PORT environment variable support) |

---

## 🗄️ Database Configuration

### MongoDB Atlas (Primary)
The system uses MongoDB Atlas for persistent storage of:
- Conversation history
- Extracted intelligence (UPI IDs, bank accounts, etc.)
- Session metadata

### In-Memory Fallback
If MongoDB is unavailable, the system automatically falls back to in-memory storage. This ensures scammer engagement continues even during database outages.

### Connection
```python
MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/honeypot
```

---

## 🔐 Security

### Environment Variables
All sensitive configuration is managed through environment variables. Copy `.env.example` to `.env` and fill in your values:

| Variable | Description | Required |
|----------|-------------|----------|
| `API_KEY` | API key for request authentication | Yes |
| `OPENROUTER_API_KEY` | OpenRouter LLM API key | Yes |
| `MONGODB_URI` | MongoDB Atlas connection string | No* |
| `GUVI_CALLBACK_URL` | Webhook URL for intelligence reporting | No |
| `PORT` | Server port (default: 8000) | No |
| `DEBUG` | Enable debug mode | No |

*If not set, system uses in-memory storage fallback

## 🚀 Key Features

### 1. Instant Engagement
- Asynchronous architecture responds to scammers in under 1 second
- 8-second timeout protection prevents system hanging

### 2. Deep Intelligence Extraction
- LLM-powered analysis identifies scammer pressure tactics
- Regex patterns extract financial entities (UPI IDs, bank accounts, phone numbers, URLs)
- Dual extraction approach ensures comprehensive data capture

### 3. Resilience Engine
- "Strict JSON Isolation" handles malformed or conversational AI outputs
- Graceful degradation when LLM fails (keyword-based fallback)
- Comprehensive error handling with fallback responses

### 4. Automated Callback
- Real-time reporting of captured data to security platforms
- Non-blocking background tasks for webhook delivery
- Detailed logging for debugging and monitoring

### 5. Cloud Ready
- Fully containerized logic
- Environment variable configuration
- Render deployment ready with PORT support

---

## 📄 File Details

### 1. `main.py` - FastAPI Application

#### Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | POST | Primary endpoint for scam engagement |
| `/message` | POST | Alias for backward compatibility |

#### Request Schema

```json
{
  "sessionId": "string",
  "message": {
    "sender": "scammer",
    "text": "string",
    "timestamp": 1234567890
  },
  "conversationHistory": [
    {
      "sender": "scammer",
      "text": "previous message",
      "timestamp": 1234567890
    }
  ],
  "metadata": {
    "channel": "SMS",
    "language": "English",
    "locale": "IN"
  }
}
```

#### Response Schema

```json
{
  "status": "success",
  "reply": "AI-generated response to keep scammer engaged"
}
```

#### Key Functions

| Function | Location | Purpose |
|----------|----------|---------|
| `verify_api_key()` | Line 38 | Validates `x-api-key` header against hardcoded key |
| `send_guvi_callback()` | Line 43 | Background task to report intelligence to GUVI webhook |
| `handle_message_root()` | Line 56 | Main request handler with 8-second timeout protection |
| `validation_exception_handler()` | Line 22 | Custom error handler for request validation errors |

#### Configuration

| Variable | Value | Source |
|----------|-------|--------|
| `API_KEY` | Environment variable required | Yes |
| `GUVI_CALLBACK_URL` | `https://hackathon.guvi.in/api/updateHoneyPotFinalResult` | Environment variable with fallback |

---

### 2. `agent.py` - ScamAgent Class

#### Class: `ScamAgent`

##### Constructor

```python
def __init__(self):
    self.openrouter_api_key = os.getenv("OPENROUTER_API_KEY")
    self.openrouter_url = "https://openrouter.ai/api/v1/chat/completions"
    self.model = "mistralai/mistral-7b-instruct"
```

##### Methods

| Method | Location | Input | Output | Description |
|--------|----------|-------|--------|-------------|
| `_call_llm_api()` | Line 15 | `messages: list`, `response_as_json: bool` | `dict` | Internal method to call OpenRouter API |
| `detect_scam()` | Line 41 | `message: str`, `history: list` | `bool` | Detects if message contains scam intent |
| `generate_response()` | Line 61 | `message: str`, `history: list`, `metadata: dict` | `str` | Generates tarpitting response |
| `extract_intelligence()` | Line 90 | `message: str`, `history: list` | `dict` | Extracts entities and suspicious keywords |

##### Intelligence Extraction Patterns

| Entity | Regex Pattern | Example Matches |
|--------|---------------|-----------------|
| UPI IDs | `[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}` | `scammer@paytm`, `user.name@bank` |
| URLs | `(https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+)` | `http://fake-bank.com` |
| Bank Accounts | `\b\d{9,18}\b` | `12345678901` |
| Phone Numbers | `\b(?:\+?\d{1,3}[- ]?)?\(?\d{3}\)?[- ]?\d{3}[- ]?\d{4}\b` | `+91 9988776655` |

##### Intelligence Output Schema

```json
{
  "bankAccounts": ["list of account numbers"],
  "upiIds": ["list of UPI IDs"],
  "phishingLinks": ["list of URLs"],
  "phoneNumbers": ["list of phone numbers"],
  "suspiciousKeywords": ["list of keywords"],
  "agentNotes": "Summary of scam intent"
}
```

##### Fallback Mechanism

- **Scam Detection**: Falls back to keyword matching if LLM fails
  - Keywords: `verify`, `blocked`, `suspended`, `upi`, `win`, `gift`, `account`
- **Intelligence Extraction**: Uses regex-only extraction if LLM fails
- **Response Generation**: Returns generic response if LLM fails

---

### 3. `test_api.py` - Test Script

Tests the `/message` endpoint with a simulated work-from-home scam:

```
"CONGRATULATIONS! You have been selected for a Work-From-Home job with Amazon. 
Earn 5000 daily. Just pay a 500 registration fee to our HR UPI: jobhero@paytm. 
Contact +91 9988776655 for details."
```

### 4. `test_root.py` - Test Script

Tests the `/` endpoint with a simulated account blocking scam:

```
"Your account is blocked. Pay 5000 now to unlock."
```

---

## 🔄 Data Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                    1. Scammer sends message                     │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│              2. API Key Validation (x-api-key header)           │
│                     └── Invalid → 403 Error                     │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│              3. Scam Detection (LLM → Keyword Fallback)         │
│                  └── Not Scam → Return generic greeting         │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│           4. Intelligence Extraction (Regex + LLM)              │
│                  - Extract UPI IDs                              │
│                  - Extract Bank Accounts                        │
│                  - Extract Phone Numbers                        │
│                  - Extract Phishing Links                       │
│                  - Identify Suspicious Keywords                 │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│              5. Generate Tarpitting Response                    │
│           (AI persona: confused, worried, human user)           │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│        6. Background Callback to GUVI with intelligence         │
│                      (Non-blocking)                             │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                   7. Return response to scammer                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🔐 Security Features

### 1. API Key Authentication
- All requests require valid `x-api-key` header
- Hardcoded key for hackathon: `<HIDDEN_API_KEY>`

### 2. Timeout Protection
- 8-second timeout on AI processing prevents system hanging
- Fallback responses ensure continuity

### 3. Graceful Degradation
- System continues functioning even if LLM fails
- Keyword-based fallback for scam detection
- Regex-based fallback for intelligence extraction

### 4. Error Handling
- Comprehensive try-catch blocks
- Detailed logging for debugging
- Fallback responses prevent information leakage

---

## 🚀 Deployment

### Environment Variables Required

| Variable | Description | Required |
|----------|-------------|----------|
| `OPENROUTER_API_KEY` | API key for OpenRouter LLM service | Yes |
| `GUVI_CALLBACK_URL` | Webhook URL for reporting | No (has default) |
| `PORT` | Server port | No (default: 8000) |

### Running Locally

```bash
# Install dependencies
pip install -r requirements.txt

# Set environment variables (Linux/Mac)
export OPENROUTER_API_KEY="your-key-here"

# Set environment variables (Windows CMD)
set OPENROUTER_API_KEY=your-key-here

# Set environment variables (Windows PowerShell)
$env:OPENROUTER_API_KEY="your-key-here"

# Run server
python main.py
```

### Running with Uvicorn

```bash
# Development mode
uvicorn main:app --reload --port 8000

# Production mode
uvicorn main:app --host 0.0.0.0 --port 8000
```

### Dependencies (`requirements.txt`)

| Package | Purpose |
|---------|---------|
| `fastapi` | Modern web framework for building APIs |
| `uvicorn[standard]` | ASGI server for FastAPI |
| `pydantic` | Data validation using Python type hints |
| `python-dotenv` | Load environment variables from .env file |
| `requests` | HTTP client for external API calls |

---

## 📊 Callback Payload Structure

The system sends the following payload to GUVI webhook:

```json
{
  "sessionId": "session-identifier",
  "scamDetected": true,
  "totalMessagesExchanged": 5,
  "extractedIntelligence": {
    "bankAccounts": ["12345678901"],
    "upiIds": ["scammer@paytm"],
    "phishingLinks": ["http://fake-bank.com"],
    "phoneNumbers": ["+91 9988776655"],
    "suspiciousKeywords": ["URGENT", "blocked", "OTP"]
  },
  "agentNotes": "Scammer attempting to extract banking credentials"
}
```

---

## 🎯 Key Design Principles

### 1. Fail-Safe Architecture
- System remains operational even with LLM failures
- Multiple fallback mechanisms at every critical point

### 2. Non-Blocking Callbacks
- Intelligence reporting happens in background
- Main response is not delayed by webhook delivery

### 3. Tarpitting Strategy
- AI persona designed to waste scammer's time
- Provides fake, realistic credentials when asked
- Varies responses to maintain engagement

### 4. Dual Extraction
- Combines regex patterns with LLM analysis
- Ensures comprehensive intelligence gathering
- Regex provides baseline, LLM adds context

---

## 🧪 Testing

### Manual Testing

1. Start the server:
   ```bash
   python main.py
   ```

2. Run test scripts:
   ```bash
   # Test root endpoint
   python test_root.py
   
   # Test /message endpoint
   python test_api.py
   ```

### Expected Test Results

**test_root.py:**
- Status Code: 200
- Response contains AI-generated reply engaging with the scammer

**test_api.py:**
- Status Code: 200
- Response contains AI-generated reply
- Background callback sent to GUVI webhook

---

## 📝 Sample Output

### Successful Extraction Example

```json
{
  "scamDetected": true,
  "extractedIntelligence": {
    "bankAccounts": ["SBI"],
    "suspiciousKeywords": ["URGENT", "blocked in 2 hours", "OTP", "account number"]
  },
  "agentNotes": "The message is a classic phishing scam intent on creating urgency to extract sensitive financial data."
}
```

---

## 🔧 Troubleshooting

### Common Issues

| Issue | Solution |
|-------|----------|
| `OPENROUTER_API_KEY not set` warning | Set the environment variable |
| 403 Forbidden error | Verify `x-api-key` header matches your configured API_KEY |
| AI Processing timeout | System will use fallback response automatically |
| JSON Decode Error | System will use regex-based extraction |

### Debug Logging

The system provides detailed logging:
- `RAW REQUEST:` - Incoming request body
- `DEBUG: GUVI Callback` - Webhook response status
- `ERROR:` - Any errors during processing
- `WARNING:` - Missing configuration

---

## 📜 License

This project was created for a hackathon event.

---

## 👤 Author

Created for GUVI Hackathon
