# Agentic AI Honeypot - Production Upgrade Plan

## Executive Summary

This document outlines the comprehensive upgrade plan to transform the current Agentic AI Honeypot codebase into a production-grade, scalable, and maintainable system.

---

## Current State Analysis

### Issues Identified

| # | Issue | Severity | Location |
|---|-------|----------|----------|
| 1 | **Synchronous HTTP calls** using `requests` library blocking the event loop | HIGH | [`agent.py:37`](agent.py:37), [`main.py:46`](main.py:46) |
| 2 | **No database persistence** - conversationHistory and intelligence stored only in-memory | HIGH | N/A |
| 3 | **Hardcoded API key** - `<HIDDEN_API_KEY>` exposed in source | HIGH | [`main.py`](main.py) |
| 4 | **Manual field extraction** - No Pydantic request models, raw dict parsing | MEDIUM | [`main.py:71-77`](main.py:71) |
| 5 | **Limited error handling** - No global exception handler for uncaught crashes | MEDIUM | [`main.py:22-30`](main.py:22) |
| 6 | **Redundant LLM calls** - `detect_scam()` always calls LLM, no caching | LOW | [`agent.py:41-59`](agent.py:41) |

---

## Recommended Changes

### 1. Environment Variables (.env structure)

Create a `.env.example` file and refactor all hardcoded values:

```env
# API Security
API_KEY=<HIDDEN_API_KEY>

# LLM Configuration
OPENROUTER_API_KEY=your_openrouter_key_here

# Callback Configuration
GUVI_CALLBACK_URL=https://hackathon.guvi.in/api/updateHoneyPotFinalResult

# MongoDB Atlas Configuration
MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/honeypot?retryWrites=true&w=majority

# Application Settings
PORT=8000
LOG_LEVEL=INFO
```

### 2. Async Transition (httpx.AsyncClient)

Replace all synchronous `requests` calls with `httpx.AsyncClient`:

#### In [`agent.py`](agent.py):
- Replace [`requests.post()`](agent.py:37) with `httpx.AsyncClient.post()`
- Make `_call_llm_api()` an async method
- Make all public methods (`detect_scam`, `generate_response`, `extract_intelligence`) async

#### In [`main.py`](main.py):
- Replace [`requests.post()`](main.py:46) in `send_guvi_callback()` with async httpx call

### 3. MongoDB Atlas Integration

Add database persistence for conversation history and intelligence:

```python
# Proposed database schema (MongoDB)

# Collection: conversations
{
  "_id": ObjectId,
  "sessionId": "string",
  "createdAt": datetime,
  "updatedAt": datetime,
  "messages": [
    {
      "sender": "scammer" | "user",
      "text": "string",
      "timestamp": int
    }
  ],
  "metadata": {
    "channel": "SMS",
    "language": "English",
    "locale": "IN"
  },
  "intelligence": {
    "bankAccounts": ["string"],
    "upiIds": ["string"],
    "phishingLinks": ["string"],
    "phoneNumbers": ["string"],
    "suspiciousKeywords": ["string"],
    "agentNotes": "string"
  },
  "messageCount": int
}
```

### 4. Pydantic Models

Create structured request/response schemas:

```python
# models.py (new file)

class MessageContent(BaseModel):
    sender: str
    text: str
    timestamp: int

class ConversationMessage(BaseModel):
    sender: str
    text: str
    timestamp: int

class Metadata(BaseModel):
    channel: str = "SMS"
    language: str = "English"
    locale: str = "IN"

class HoneypotRequest(BaseModel):
    sessionId: str
    message: MessageContent
    conversationHistory: List[ConversationMessage] = []
    metadata: Metadata = Metadata()

class HoneypotResponse(BaseModel):
    status: str
    reply: str

class IntelligenceData(BaseModel):
    bankAccounts: List[str] = []
    upiIds: List[str] = []
    phishingLinks: List[str] = []
    phoneNumbers: List[str] = []
    suspiciousKeywords: List[str] = []
    agentNotes: str = ""
```

### 5. Global Error Handling

Implement comprehensive exception handling:

```python
# In main.py
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={
            "status": "error",
            "error": "Internal server error",
            "message": str(exc) if DEBUG else "An unexpected error occurred"
        }
    )
```

### 6. ScamAgent Refactoring

Simplify the class by:
- Creating a shared `httpx.AsyncClient` instance
- Adding optional caching for scam detection results
- Consolidating error handling

---

## Implementation Sequence

```mermaid
graph TD
    A[Start] --> B[Create .env structure]
    B --> C[Update requirements.txt]
    C --> D[Create Pydantic models]
    D --> E[Refactor agent.py with async httpx]
    E --> F[Refactor main.py with async callbacks]
    F --> G[Add MongoDB integration]
    G --> H[Add global error handler]
    H --> I[Update documentation]
    I --> J[End]
```

---

## New Dependencies

Add to `requirements.txt`:

```
httpx>=0.25.0
motor>=3.3.0
pymongo>=4.6.0
python-dotenv>=1.0.0
```

---

## Files to Modify

| File | Changes |
|------|---------|
| `.env.example` | New file - environment variable template |
| `requirements.txt` | Add httpx, motor, pymongo |
| `models.py` | New file - Pydantic schemas |
| `database.py` | New file - MongoDB connection and operations |
| `agent.py` | Convert to async, use httpx |
| `main.py` | Use Pydantic models, async callbacks, global error handler |
| `ARCHITECTURE.md` | Update with new architecture |
| `DOCUMENTATION.md` | Update with new setup instructions |

---

## Migration Checklist

- [ ] Create `.env` file from `.env.example`
- [ ] Set up MongoDB Atlas cluster and get connection string
- [ ] Update OpenRouter API key in environment
- [ ] Test all endpoints with new async implementation
- [ ] Verify database persistence is working

---

## Estimated Changes Summary

| Category | Files Changed | New Files |
|----------|---------------|------------|
| Refactoring | 2 | 0 |
| New Models | 0 | 2 |
| Documentation | 2 | 1 |
| Configuration | 1 | 1 |

---

Do you approve this plan? Once confirmed, I'll proceed with implementing all the changes in sequence.
