# Agentic AI Honeypot - System Architecture Blueprint

## System Overview

The Agentic AI Honeypot is a real-time scam intelligence system that uses AI to engage scammers, detect malicious intent, and extract actionable intelligence. This document provides a detailed technical blueprint of the system architecture.

---

## High-Level Architecture

```
                                    INTERNET
                                        |
                                        v
    +------------------------------------------------------------------+
    |                         FASTAPI SERVER                           |
    |                          (main.py)                               |
    |                                                                  |
    |   +--------------------------------------------------------+    |
    |   |                    REQUEST LAYER                        |    |
    |   |  - API Key Validation                                   |    |
    |   |  - Request Parsing                                      |    |
    |   |  - Error Handling                                       |    |
    |   +--------------------------------------------------------+    |
    |                              |                                   |
    |                              v                                   |
    |   +--------------------------------------------------------+    |
    |   |                 BUSINESS LOGIC LAYER                   |    |
    |   |  - Scam Detection                                       |    |
    |   |  - Intelligence Extraction                              |    |
    |   |  - Response Generation                                  |    |
    |   +--------------------------------------------------------+    |
    |                              |                                   |
    |                              v                                   |
    |   +--------------------------------------------------------+    |
    |   |                 BACKGROUND TASKS LAYER                  |    |
    |   |  - Webhook Callbacks                                    |    |
    |   |  - Non-blocking Intelligence Reporting                  |    |
    |   +--------------------------------------------------------+    |
    |                                                                  |
    +------------------------------------------------------------------+
                                        |
                                        v
    +------------------------------------------------------------------+
    |                        SCAM AGENT                                |
    |                         (agent.py)                               |
    |                                                                  |
    |   +------------------+    +------------------+    +-----------+  |
    |   |   detect_scam    |    |extract_intelligence|   |generate  |  |
    |   |                  |    |                   |   |_response |  |
    |   +------------------+    +------------------+    +-----------+  |
    |           |                       |                    |        |
    |           v                       v                    v        |
    |   +--------------------------------------------------------+    |
    |   |              LLM API CLIENT                            |    |
    |   |          (OpenRouter Integration)                       |    |
    |   +--------------------------------------------------------+    |
    |                                                                  |
    +------------------------------------------------------------------+
                                        |
                                        v
    +------------------------------------------------------------------+
    |                     OPENROUTER API                               |
    |                  (Mistral 7B Instruct)                           |
    +------------------------------------------------------------------+
```

---

## Component Architecture

### 1. FastAPI Application (main.py)

```
+------------------------------------------------------------------+
|                        main.py Structure                          |
+------------------------------------------------------------------+
|                                                                   |
|  Imports:                                                         |
|  - FastAPI, HTTPException, BackgroundTasks, Request              |
|  - Pydantic BaseModel                                             |
|  - asyncio, requests, os, time                                    |
|  - ScamAgent from agent.py                                        |
|                                                                   |
+------------------------------------------------------------------+
|                                                                   |
|  Configuration:                                                   |
|  +-------------------------------------------------------------+  |
|  | API_KEY = os.getenv("API_KEY")                           |  |
|  | GUVI_CALLBACK_URL = env("GUVI_CALLBACK_URL", default)      |  |
|  +-------------------------------------------------------------+  |
|                                                                   |
+------------------------------------------------------------------+
|                                                                   |
|  Exception Handlers:                                              |
|  +-------------------------------------------------------------+  |
|  | validation_exception_handler()                             |  |
|  |   - Catches RequestValidationError                         |  |
|  |   - Logs raw request body                                  |  |
|  |   - Returns 422 with error details                         |  |
|  +-------------------------------------------------------------+  |
|                                                                   |
+------------------------------------------------------------------+
|                                                                   |
|  Security Functions:                                              |
|  +-------------------------------------------------------------+  |
|  | verify_api_key(x_api_key: Header)                          |  |
|  |   - Compares against API_KEY                               |  |
|  |   - Raises HTTPException(403) if invalid                   |  |
|  +-------------------------------------------------------------+  |
|                                                                   |
+------------------------------------------------------------------+
|                                                                   |
|  Background Tasks:                                                |
|  +-------------------------------------------------------------+  |
|  | send_guvi_callback(session_id, payload)                    |  |
|  |   - POST to GUVI_CALLBACK_URL                              |  |
|  |   - 15-second timeout                                       |  |
|  |   - Error logging                                           |  |
|  +-------------------------------------------------------------+  |
|                                                                   |
+------------------------------------------------------------------+
|                                                                   |
|  Endpoints:                                                       |
|  +-------------------------------------------------------------+  |
|  | POST /                                                     |  |
|  |   - Primary endpoint                                       |  |
|  |   - Calls handle_message_root()                            |  |
|  +-------------------------------------------------------------+  |
|  +-------------------------------------------------------------+  |
|  | POST /message                                              |  |
|  |   - Backward compatibility alias                           |  |
|  |   - Routes to handle_message_root()                        |  |
|  +-------------------------------------------------------------+  |
|                                                                   |
+------------------------------------------------------------------+
```

### 2. Request Handler Flow (handle_message_root)

```
+------------------------------------------------------------------+
|              handle_message_root() Flow Diagram                    |
+------------------------------------------------------------------+

START
  |
  v
+-------------------+
| API Key Check     |---- Invalid ----> HTTPException(403)
+-------------------+
  |
  v
+-------------------+
| Parse Request     |---- Error ----> Return error response
| - sessionId       |
| - message.text    |
| - conversationHistory |
| - metadata        |
+-------------------+
  |
  v
+-------------------+
| detect_scam()     |---- Not Scam ---> Return generic greeting
+-------------------+
  |
  v (Is Scam)
  |
+-------------------+
| asyncio.wait_for( |
|   extract_intel,  |---- Timeout ---> Use fallback response
|   generate_resp,  |                  Empty intelligence
|   timeout=8s      |
| )                 |
+-------------------+
  |
  v
+-------------------+
| Build Callback    |
| Payload           |
+-------------------+
  |
  v
+-------------------+
| background_tasks. |
| add_task(         |
|   send_callback   |
| )                 |
+-------------------+
  |
  v
+-------------------+
| Return Response   |
| {status, reply}   |
+-------------------+
  |
  v
END
```

### 3. ScamAgent Class (agent.py)

```
+------------------------------------------------------------------+
|                     ScamAgent Class Structure                     |
+------------------------------------------------------------------+
|                                                                   |
|  Attributes:                                                      |
|  +-------------------------------------------------------------+  |
|  | openrouter_api_key: str (from env)                          |  |
|  | openrouter_url: str (API endpoint)                          |  |
|  | model: str ("mistralai/mistral-7b-instruct")               |  |
|  +-------------------------------------------------------------+  |
|                                                                   |
+------------------------------------------------------------------+
|                                                                   |
|  Methods:                                                         |
|                                                                   |
|  +-------------------------------------------------------------+  |
|  | _call_llm_api(messages, response_as_json=False)            |  |
|  |                                                             |  |
|  | Input:                                                      |  |
|  |   - messages: list[dict] (OpenAI format)                   |  |
|  |   - response_as_json: bool (flag for JSON mode)            |  |
|  |                                                             |  |
|  | Process:                                                    |  |
|  |   1. Build headers with Authorization                      |  |
|  |   2. Build payload with model, messages, temperature=0     |  |
|  |   3. POST to OpenRouter API                                 |  |
|  |   4. Return JSON response                                   |  |
|  |                                                             |  |
|  | Error Handling:                                             |  |
|  |   - raise_for_status() on HTTP errors                       |  |
|  +-------------------------------------------------------------+  |
|                                                                   |
|  +-------------------------------------------------------------+  |
|  | detect_scam(message, history) -> bool                       |  |
|  |                                                             |  |
|  | Process:                                                    |  |
|  |   1. Build prompt for scam detection                       |  |
|  |   2. Call LLM API                                           |  |
|  |   3. Parse response ('true'/'false')                       |  |
|  |                                                             |  |
|  | Fallback:                                                   |  |
|  |   - Keyword matching: verify, blocked, suspended,          |  |
|  |     upi, win, gift, account                                 |  |
|  +-------------------------------------------------------------+  |
|                                                                   |
|  +-------------------------------------------------------------+  |
|  | generate_response(message, history, metadata) -> str       |  |
|  |                                                             |  |
|  | System Prompt:                                              |  |
|  |   - Persona: Actor in cybersecurity simulation             |  |
|  |   - Goal: Tarpitting (keep attacker engaged)               |  |
|  |   - Rules: Never refuse, provide fake credentials          |  |
|  |   - Output: Single message, 1-2 sentences                   |  |
|  |                                                             |  |
|  | Process:                                                    |  |
|  |   1. Build messages with system prompt                      |  |
|  |   2. Add conversation history                              |  |
|  |   3. Add current message                                    |  |
|  |   4. Call LLM API                                           |  |
|  |   5. Return generated response                              |  |
|  |                                                             |  |
|  | Fallback:                                                   |  |
|  |   - Generic confused response                               |  |
|  +-------------------------------------------------------------+  |
|                                                                   |
|  +-------------------------------------------------------------+  |
|  | extract_intelligence(message, history) -> dict             |  |
|  |                                                             |  |
|  | Regex Extraction:                                           |  |
|  |   - UPI IDs: [a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}         |  |
|  |   - URLs: https?:// pattern                                  |  |
|  |   - Bank Accounts: \d{9,18}                                 |  |
|  |   - Phone Numbers: International format pattern             |  |
|  |                                                             |  |
|  | LLM Extraction:                                             |  |
|  |   - Intent identification                                   |  |
|  |   - Financial entity extraction                             |  |
|  |   - Suspicious keyword identification                       |  |
|  |                                                             |  |
|  | JSON Parsing:                                               |  |
|  |   - Regex isolation of JSON object                          |  |
|  |   - JSONDecodeError handling                                |  |
|  |                                                             |  |
|  | Merge Strategy:                                             |  |
|  |   - Combine regex + LLM results                             |  |
|  |   - Deduplicate with set()                                   |  |
|  |   - Ensure all required keys present                        |  |
|  +-------------------------------------------------------------+  |
|                                                                   |
+------------------------------------------------------------------+
```

---

## Data Models

### Request Model

```
+------------------------------------------------------------------+
|                       Request Payload Schema                       |
+------------------------------------------------------------------+

{
  "sessionId": string,           // Unique session identifier
  "message": {
    "sender": string,            // "scammer" or "user"
    "text": string,              // Message content
    "timestamp": number          // Unix timestamp (milliseconds)
  },
  "conversationHistory": [       // Array of previous messages
    {
      "sender": string,
      "text": string,
      "timestamp": number
    }
  ],
  "metadata": {
    "channel": string,           // "SMS", "WhatsApp", etc.
    "language": string,          // "English", "Hindi", etc.
    "locale": string             // "IN", "US", etc.
  }
}
```

### Response Model

```
+------------------------------------------------------------------+
|                       Response Payload Schema                      |
+------------------------------------------------------------------+

{
  "status": "success" | "error",
  "reply": string                 // AI-generated response
}
```

### Intelligence Model

```
+------------------------------------------------------------------+
|                    Intelligence Payload Schema                     |
+------------------------------------------------------------------+

{
  "bankAccounts": string[],       // Extracted bank account numbers
  "upiIds": string[],             // Extracted UPI IDs
  "phishingLinks": string[],      // Extracted suspicious URLs
  "phoneNumbers": string[],       // Extracted phone numbers
  "suspiciousKeywords": string[], // Identified pressure words
  "agentNotes": string            // AI summary of scam intent
}
```

### Callback Payload Model

```
+------------------------------------------------------------------+
|                     Callback Payload Schema                        |
+------------------------------------------------------------------+

{
  "sessionId": string,
  "scamDetected": boolean,
  "totalMessagesExchanged": number,
  "extractedIntelligence": {
    "bankAccounts": string[],
    "upiIds": string[],
    "phishingLinks": string[],
    "phoneNumbers": string[],
    "suspiciousKeywords": string[]
  },
  "agentNotes": string
}
```

---

## Sequence Diagrams

### 1. Normal Scam Detection Flow

```
Scammer     FastAPI      ScamAgent     OpenRouter     GUVI
   |           |             |             |           |
   |--POST---->|             |             |           |
   |           |--verify---->|             |           |
   |           |    key      |             |           |
   |           |             |             |           |
   |           |--detect---->|             |           |
   |           |   scam      |             |           |
   |           |             |--LLM call-->|           |
   |           |             |<--response--|           |
   |           |<--true------|             |           |
   |           |             |             |           |
   |           |--extract--->|             |           |
   |           |  intel      |             |           |
   |           |             |--LLM call-->|           |
   |           |             |<--JSON------|           |
   |           |<--intel-----|             |           |
   |           |             |             |           |
   |           |--generate-->|             |           |
   |           |  response   |             |           |
   |           |             |--LLM call-->|           |
   |           |             |<--response--|           |
   |           |<--reply-----|             |           |
   |           |             |             |           |
   |           |--------background--------->|           |
   |           |         callback           |           |
   |<--reply---|             |             |           |
   |           |             |             |           |
```

### 2. Timeout Fallback Flow

```
Scammer     FastAPI      ScamAgent     OpenRouter
   |           |             |             |
   |--POST---->|             |             |
   |           |--verify---->|             |
   |           |    key      |             |
   |           |             |             |
   |           |--detect---->|             |
   |           |   scam      |             |
   |           |             |--LLM call-->|
   |           |             |<--response--|
   |           |<--true------|             |
   |           |             |             |
   |           |--async      |             |
   |           |  wait_for   |             |
   |           |  (8s timeout)            |
   |           |             |--LLM call-->|
   |           |             |   (slow)    |
   |           |             |             |
   |           | X timeout   |             |
   |           |             |             |
   |           | (use fallback)           |
   |<--fallback reply--------|             |
   |           |             |             |
```

### 3. LLM Failure Fallback Flow

```
Scammer     FastAPI      ScamAgent     OpenRouter
   |           |             |             |
   |--POST---->|             |             |
   |           |             |             |
   |           |--detect---->|             |
   |           |   scam      |             |
   |           |             |--LLM call-->|
   |           |             | X  error    |
   |           |             |             |
   |           |             | (fallback to
   |           |             |  keywords)  |
   |           |<--true------|             |
   |           |  (keyword)  |             |
   |           |             |             |
   |           |--extract--->|             |
   |           |  intel      |             |
   |           |             |--LLM call-->|
   |           |             | X  error    |
   |           |             |             |
   |           |             | (regex only)
   |           |<--intel-----|             |
   |           |  (regex)    |             |
   |           |             |             |
   |<--reply---|             |             |
   |           |             |             |
```

---

## Error Handling Strategy

```
+------------------------------------------------------------------+
|                    Error Handling Decision Tree                    |
+------------------------------------------------------------------+

Error Occurred
      |
      v
+---------------+
| Error Type?   |
+---------------+
      |
      +-- HTTP Error (API Key)
      |       |
      |       v
      |   Return 403 Forbidden
      |
      +-- Validation Error
      |       |
      |       v
      |   Log raw body
      |   Return 422 Unprocessable Entity
      |
      +-- LLM API Error
      |       |
      |       v
      |   +---------------+
      |   | Which Method? |
      |   +---------------+
      |       |
      |       +-- detect_scam
      |       |       |
      |       |       v
      |       |   Use keyword fallback
      |       |
      |       +-- generate_response
      |       |       |
      |       |       v
      |       |   Return generic response
      |       |
      |       +-- extract_intelligence
      |               |
      |               v
      |           Use regex-only extraction
      |
      +-- Timeout Error
      |       |
      |       v
      |   Use fallback response
      |   Return empty intelligence
      |
      +-- JSON Decode Error
      |       |
      |       v
      |   Log raw output
      |   Use regex extraction
      |
      +-- Callback Error
              |
              v
          Log error
          Continue (non-blocking)
```

---

## Deployment Architecture

```
+------------------------------------------------------------------+
|                    Production Deployment                           |
+------------------------------------------------------------------+

                    +-----------------+
                    |   Load Balancer |
                    +-----------------+
                            |
            +---------------+---------------+
            |                               |
            v                               v
    +---------------+               +---------------+
    |  Container 1  |               |  Container 2  |
    |  (Render)     |               |  (Render)     |
    |               |               |               |
    |  - FastAPI    |               |  - FastAPI    |
    |  - Uvicorn    |               |  - Uvicorn    |
    |  - ScamAgent  |               |  - ScamAgent  |
    +---------------+               +---------------+
            |                               |
            +---------------+---------------+
                            |
                            v
                    +-----------------+
                    |  Environment    |
                    |  Variables:     |
                    |  - OPENROUTER   |
                    |  - PORT         |
                    |  - GUVI_CALLBACK|
                    +-----------------+
                            |
            +---------------+---------------+
            |                               |
            v                               v
    +---------------+               +---------------+
    | OpenRouter    |               | GUVI Webhook  |
    | API           |               | Endpoint      |
    +---------------+               +---------------+
```

---

## Performance Considerations

### Response Time Targets

| Operation | Target | Fallback |
|-----------|--------|----------|
| API Key Validation | <10ms | N/A |
| Scam Detection | <2s | Keyword check <50ms |
| Intelligence Extraction | <5s | Regex <100ms |
| Response Generation | <3s | Generic response <1ms |
| Total Response | <8s | Fallback response |

### Concurrency Model

```
+------------------------------------------------------------------+
|                    Concurrency Architecture                       |
+------------------------------------------------------------------+

                    FastAPI Application
                            |
            +---------------+---------------+
            |                               |
            v                               v
    +---------------+               +---------------+
    | Request Handler|              | Background    |
    | (async)        |              | Tasks         |
    |               |               |               |
    | - await parse |               | - Callback    |
    | - await detect|               | - Non-blocking|
    | - await wait_for|             | - Fire/forget|
    |   (8s timeout)|               |               |
    +---------------+               +---------------+
            |                               |
            v                               v
    +---------------+               +---------------+
    | asyncio.to_thread|             | requests.post |
    | (blocking LLM) |               | (sync HTTP)   |
    +---------------+               +---------------+

Key Points:
- Main handler is async for fast response
- LLM calls run in thread pool (asyncio.to_thread)
- Callbacks run in background (BackgroundTasks)
- Timeout protection prevents hanging
```

---

## Security Architecture

```
+------------------------------------------------------------------+
|                    Security Layers                                 |
+------------------------------------------------------------------+

Layer 1: Transport Security
+--------------------------------------------------+
| - HTTPS (production)                             |
| - Secure webhook endpoints                       |
+--------------------------------------------------+

Layer 2: Authentication
+--------------------------------------------------+
| - API Key in header (x-api-key)                  |
| - Constant-time comparison (prevent timing)      |
+--------------------------------------------------+

Layer 3: Input Validation
+--------------------------------------------------+
| - Request body parsing                           |
| - Type validation (Pydantic)                     |
| - Error handling without info leakage            |
+--------------------------------------------------+

Layer 4: Error Handling
+--------------------------------------------------+
| - Generic error responses                        |
| - No stack traces in production                  |
| - Detailed logging (internal only)               |
+--------------------------------------------------+

Layer 5: Resilience
+--------------------------------------------------+
| - Timeout protection                             |
| - Graceful degradation                           |
| - Fallback mechanisms                            |
+--------------------------------------------------+
```

---

## Monitoring & Logging

### Log Points

| Location | Log Type | Information |
|----------|----------|-------------|
| `validation_exception_handler` | ERROR | Raw request body on validation failure |
| `handle_message_root` | DEBUG | Raw request body |
| `send_guvi_callback` | DEBUG | Callback response status |
| `send_guvi_callback` | ERROR | Callback failure details |
| `detect_scam` | ERROR | LLM failure, fallback used |
| `generate_response` | ERROR | LLM failure, fallback used |
| `extract_intelligence` | ERROR | JSON decode failure |
| `extract_intelligence` | DEBUG | Raw LLM output (first/last 100 chars) |

### Recommended Metrics

- Request count by endpoint
- Response time distribution
- Scam detection rate
- LLM API latency
- Callback success rate
- Error rate by type
- Timeout frequency

---

## Future Enhancements

### Potential Improvements

1. **Authentication**
   - JWT token support
   - Rate limiting per API key
   - IP-based throttling

2. **Intelligence Extraction**
   - Support for more entity types
   - Multi-language extraction
   - Image/media analysis

3. **Response Generation**
   - Persona customization
   - Multi-language responses
   - Emotion/sentiment adaptation

4. **Reporting**
   - Multiple webhook endpoints
   - Retry mechanism for failed callbacks
   - Batch reporting

5. **Monitoring**
   - Prometheus metrics endpoint
   - Health check endpoint
   - OpenTelemetry tracing

---

*Document Version: 1.0*
*Last Updated: 2026-02-25*