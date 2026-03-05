# 🔐 Agentic AI Honeypot - Cyber-Intelligence Engine

**Version 1.2.0 Titanium** | A production-grade FastAPI application engineered for real-time scam detection and intelligence extraction.

Built with enterprise-grade security patterns including constant-time cryptographic comparison, deterministic rule-based logic, and comprehensive telemetry. Designed for integration with React Native/Expo mobile applications.

---

## 🏗️ System Architecture

The system implements a **Defense-in-Depth** strategy with five hardened architectural pillars:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         v1.2.0 TITANIUM ARCHITECTURE                        │
├─────────────────────────────────────────────────────────────────────────────┤
│  PILLAR 1: THE ARMOR (Security)                                             │
│  ├── Constant-Time API Key Validation (secrets.compare_digest)              │
│  ├── SlowAPI Rate Limiting (10 req/min, memory-backed)                      │
│  └── Restricted CORS (localhost:19000, production domain)                   │
├─────────────────────────────────────────────────────────────────────────────┤
│  PILLAR 2: THE HEART (Reliability)                                          │
│  ├── 15-Second AI Timeout with 504 Gateway Timeout                          │
│  ├── Input Normalization (invisible Unicode removal)                        │
│  └── Health Check Endpoint (/health)                                        │
├─────────────────────────────────────────────────────────────────────────────┤
│  PILLAR 3: THE DASHBOARD (Telemetry)                                        │
│  ├── Latency Tracking (latency_ms in every response)                        │
│  └── Version/Timestamp Metadata (production observability)                  │
├─────────────────────────────────────────────────────────────────────────────┤
│  PILLAR 4: THE FINAL GATEKEEPER (Deterministic Logic)                       │
│  ├── Evidence Mandate (artifacts → riskScore ≥ 75)                          │
│  ├── OTP Safeguard (clean OTP → riskScore = 5)                              │
│  └── Boolean Sync (isPhishing matches threshold ≥ 70)                       │
├─────────────────────────────────────────────────────────────────────────────┤
│  PILLAR 5: THE FILTER (Data Integrity)                                      │
│  ├── Zero-Null Policy (never return null, always "")                        │
│  └── Recursive Flattening (nested AI output sanitization)                   │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 🔒 Security Architecture

### 1. Constant-Time API Key Validation

Prevents timing attacks using `secrets.compare_digest()` for cryptographic comparison:

```python
import secrets

# Constant-time comparison prevents timing analysis attacks
if not secrets.compare_digest(provided_key, EXPECTED_KEY):
    raise HTTPException(status_code=401, detail="Invalid or missing API Key")
```

**Security Properties:**
- Execution time is independent of key position (no early exit)
- Uses HMAC-based comparison (cryptographically secure)
- Unified error message prevents information leakage
- Silent validation (debug-level logging only)

### 2. SlowAPI Rate Limiting

Production-grade rate limiting with in-memory storage:

```python
from slowapi import Limiter

limiter = Limiter(key_func=get_remote_address, storage_uri='memory://')

@app.post("/message")
@limiter.limit("10/minute")
async def handle_message(...):
```

**Configuration:**
- **Limit:** 10 requests per minute per IP address
- **Storage:** In-memory (`memory://`) for Render deployment
- **Response:** `429 Too Many Requests` when exceeded
- **Headers:** Exposes `X-RateLimit-Limit` and `X-RateLimit-Remaining`

### 3. CORS Restriction

Prevents unauthorized cross-origin access:

```python
ALLOWED_ORIGINS = [
    "http://localhost:19000",  # Expo development
    "http://localhost:3000",   # React development
    "https://your-production-domain.com",
]
```

---

## ⚡ Reliability Features

### 15-Second AI Timeout

Prevents resource exhaustion with strict timeout handling:

```python
try:
    intel, reply = await asyncio.wait_for(
        asyncio.gather(
            agent.extract_intelligence(...),
            agent.generate_response(...)
        ),
        timeout=15.0
    )
except asyncio.TimeoutError:
    raise HTTPException(status_code=504, detail="AI analysis timed out")
```

**Behavior:**
- Hard 15-second limit on AI processing
- Returns clean `504 Gateway Timeout` (not partial data)
- Includes latency telemetry even on failure

### Input Normalization

Sanitizes user input before AI processing:

```python
def normalize_input(text: str) -> str:
    # Remove invisible Unicode characters
    invisible_chars = r'[\u200b\u200c\u200d\ufeff\x00-\x08\x0b\x0c\x0e-\x1f\x7f]'
    text = re.sub(invisible_chars, '', text)
    text = re.sub(r'\s+', ' ', text)  # Normalize whitespace
    return text.strip()
```

**Removes:**
- Zero-width spaces (`\u200b`, `\u200c`, `\u200d`)
- Byte order marks (`\ufeff`)
- ASCII control characters
- Excessive whitespace

---

## 🎯 The Triple-Threat Logic

Three immutable validation rules enforced as the **Final Gatekeeper**:

### Rule 1: Evidence Mandate

**Trigger:** `phishingLinks` OR `upiIds` are NOT empty

| Field | Enforced Value |
|-------|---------------|
| `riskScore` | `max(current, 75)` |
| `isPhishing` | `True` |
| `scamType` | `"Confirmed Phishing/Scam"` |
| `agentNotes` | `"Evidence Found: [artifacts]"` |

**Logic:** Physical evidence (links, UPI IDs) forces high-risk classification regardless of AI output.

### Rule 2: OTP Transactional Safeguard

**Trigger:** `"OTP" in text` AND `no links/UPIs` AND `no "forward"/"share"`

| Field | Enforced Value |
|-------|---------------|
| `riskScore` | `5` |
| `isPhishing` | `False` |
| `scamType` | `"Safe/Transactional"` |

**Logic:** Legitimate OTPs (without forwarding instructions) are never flagged as scams.

### Rule 3: Boolean Sync

**Trigger:** Applied to ALL responses

| Condition | `isPhishing` Value |
|-----------|-------------------|
| `riskScore < 70` | `False` |
| `riskScore >= 70` | `True` |

**Logic:** The boolean flag is strictly synchronized with the risk threshold.

### Execution Priority

```
┌─────────────────────────────────────────────────────────┐
│  1. OTP Safeguard (Rule 2) - Prevents false positives   │
├─────────────────────────────────────────────────────────┤
│  2. Evidence Mandate (Rule 1) - Overrides if artifacts  │
├─────────────────────────────────────────────────────────┤
│  3. Boolean Sync (Rule 3) - Final consistency check     │
└─────────────────────────────────────────────────────────┘
```

---

## 🛡️ Final Safety Guards

Two additional production safeguards ensure API efficiency and frontend stability:

### 1. Short-Input Short-Circuit

**Trigger:** Input text length < 3 characters (e.g., "hi", "OK", "1")

**Behavior:** Returns Safe response immediately without calling AI:

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
    "threatSource": ""
  },
  "version": "1.2.0",
  "timestamp": "2024-01-15T10:30:00.000000",
  "latency_ms": 2
}
```

**Benefits:**
- **Cost Efficiency:** No AI API calls for unanalyzable inputs
- **Latency:** Sub-millisecond response (< 2ms vs 500-2000ms for AI)
- **Safety Default:** Unknown short inputs classified as Safe

### 2. Default Schema Enforcement (Zero-Null Policy)

**Purpose:** React Native and frontend applications crash when iterating over `null` values.

**Guarantee:** All array fields return `[]`, never `null`:

| Field | Type | Default |
|-------|------|---------|
| `phishingLinks` | `List[str]` | `[]` |
| `upiIds` | `List[str]` | `[]` |
| `bankAccounts` | `List[str]` | `[]` |
| `phoneNumbers` | `List[str]` | `[]` |
| `suspiciousKeywords` | `List[str]` | `[]` |
| `extractedEntities` | `List[str]` | `[]` |

**React Native Safe Usage:**
```javascript
// No null checks needed - guaranteed arrays
intelligence.phishingLinks.map(link => renderLink(link))
const hasUpi = intelligence.upiIds.length > 0;
```

**Implementation:** All responses originate from [`DEFAULT_INTEL`](main.py:214) template and pass through `finalize_intelligence()` sanitization.

---

## 📊 Data Contract

### Response Structure

Every API response follows this deterministic schema:

```json
{
  "status": "success",
  "reply": "❌ Danger: Evidence Found: evil.com",
  "intelligence": {
    "isPhishing": true,
    "riskScore": 75,
    "scamType": "Confirmed Phishing/Scam",
    "urgencyLevel": "High",
    "agentNotes": "Evidence Found: evil.com",
    "phishingLinks": ["evil.com"],
    "upiIds": [],
    "bankAccounts": [],
    "phoneNumbers": [],
    "suspiciousKeywords": ["verify", "account"],
    "extractedEntities": ["evil.com"]
  },
  "version": "1.2.0",
  "timestamp": "2024-01-15T10:30:00.000000",
  "latency_ms": 245
}
```

### Telemetry Fields

| Field | Type | Description |
|-------|------|-------------|
| `version` | string | API version (e.g., "1.2.0") |
| `timestamp` | ISO-8601 | UTC timestamp of response |
| `latency_ms` | integer | Request processing time in milliseconds |

### Zero-Null Policy

All array fields are guaranteed to return empty arrays `[]`, never `null`:

```python
# Implementation
intel["phishingLinks"] = intel.get("phishingLinks") or []
intel["upiIds"] = intel.get("upiIds") or []
intel["bankAccounts"] = intel.get("bankAccounts") or []
intel["phoneNumbers"] = intel.get("phoneNumbers") or []
intel["suspiciousKeywords"] = intel.get("suspiciousKeywords") or []
```

### Recursive Flattening

The `extractedEntities` field is recursively flattened to ensure `List[str]`:

```python
# Handles nested AI output
[['url1', 'url2']]         → ['url1', 'url2']
[{'link': 'url1'}]         → ['url1']
{'0': 'url1', '1': 'url2'} → ['url1', 'url2']
None                       → []
```

---

## 🎨 Visual Legend

Risk scores map to standardized UI components:

| Risk Score | Prefix | Color | Icon | Action |
|------------|--------|-------|------|--------|
| 0-69 | `✅ Safe:` | Green (#22c55e) | Checkmark | None |
| 70-100 | `❌ Danger:` | Red (#ef4444) | X-Circle | Block Immediately |

**Example Responses:**
```json
{"reply": "✅ Safe: Transactional OTP message"}
{"reply": "❌ Danger: Evidence Found: evil.com"}
```

---

## 🛠️ Setup

### 1. Clone & Install

```bash
git clone <repository-url>
cd honeypot-ai
python -m venv venv
venv\Scripts\activate  # Windows
pip install -r requirements.txt
```

### 2. Configure Environment

```bash
copy .env.example .env
# Edit .env with your keys:
# - API_KEY: Your secure API key
# - OPENROUTER_API_KEY: Get from https://openrouter.ai/
# - PRODUCTION_DOMAIN: Your production domain (for CORS)
```

### 3. Run the Server

```bash
# Development
python -m uvicorn main:app --reload --host 0.0.0.0 --port 8000

# Production
python -m uvicorn main:app --host 0.0.0.0 --port 8000
```

### 4. Health Check

```bash
curl http://localhost:8000/health
# Response: {"status": "online", "version": "1.2.0", "timestamp": "..."}
```

---

## 🧪 Testing

### PowerShell Test

```powershell
$headers = @{
    "X-API-Key" = "prajwal_hackathon_key_2310"
    "Content-Type" = "application/json"
}
$body = '{"message": {"text": "Your OTP is 123456"}, "sessionId": "test123"}'
Invoke-WebRequest -Uri "http://localhost:8000/message" -Method POST -Headers $headers -Body $body
```

### cURL Test

```bash
curl -X POST http://localhost:8000/message \
  -H "X-API-Key: prajwal_hackathon_key_2310" \
  -H "Content-Type: application/json" \
  -d '{"message": {"text": "Click here: evil.com"}, "sessionId": "test123"}'
```

---

## 📄 License

MIT License - See [LICENSE](LICENSE) for details.

---

**Engineered for Production** | **Class 11 CS Portfolio Project** | **Version 1.2.0 Titanium**
