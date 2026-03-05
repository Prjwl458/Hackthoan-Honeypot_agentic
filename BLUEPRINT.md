# 🏗️ Agentic AI Honeypot - Technical Blueprint

**Version 1.2.0 Titanium** | Production Architecture Document

---

## 1. Executive Summary

The Agentic AI Honeypot is a hardened FastAPI application designed for real-time scam detection. Version 1.2.0 Titanium introduces enterprise-grade security patterns including constant-time cryptographic comparison, deterministic rule-based logic, and comprehensive telemetry.

**Key Engineering Decisions:**
- **Defense in Depth:** Five architectural pillars provide overlapping security guarantees
- **Deterministic Logic:** Triple-Threat rules eliminate AI hallucinations
- **Zero-Trust Validation:** Every input is sanitized, every output is validated
- **Observable by Design:** Full telemetry for production monitoring

---

## 2. The Five Architectural Pillars

### Pillar 1: The Armor (Security)

#### 1.1 Constant-Time API Key Validation

**Threat Model:** Timing attacks on API key comparison can leak key length and character positions through statistical analysis of response times.

**Mitigation:** `secrets.compare_digest()` provides HMAC-based constant-time comparison.

```python
import secrets

async def verify_api_key(x_api_key: Optional[str] = Header(None)) -> str:
    if not x_api_key:
        raise HTTPException(status_code=401, detail="Invalid or missing API Key")
    
    provided_key = x_api_key.strip()
    
    # Constant-time comparison prevents timing analysis
    if not secrets.compare_digest(provided_key, EXPECTED_KEY):
        raise HTTPException(status_code=401, detail="Invalid or missing API Key")
    
    return provided_key
```

**Security Properties:**
- Execution time independent of key position (no early exit)
- HMAC-based comparison (cryptographically secure)
- Unified error message prevents information leakage
- Debug-level logging only (silent on success)

#### 1.2 SlowAPI Rate Limiting

**Configuration:**
```python
from slowapi import Limiter
from slowapi.util import get_remote_address

# Memory-backed storage for Render deployment
limiter = Limiter(
    key_func=get_remote_address,
    storage_uri='memory://'
)

@app.post("/message")
@limiter.limit("10/minute")
async def handle_message(...):
```

**Behavior:**
| Condition | Response |
|-----------|----------|
| Under limit | Request processed |
| Over limit | `429 Too Many Requests` |
| Rate limit headers | `X-RateLimit-Limit`, `X-RateLimit-Remaining` |

**Rationale:** In-memory storage avoids Redis dependency on Render free tier while providing per-IP rate limiting.

#### 1.3 CORS Restriction

```python
ALLOWED_ORIGINS = [
    "http://localhost:19000",  # Expo Metro bundler
    "http://localhost:19006",  # Expo web
    "http://localhost:3000",   # React development
    "https://your-production-domain.com",  # Production
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Authorization", "X-API-Key", "Content-Type", "X-Request-ID"],
    expose_headers=["X-RateLimit-Limit", "X-RateLimit-Remaining"],
)
```

---

### Pillar 2: The Heart (Reliability)

#### 2.1 15-Second AI Timeout

**Problem:** LLM API calls can hang indefinitely, consuming worker threads and causing cascading failures.

**Solution:** Hard timeout with structured 504 response.

```python
try:
    intel, reply = await asyncio.wait_for(
        asyncio.gather(
            agent.extract_intelligence(message_text, history, sender_id),
            agent.generate_response(message_text, history, metadata)
        ),
        timeout=15.0
    )
except asyncio.TimeoutError:
    latency_ms = int((time() - start_time) * 1000)
    raise HTTPException(
        status_code=504,
        detail={
            "status": "error",
            "error": "Gateway Timeout",
            "message": "AI analysis timed out after 15 seconds",
            "latency_ms": latency_ms,
            "version": API_VERSION,
            "timestamp": datetime.utcnow().isoformat()
        }
    )
```

**Key Points:**
- Returns `504 Gateway Timeout` (not 500 or partial data)
- Includes  even on failure
- Clean error structure for client handling

#### 2.2 Input Normalization

**Threat:** Invisible Unicode characters can bypass regex patterns and poison AI context.

**Implementation:**
```python
def normalize_input(text: str) -> str:
    """
    Sanitize input by removing invisible Unicode characters.
    
    Removes:
    - \u200b: Zero-width space
    - \u200c: Zero-width non-joiner  
    - \u200d: Zero-width joiner
    - \ufeff: Byte order mark (BOM)
    - \x00-\x1f: ASCII control characters (except \t, \n, \r)
    - \x7f: DEL character
    """
    if not text:
        return ""
    
    text = text.strip()
    invisible_chars = r'[\u200b\u200c\u200d\ufeff\x00-\x08\x0b\x0c\x0e-\x1f\x7f]'
    text = re.sub(invisible_chars, '', text)
    text = re.sub(r'\s+', ' ', text)  # Normalize whitespace
    return text.strip()
```

**Example:**
```
Input:  "  Hello\u200bWorld  \x00\x01  "
Output: "Hello World"
```

#### 2.3 Health Check Endpoint

```bash
GET /health

Response:
{
    "status": "online",
    "version": "1.2.0",
    "timestamp": "2024-01-15T10:30:00.000000"
}
```

**Purpose:** Load balancer health checks and deployment verification.

#### 2.4 Short-Input Short-Circuit

**Problem:** Very short inputs (< 3 characters) are insufficient for meaningful AI analysis and waste API credits. Examples: "hi", "OK", "1".

**Solution:** Pre-flight check returns Safe response immediately without calling AI.

```python
# =====================================================================
# GUARD 1: Short-Input Short-Circuit
# If input is too short (< 3 chars), return Safe without calling AI
# =====================================================================
if len(message_text) < 3:
    logger.info(f"Short-input short-circuit: '{message_text}' (length: {len(message_text)})")
    short_response = {
        "bankAccounts": [],
        "upiIds": [],
        "phishingLinks": [],
        "phoneNumbers": [],
        "suspiciousKeywords": [],
        "agentNotes": "Input too short for analysis",
        "scamType": "Safe/Transactional",
        "urgencyLevel": "Low",
        "riskScore": 0,
        "extractedEntities": [],
        "threatSource": "",
        "isPhishing": False
    }
    return HoneypotResponse(
        status="success",
        reply="✅ Safe: Input too short for analysis",
        intelligence=short_response
    )
```

**Response Structure:**

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
- **Cost Efficiency:** No AI API calls for inputs that cannot contain scams
- **Latency:** Sub-millisecond response (< 2ms vs 500-2000ms for AI)
- **Safety Default:** Unknown short inputs classified as Safe (conservative approach)
- **Schema Compliance:** Returns complete intelligence object matching full AI flow

---

### Pillar 3: The Dashboard (Telemetry)

#### 3.1 Latency Tracking

Every request captures processing time:

```python
# Request start
start_time = time()

# ... processing ...

# Response inclusion
latency_ms = int((time() - start_time) * 1000)
```

#### 3.2 Response Schema

All responses include root-level telemetry:

```json
{
  "status": "success",
  "reply": "...",
  "intelligence": {...},
  "version": "1.2.0",
  "timestamp": "2024-01-15T10:30:00.000000",
  "latency_ms": 245
}
```

**Fields:**
| Field | Type | Description |
|-------|------|-------------|
| `version` | string | API semantic version |
| `timestamp` | ISO-8601 | UTC response timestamp |
| `latency_ms` | integer | Wall-clock processing time |

---

### Pillar 4: The Final Gatekeeper (Deterministic Logic)

Three immutable rules enforce logical consistency and override AI hallucinations.

#### Rule 1: Evidence Mandate

**Trigger:** `phishingLinks` OR `upiIds` are NOT empty

**Enforcement:**
```python
has_evidence = len(phishing_links) > 0 or len(upi_ids) > 0

if has_evidence:
    intel["riskScore"] = max(risk_score, 75)  # Force ≥ 75
    intel["isPhishing"] = True
    intel["scamType"] = "Confirmed Phishing/Scam"
    intel["urgencyLevel"] = "High"
    intel["agentNotes"] = f"Evidence Found: {artifact_str}"
    reply = f"❌ Danger: Evidence Found: {artifact_str}"
    return intel, reply  # Early exit
```

**Logic:** Physical evidence (links, UPI IDs) takes precedence over AI scoring. If artifacts exist, the message is high-risk regardless of AI output.

#### Rule 2: OTP Transactional Safeguard

**Trigger:** `"OTP" in text` AND `no links/UPIs` AND `no "forward"/"share"`

**Enforcement:**
```python
has_otp = "otp" in message_lower
has_links_or_upi = len(phishing_links) > 0 or len(upi_ids) > 0
has_forward_share = "forward" in message_lower or "share" in message_lower

if has_otp and not has_links_or_upi and not has_forward_share:
    intel["riskScore"] = 5  # Force low
    intel["isPhishing"] = False
    intel["scamType"] = "Safe/Transactional"
    intel["agentNotes"] = "Safe: Transactional OTP message"
    reply = "✅ Safe: Transactional OTP message"
    return intel, reply  # Early exit
```

**Logic:** Legitimate OTPs (without forwarding instructions or suspicious links) are never flagged as scams. Prevents false positives on transactional messages.

#### Rule 3: Boolean Sync

**Trigger:** Applied to ALL remaining responses

**Enforcement:**
```python
if risk_score < 70:
    intel["isPhishing"] = False
else:
    intel["isPhishing"] = True
```

**Logic:** The boolean flag is strictly synchronized with the risk threshold at 70. Eliminates any inconsistency between `riskScore` and `isPhishing`.

#### Execution Priority

```
┌─────────────────────────────────────────────────────────┐
│  STEP 1: OTP Safeguard (Rule 2)                         │
│  ├── Prevents false positives on transactional messages │
│  └── Early exit if triggered                            │
├─────────────────────────────────────────────────────────┤
│  STEP 2: Evidence Mandate (Rule 1)                      │
│  ├── Overrides OTP Safeguard if artifacts found         │
│  └── Forces high-risk classification                    │
├─────────────────────────────────────────────────────────┤
│  STEP 3: Boolean Sync (Rule 3)                          │
│  └── Final consistency check (threshold: 70)            │
└─────────────────────────────────────────────────────────┘
```

---

### Pillar 5: The Filter (Data Integrity)

#### 5.1 Zero-Null Policy & Default Schema Enforcement

**Problem:** Frontend applications (especially React Native) crash when iterating over `null` values or receiving incomplete objects.

**Solution:** Two-layer enforcement guarantees consistent schema compliance.

**Layer 1: DEFAULT_INTEL Template**

All responses originate from a canonical template ensuring every field has a valid default:

```python
# Default intelligence template for consistent API responses
DEFAULT_INTEL = {
    "bankAccounts": [],
    "upiIds": [],
    "phishingLinks": [],
    "phoneNumbers": [],
    "suspiciousKeywords": [],
    "agentNotes": "",
    "scamType": "Safe/Transactional",
    "urgencyLevel": "Low",
    "riskScore": 5,
    "extractedEntities": [],
    "threatSource": "System",
    "isPhishing": False
}
```

**Layer 2: Runtime Zero-Null Enforcement**

The `finalize_intelligence()` function ensures AI outputs never violate the contract:

```python
def finalize_intelligence(intel: Dict[str, Any], ...) -> tuple:
    # ZERO NULLS ENFORCEMENT - Ensure all artifact lists are never null
    intel["phishingLinks"] = intel.get("phishingLinks") or []
    intel["upiIds"] = intel.get("upiIds") or []
    intel["bankAccounts"] = intel.get("bankAccounts") or []
    intel["phoneNumbers"] = intel.get("phoneNumbers") or []
    intel["suspiciousKeywords"] = intel.get("suspiciousKeywords") or []
```

**Schema Guarantees:**

| Field | Default | Never Null |
|-------|---------|------------|
| `phishingLinks` | `[]` | ✓ Always List[str] |
| `upiIds` | `[]` | ✓ Always List[str] |
| `bankAccounts` | `[]` | ✓ Always List[str] |
| `phoneNumbers` | `[]` | ✓ Always List[str] |
| `suspiciousKeywords` | `[]` | ✓ Always List[str] |
| `extractedEntities` | `[]` | ✓ Always List[str] |
| `agentNotes` | `""` | ✓ Always string |
| `scamType` | `"Safe/Transactional"` | ✓ Always string |
| `urgencyLevel` | `"Low"` | ✓ Always string |
| `threatSource` | `"System"` | ✓ Always string |

**React Native Compatibility:**

```javascript
// Safe iteration - never throws TypeError
intelligence.phishingLinks.map(link => ...)
intelligence.upiIds.forEach(upi => ...)

// No defensive null checks needed
const hasLinks = intelligence.phishingLinks.length > 0;
```

**Null Transformations:**
| Input | Output |
|-------|--------|
| `null` | `[]` |
| `undefined` | `[]` |
| `[]` | `[]` |
| `['item']` | `['item']` |

#### 5.2 Recursive Flattening

**Problem:** LLMs return nested structures that violate Pydantic schemas.

**Solution:** Recursive flattener ensures `List[str]` for all array fields.

```python
def flatten_to_strings(val):
    """Recursively flatten nested lists and extract string values."""
    result = []
    if isinstance(val, list):
        for item in val:
            result.extend(flatten_to_strings(item))
    elif isinstance(val, dict):
        for v in val.values():
            result.extend(flatten_to_strings(v))
    elif isinstance(val, str):
        result.append(val)
    return result

intel["extractedEntities"] = flatten_to_strings(raw_entities)
```

**Transformations:**
| Input | Output |
|-------|--------|
| `[['url1', 'url2']]` | `['url1', 'url2']` |
| `[{'link': 'url1'}]` | `['url1']` |
| `{'0': 'url1', '1': 'url2'}` | `['url1', 'url2']` |
| `None` | `[]` |
| `'string'` | `[]` |

---

## 3. Data Contract

### 3.1 Request Schema

```json
{
  "message": {
    "text": "Your OTP is 123456",
    "sender": "user",
    "sender_id": "+1234567890",
    "timestamp": 1705315800
  },
  "sessionId": "session_abc123",
  "conversationHistory": [],
  "metadata": {}
}
```

### 3.2 Response Schema

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

### 3.3 Intelligence Object Fields

| Field | Type | Description |
|-------|------|-------------|
| `isPhishing` | boolean | Deterministic flag based on riskScore >= 70 |
| `riskScore` | integer | 0-100 danger rating |
| `scamType` | string | Classification (Safe/Transactional, Confirmed Phishing/Scam) |
| `urgencyLevel` | string | Low, Medium, High |
| `agentNotes` | string | Human-readable summary |
| `phishingLinks` | List[str] | Extracted suspicious URLs |
| `upiIds` | List[str] | Extracted UPI payment addresses |
| `bankAccounts` | List[str] | Extracted account numbers |
| `phoneNumbers` | List[str] | Extracted phone numbers |
| `suspiciousKeywords` | List[str] | Detected risk indicators |
| `extractedEntities` | List[str] | Combined flattened entities |

---

## 4. Risk Score Mapping

| Risk Score | Classification | isPhishing | UI Color | Action |
|------------|---------------|------------|----------|--------|
| 0-69 | Safe/Transactional | False | Green | None |
| 70-100 | Confirmed Phishing/Scam | True | Red | Block |

**Thresholds:**
- **70:** Boolean sync threshold (`isPhishing` becomes `True`)
- **75:** Evidence mandate minimum (if artifacts present)

---

## 5. Error Handling

### 5.1 HTTP Status Codes

| Code | Scenario | Response Structure |
|------|----------|-------------------|
| 200 | Success | Full response with telemetry |
| 401 | Invalid/missing API key | `{"detail": "Invalid or missing API Key"}` |
| 429 | Rate limit exceeded | SlowAPI default response |
| 504 | AI timeout | Error object with latency, version, timestamp |
| 500 | Internal error | Error object with optional debug info |

### 5.2 Timeout Response Example

```json
{
  "status": "error",
  "error": "Gateway Timeout",
  "message": "AI analysis timed out after 15 seconds",
  "latency_ms": 15000,
  "version": "1.2.0",
  "timestamp": "2024-01-15T10:30:15.000000"
}
```

---

## 6. Deployment Notes

### 6.1 Render Configuration

**Environment Variables:**
```bash
API_KEY=your_secure_key
OPENROUTER_API_KEY=your_openrouter_key
PRODUCTION_DOMAIN=https://your-app.onrender.com
DEBUG=false
```

**Build Command:**
```bash
pip install -r requirements.txt
```

**Start Command:**
```bash
python -m uvicorn main:app --host 0.0.0.0 --port $PORT
```

### 6.2 Memory Storage Limitation

The current SlowAPI configuration uses in-memory storage (`memory://`). This means:
- Rate limits are per-instance (not shared across workers)
- Limits reset on deployment/restart
- Suitable for single-instance deployments on Render free tier

**Future Enhancement:** Migrate to Redis-backed storage for distributed rate limiting:
```python
limiter = Limiter(key_func=get_remote_address, storage_uri='redis://localhost:6379')
```

---

## 7. Testing

### 7.1 Health Check

```bash
curl https://your-app.onrender.com/health
```

### 7.2 Valid Request

```bash
curl -X POST https://your-app.onrender.com/message \
  -H "X-API-Key: your_api_key" \
  -H "Content-Type: application/json" \
  -d '{
    "message": {"text": "Your OTP is 123456"},
    "sessionId": "test123"
  }'
```

### 7.3 Rate Limit Test

```bash
for i in {1..12}; do
  curl -X POST https://your-app.onrender.com/message \
    -H "X-API-Key: your_api_key" \
    -H "Content-Type: application/json" \
    -d '{"message": {"text": "test"}}' \
    -w "\nHTTP Status: %{http_code}\n"
done
```

---

**Document Version:** 1.2.0 Titanium  
**Last Updated:** 2024-01-15  
**Author:** Prajwal
