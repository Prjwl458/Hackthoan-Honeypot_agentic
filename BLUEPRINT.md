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

#### Layer 1: Pre-Process (Instruction-Based Whitelisting)
**Purpose**: Fast-path legitimate messages while detecting instruction-based scams

The whitelist uses **context-aware pattern matching** that examines both content AND intent:

##### Standard Safe Patterns

| Pattern | Detection | Result |
|---------|-----------|--------|
| OTP | `[0-9]{4,6}` + "verification/code" keywords | Risk: 5, Type: Safe/Transactional |
| Bank Update | "A/C XX" + "debited/credited" + balance | Risk: 10, Type: Bank Update |

##### Social Engineering Detection (The OTP Rule)

**The Critical Exception**: If an OTP message contains **forwarding instructions**, it's immediately escalated to maximum risk:

```
IF message.contains("OTP") 
   AND (message.contains("forward") OR message.contains("share with") OR message.contains("send to")):
       riskScore = 100
       scamType = "Social Engineering"
```

**Examples:**

| Message | Risk | Reason |
|---------|------|--------|
| "Your OTP is 1234. Do not share." | 5 | Standard safe OTP |
| "Your OTP is 1234. Forward this to our agent to verify." | 100 | **Forwarding instruction detected** |
| "Your OTP is 5678. Share with customer care." | 100 | **Sharing instruction detected** |

This **Instruction-Based Whitelisting** prevents sophisticated social engineering attacks that use legitimate-looking OTPs as the bait, but dangerous forwarding instructions as the hook.

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

## 2. v1.2 Titanium: The 5 Architectural Pillars

The v1.2 Titanium release introduces 5 production-grade architectural pillars that harden the system for enterprise deployment.

---

### Pillar 1: The Armor (Security)

#### Rate Limiting with slowapi
**Purpose:** Prevent API credit exhaustion and protect against abuse

**Configuration:**
```python
from slowapi import Limiter

limiter = Limiter(key_func=get_remote_address)

@app.post("/message")
@limiter.limit("10/minute")
async def handle_message(...):
    # Rate limited to 10 requests per minute per IP
```

**Behavior:**
- Returns `429 Too Many Requests` when limit exceeded
- Tracks by client IP address
- Independent of session-based rate limiting (dual protection)

#### Restricted CORS
**Purpose:** Prevent unauthorized cross-origin requests

**Allowed Origins:**
```python
ALLOWED_ORIGINS = [
    "http://localhost:19000",  # Expo development
    "http://localhost:19006",  # Expo web
    "http://localhost:3000",   # React development
    "https://your-production-domain.com",  # Production (via env)
]
```

**Configuration:**
- Methods: `GET`, `POST`, `OPTIONS`
- Headers: `Authorization`, `X-API-Key`, `Content-Type`, `X-Request-ID`
- Exposed: `X-RateLimit-Limit`, `X-RateLimit-Remaining`

---

### Pillar 2: The Heart (Reliability)

#### Request Timeout Protection
**Purpose:** Prevent hung connections from consuming resources

**Implementation:**
```python
try:
    intel, reply = await asyncio.wait_for(
        asyncio.gather(
            agent.extract_intelligence(...),
            agent.generate_response(...)
        ),
        timeout=15.0  # 15 seconds max
    )
except asyncio.TimeoutError:
    raise HTTPException(
        status_code=504,
        detail={
            "status": "error",
            "error": "Gateway Timeout",
            "message": "AI analysis timed out after 15 seconds"
        }
    )
```

**Response:** Returns clean `504 Gateway Timeout` instead of partial fallback data

#### Health Check Endpoint
**Purpose:** Service status monitoring for load balancers

```bash
GET /health

Response:
{
    "status": "online",
    "version": "1.2.0",
    "timestamp": "2024-01-15T10:30:00.000000"
}
```

---

### Pillar 3: The Dashboard (Telemetry)

#### Latency Tracking
**Purpose:** Monitor API performance and identify bottlenecks

**Implementation:**
```python
start_time = time()
# ... processing ...
latency_ms = int((time() - start_time) * 1000)
```

**Response Fields:**
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

#### Version & Timestamp
Every response includes:
- `version`: API version (e.g., "1.2.0")
- `timestamp`: ISO-formatted UTC timestamp
- `latency_ms`: Request processing time in milliseconds

---

### Pillar 4: The Final Gatekeeper (Deterministic Logic)

#### Rule 1: Evidence Mandate (Updated for v1.2)
**Trigger:** `phishingLinks` OR `upiIds` are NOT empty

| Field | Enforced Value |
|-------|---------------|
| `isPhishing` | `True` |
| `riskScore` | `max(current, 70)` |
| `agentNotes` | `"Evidence Found: [artifacts]"` |

**Change from v1.0:** Threshold lowered from 75 to 70; `bankAccounts` removed from trigger

#### Rule 2: OTP Transactional Safeguard
**Trigger:** `"OTP" in text` AND `no links/UPIs` AND `no "forward"/"share"`

| Field | Enforced Value |
|-------|---------------|
| `isPhishing` | `False` |
| `riskScore` | `5` |
| `scamType` | `"Safe/Transactional"` |

#### Rule 3: Master Boolean Sync
**Logic:** Strict threshold at 30

```python
if risk_score < 30:
    intel["isPhishing"] = False
else:
    intel["isPhishing"] = True
```

---

### Pillar 5: The Filter (Input Normalization)

#### normalize_input() Function
**Purpose:** Sanitize user input before AI processing

**Operations:**
1. **Strip whitespace:** Remove leading/trailing spaces
2. **Remove invisible Unicode:**
   - Zero-width space (`\u200b`)
   - Zero-width non-joiner (`\u200c`)
   - Zero-width joiner (`\u200d`)
   - Byte order mark (`\ufeff`)
   - ASCII control characters (`\x00-\x1f` except `\t`, `\n`, `\r`)
3. **Normalize spaces:** Collapse multiple spaces to single space

**Implementation:**
```python
def normalize_input(text: str) -> str:
    text = text.strip()
    invisible_chars = r'[\u200b\u200c\u200d\ufeff\x00-\x08\x0b\x0c\x0e-\x1f\x7f]'
    text = re.sub(invisible_chars, '', text)
    text = re.sub(r'\s+', ' ', text)
    return text.strip()
```

**Example:**
```
Input:  "  Hello\u200bWorld  \x00\x01  "
Output: "Hello World"
```

---

## 3. The Final Three: Deterministic Override Rules

The `finalize_intelligence()` function implements **three immutable validation rules** as the FINAL GATE. These rules enforce **100% logical harmony** by correcting AI hallucinations.

The `finalize_intelligence()` function implements **three immutable validation rules** as the FINAL GATE. These rules enforce **100% logical harmony** by correcting AI hallucinations and guaranteeing consistent output.

---

### 2.1 The Deterministic Decision Matrix

Rules are evaluated in **strict priority order** with early-exit behavior. Once a rule triggers, subsequent rules are skipped.

#### Priority Order

```
┌─────────────────────────────────────────────────────────────────┐
│  PRIORITY 1: Rule 2 (OTP Transactional Safeguard)               │
│  ├── Trigger: 'OTP' in message AND no artifacts AND no danger   │
│  ├── Action: Force Safe classification (riskScore=5)            │
│  └── Exit: Returns immediately if triggered                     │
├─────────────────────────────────────────────────────────────────┤
│  PRIORITY 2: Rule 1 (Evidence Mandate)                          │
│  ├── Trigger: phishingLinks OR upiIds OR bankAccounts not empty │
│  ├── Action: Force High Risk (riskScore≥75, isPhishing=True)    │
│  ├── Override: Cancels Rule 2 if artifacts found with OTP       │
│  └── Exit: Returns immediately if triggered                     │
├─────────────────────────────────────────────────────────────────┤
│  PRIORITY 3: Rule 3 (Master Boolean Sync)                       │
│  ├── Trigger: Applied to ALL remaining responses                │
│  ├── Action: Sync isPhishing to riskScore threshold (30)        │
│  └── Exit: Always applied as final consistency check            │
└─────────────────────────────────────────────────────────────────┘
```

#### Override Logic

**Rule 1 Overrides Rule 2 when:**
- An OTP message ALSO contains a phishing link (e.g., "Your OTP is 1234. Verify at evil.com")
- An OTP message contains forwarding instructions ("forward", "share")

**Example Override Scenarios:**

| Message | Rule 2 Check | Rule 1 Check | Final Result |
|---------|--------------|--------------|--------------|
| "Your OTP is 1234" | ✓ Pass (no artifacts, no danger) | ✗ Skip (no artifacts) | ✅ Safe (Rule 2) |
| "Your OTP is 1234. Click evil.com" | ✗ Fail (has link) | ✓ Trigger (has link) | ❌ Danger (Rule 1) |
| "Your OTP is 1234. Forward to agent" | ✗ Fail (has "forward") | ✗ Skip (no artifacts) | ⚠️ Warning (Rule 3) |

---

### 2.2 The 'Zero-Null' Policy

**Guarantee:** `phishingLinks`, `upiIds`, and `bankAccounts` are guaranteed to return an empty list `[]` and **never null**, ensuring frontend stability.

#### Why This Matters

React Native/Expo applications iterating over these arrays will crash if they encounter `null`:

```javascript
// ❌ CRASH: Cannot read property 'map' of null
intel.phishingLinks.map(link => <Text>{link}</Text>)

// ✅ SAFE: Empty array returns nothing, no crash
intel.phishingLinks.map(link => <Text>{link}</Text>)  // Returns [] if empty
```

#### Implementation

```python
# ZERO NULLS ENFORCEMENT - First operation in finalize_intelligence()
intel["phishingLinks"] = intel.get("phishingLinks") or []
intel["upiIds"] = intel.get("upiIds") or []
intel["bankAccounts"] = intel.get("bankAccounts") or []
intel["phoneNumbers"] = intel.get("phoneNumbers") or []
intel["suspiciousKeywords"] = intel.get("suspiciousKeywords") or []
```

| Input from AI | Output to Frontend |
|---------------|-------------------|
| `null` | `[]` |
| `undefined` | `[]` |
| `[]` | `[]` |
| `["evil.com"]` | `["evil.com"]` |

---

### 2.3 Data Sanitization (The Flattener)

**Purpose:** Ensure `extractedEntities` is always a flat `List[str]` regardless of AI output format.

#### The Problem

LLMs return probabilistic output that often violates Pydantic schemas:

| AI Output Type | Example | Schema Violation |
|----------------|---------|------------------|
| Nested Lists | `[['url1', 'url2']]` | `List[List[str]]` instead of `List[str]` |
| Dict-Wrapped | `[{'link': 'url1'}]` | `List[Dict]` instead of `List[str]` |
| MongoDB Artifact | `{'0': 'url1', '1': 'url2'}` | `Dict[str, str]` instead of `List[str]` |
| Null | `None` | `NoneType` instead of `List[str]` |

#### The Solution: `flatten_to_strings()`

```python
def flatten_to_strings(val):
    """Recursively flatten nested lists and extract string values."""
    result = []
    if isinstance(val, list):
        for item in val:
            result.extend(flatten_to_strings(item))  # Recurse into lists
    elif isinstance(val, dict):
        for v in val.values():
            result.extend(flatten_to_strings(v))     # Extract dict values
    elif isinstance(val, str):
        result.append(item)                          # Keep strings
    return result
```

#### Transformation Examples

| Input | Output | Description |
|-------|--------|-------------|
| `[['netflix.com', 'evil.com']]` | `['netflix.com', 'evil.com']` | Unwraps nested list |
| `[{'link': 'phish.com'}, {'upi': 'user@upi'}]` | `['phish.com', 'user@upi']` | Extracts dict values |
| `{'0': 'link1', '1': 'link2'}` | `['link1', 'link2']` | Converts MongoDB artifact |
| `None` | `[]` | Null safety |
| `'just-a-string'` | `[]` | Non-list input returns empty |

#### Frontend Compatibility

The flattener ensures React Native `FlatList` and `.map()` operations never fail:

```javascript
// Guaranteed to work - always receives List[str]
<FlatList
  data={intel.extractedEntities}  // Always ['item1', 'item2'], never null
  renderItem={({item}) => <Text>{item}</Text>}
/>
```

---

### 2.4 Visual Legend for Frontend

#### Risk Score Mapping Table

| Risk Score | Prefix | Category | Color Code | Icon | Usage |
|------------|--------|----------|------------|------|-------|
| 0-29 | `✅ Safe:` | Safe/Transactional | Green (#22c55e) | Checkmark | Legitimate messages |
| 30-74 | `⚠️ Warning:` | Suspicious/Unverified | Amber (#f59e0b) | Triangle | Review recommended |
| 75-100 | `❌ Danger:` | Confirmed Phishing/Scam | Red (#ef4444) | X-Circle | Immediate threat |

#### React Native Implementation

```javascript
const getVisualState = (reply) => {
  if (reply.startsWith('✅ Safe:')) {
    return {
      prefix: '✅ Safe:',
      color: '#22c55e',
      bgColor: '#dcfce7',
      icon: 'checkmark-circle',
      riskRange: '0-29',
      action: 'None - Message is safe'
    };
  } else if (reply.startsWith('⚠️ Warning:')) {
    return {
      prefix: '⚠️ Warning:',
      color: '#f59e0b',
      bgColor: '#fef3c7',
      icon: 'alert-triangle',
      riskRange: '30-74',
      action: 'Review message carefully'
    };
  } else if (reply.startsWith('❌ Danger:')) {
    return {
      prefix: '❌ Danger:',
      color: '#ef4444',
      bgColor: '#fee2e2',
      icon: 'close-circle',
      riskRange: '75-100',
      action: 'Block sender immediately'
    };
  }
};
```

#### Threshold Explanation

- **Threshold 30:** The `isPhishing` boolean flips from `False` to `True`
- **Threshold 75:** Minimum risk score when physical evidence is detected (Rule 1)
- **Max 100:** Absolute ceiling for critical social engineering attacks

---

### Critical Guarantees

| Guarantee | Implementation |
|-----------|---------------|
| **Zero Nulls** | `phishingLinks`, `upiIds`, `bankAccounts` always return `[]` never `null` |
| **Flat Lists** | `extractedEntities` is recursively flattened to `List[str]` |
| **Boolean Sync** | `isPhishing` strictly tied to `riskScore` threshold (30) |

---

### Rule 1: Evidence = High Risk

**Trigger:** `phishingLinks`, `upiIds`, OR `bankAccounts` is NOT empty

| Field | Enforced Value |
|-------|---------------|
| `riskScore` | `max(current, 75)` |
| `isPhishing` | `True` |
| `agentNotes` | `"Evidence Found: [Detected Artifacts]"` |
| `scamType` | `"Confirmed Phishing/Scam"` |
| `urgencyLevel` | `"High"` |
| `reply` | `"❌ Danger: Evidence Found: [artifacts]"` |

**Implementation:**
```python
has_evidence = len(phishing_links) > 0 or len(upi_ids) > 0 or len(bank_accounts) > 0

if has_evidence:
    artifacts = []
    if phishing_links:
        artifacts.extend(phishing_links[:2])
    if upi_ids:
        artifacts.extend(upi_ids[:2])
    if bank_accounts:
        artifacts.extend(bank_accounts[:1])
    
    artifact_str = ", ".join(artifacts)
    intel["riskScore"] = max(risk_score, 75)
    intel["isPhishing"] = True
    intel["agentNotes"] = f"Evidence Found: {artifact_str}"
    reply = f"❌ Danger: Evidence Found: {artifact_str}"
    return intel, reply
```

---

### Rule 2: OTP Transactional Safeguard

**Trigger:** `'OTP'` in message AND (`phishingLinks` empty AND `upiIds` empty) AND no `'forward'`/`'share'`

| Field | Enforced Value |
|-------|---------------|
| `riskScore` | `5` |
| `isPhishing` | `False` |
| `scamType` | `"Safe/Transactional"` |
| `urgencyLevel` | `"Low"` |
| `agentNotes` | `"Safe: Transactional OTP message"` |
| `reply` | `"✅ Safe: Transactional OTP message"` |

**Implementation:**
```python
has_otp = "otp" in message_lower
has_links_or_upi = len(phishing_links) > 0 or len(upi_ids) > 0
has_forward_share = "forward" in message_lower or "share" in message_lower

if has_otp and not has_links_or_upi and not has_forward_share:
    intel["riskScore"] = 5
    intel["isPhishing"] = False
    intel["scamType"] = "Safe/Transactional"
    intel["agentNotes"] = "Safe: Transactional OTP message"
    reply = "✅ Safe: Transactional OTP message"
    return intel, reply
```

**Key Point:** This rule specifically checks that BOTH `phishingLinks` AND `upiIds` are empty, preventing false positives on legitimate OTP messages.

---

### Rule 3: Master Boolean Sync

**Trigger:** Applied to ALL responses as final consistency check

| Condition | `isPhishing` Value |
|-----------|-------------------|
| `riskScore < 30` | `False` |
| `riskScore >= 30` | `True` |

**Implementation:**
```python
if risk_score < 30:
    intel["isPhishing"] = False
else:
    intel["isPhishing"] = True
```

This ensures the boolean flag is ALWAYS synchronized with the numeric risk score, eliminating any AI inconsistency.

---

### Execution Priority

Rules are evaluated in **strict order** with early exits:

```
┌─────────────────────────────────────────────────────────┐
│  STEP 1: ZERO NULLS & FLAT LISTS                        │
│  ├── Ensure all artifact lists are [] never null        │
│  └── Recursively flatten extractedEntities              │
├─────────────────────────────────────────────────────────┤
│  STEP 2: OTP Transactional Safeguard (Rule 2)           │
│  ├── IF: OTP + no artifacts + no forward/share          │
│  └── THEN: Force Safe → EXIT                            │
├─────────────────────────────────────────────────────────┤
│  STEP 3: Evidence = High Risk (Rule 1)                  │
│  ├── IF: Any physical artifacts exist                   │
│  └── THEN: Force High Risk → EXIT                       │
├─────────────────────────────────────────────────────────┤
│  STEP 4: Master Boolean Sync (Rule 3)                   │
│  └── Enforce: riskScore < 30 → isPhishing=False         │
└─────────────────────────────────────────────────────────┘
```

---

### Data Sanitization

#### Zero Nulls Enforcement
Before any rule logic executes:
```python
intel["phishingLinks"] = intel.get("phishingLinks") or []
intel["upiIds"] = intel.get("upiIds") or []
intel["bankAccounts"] = intel.get("bankAccounts") or []
intel["phoneNumbers"] = intel.get("phoneNumbers") or []
intel["suspiciousKeywords"] = intel.get("suspiciousKeywords") or []
```

#### Flat Lists for extractedEntities
Recursive flattener ensures React Native/Expo compatibility:
```python
def flatten_to_strings(val):
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

| Input | Output |
|-------|--------|
| `[['url1', 'url2']]` | `['url1', 'url2']` |
| `[{'link': 'url1'}]` | `['url1']` |
| `{'0': 'link1', '1': 'link2'}` | `['link1', 'link2']` |
| `None` | `[]` |

---

## 4. Data Storage: MongoDB Intelligence Structure

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

LLMs are probabilistic and may return data in unexpected formats. The `ensure_list` function acts as a **Deep Flat Sanitizer** - a recursive schema guardian that prevents 400 Bad Request errors by forcing AI-generated dictionaries and nested lists into Pydantic-compliant flat lists.

```python
def ensure_list(val):
    """
    Recursively flatten nested lists and extract dict values.
    
    Examples:
        [['url1', 'url2']] → ['url1', 'url2']
        [{'link': 'url1'}] → ['url1']
        {"sender": "PowerCorp"} → ['PowerCorp']
    """
    if val is None:
        return []
    
    result = []
    
    def flatten(item):
        if isinstance(item, list):
            for subitem in item:
                flatten(subitem)
        elif isinstance(item, dict):
            for subval in item.values():
                flatten(subval)
        elif isinstance(item, str):
            result.append(item)
        # Ignore numbers, booleans, etc.
    
    flatten(val)
    return result
```

**Applied to all array fields (with Deep Flattening):**
- `bankAccounts` - Account numbers (may come as [["123456"]] or {"account": "123456"})
- `upiIds` - Payment addresses (may come as [{"upi": "user@upi"}])
- `phishingLinks` - Malicious URLs (may come as nested [["url1", "url2"]])
- `phoneNumbers` - Contact numbers (may come as {"sender": "PowerCorp"})
- `suspiciousKeywords` - Risk indicators
- `extractedEntities` - Combined entities (most likely to be nested)

**Why Deep Flattening matters:**

| Input from AI | Without Sanitizer | With Deep Flat Sanitizer |
|--------------|------------------|-------------------------|
| `[['url1', 'url2']]` | Validation Error | `['url1', 'url2']` |
| `[{'link': 'url1'}]` | Validation Error | `['url1']` |
| `{"sender": "PowerCorp"}` | Validation Error | `['PowerCorp']` |

The **Deep Flat Sanitizer** recursively traverses nested structures, ensuring `extractedEntities` is always a flat list of strings - no nested lists, no dictionaries, just clean Pydantic-compatible arrays.

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
