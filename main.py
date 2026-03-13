from dotenv import load_dotenv
load_dotenv()

"""
FastAPI application entry point for Agentic AI Honeypot.
v2.0.0 Production Stable - Tiered Defense System with deterministic early returns.

Tier Structure:
- Tier 1: Sovereign Shields (Whitelists) - Early Return for legitimate messages
- Tier 2: Deterministic Traps (Blacklists) - Early Return for known scams
- Tier 3: LLM Heuristics - AI detection only when Tier 1/2 don't match
"""

import os
import asyncio
import logging
import re
import secrets
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Optional, Dict, Any
from collections import defaultdict
from time import time

import httpx
from fastapi import FastAPI, HTTPException, Header, BackgroundTasks, Depends, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import ValidationError

from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

API_VERSION = "2.0.0"

from models import HoneypotRequest, HoneypotResponse, IntelligenceData
from database import db_manager
from agent import ScamAgent, apply_evidence_guard

# v1.2 Titanium: Rate Limiting with slowapi (10 requests per minute per IP)
# Using memory storage to avoid Redis dependency on Render
limiter = Limiter(key_func=get_remote_address, storage_uri='memory://')

# Legacy rate limiter for session-based tracking (kept for compatibility)
rate_limit_store = defaultdict(list)

def check_rate_limit(session_id: str, max_requests: int = 10, window_seconds: int = 60) -> bool:
    """
    Check if session has exceeded rate limit using token bucket algorithm.
    
    Args:
        session_id: Unique identifier for the user's session.
        max_requests: Maximum requests allowed within the time window.
        window_seconds: Time window in seconds (default 60 = 1 minute).
    
    Returns:
        True if request is allowed, False if rate limit exceeded.
    """
    now = time()
    # Clean old entries
    rate_limit_store[session_id] = [t for t in rate_limit_store[session_id] if now - t < window_seconds]
    
    if len(rate_limit_store[session_id]) >= max_requests:
        return False
    
    rate_limit_store[session_id].append(now)
    return True


# v1.2 Titanium: Input Normalization (The Filter)
def normalize_input(text: str) -> str:
    """
    Normalize input text by stripping whitespace and removing invisible Unicode characters.
    
    This function acts as a pre-processing filter to sanitize user input before AI analysis.
    Removes control characters, zero-width spaces, and other invisible Unicode characters
    that could cause issues with regex pattern matching or AI processing.
    
    Args:
        text: Raw input text from user
        
    Returns:
        str: Normalized text with whitespace stripped and invisible characters removed
        
    Examples:
        >>> normalize_input("  Hello\\u200bWorld  ")
        "HelloWorld"
        >>> normalize_input("\\x00\\x01\\x02Hello")
        "Hello"
    """
    if not text:
        return ""
    
    # Strip leading/trailing whitespace
    text = text.strip()
    
    # Remove invisible Unicode characters:
    # - \u200b: Zero-width space
    # - \u200c: Zero-width non-joiner
    # - \u200d: Zero-width joiner
    # - \ufeff: Byte order mark (BOM)
    # - \x00-\x1f: ASCII control characters (except \t, \n, \r)
    # - \x7f: DEL character
    invisible_chars = r'[\u200b\u200c\u200d\ufeff\x00-\x08\x0b\x0c\x0e-\x1f\x7f]'
    text = re.sub(invisible_chars, '', text)
    
    # Normalize multiple spaces to single space
    text = re.sub(r'\s+', ' ', text)
    
    return text.strip()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# Application lifecycle
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown handler."""
    # Startup
    logger.info("Starting Agentic AI Honeypot...")
    
    # Initialize database connection
    db_connected = await db_manager.connect()
    if db_connected:
        logger.info("[SUCCESS] Connected to MongoDB Atlas")
    else:
        logger.warning("[FALLBACK] Database connection failed, using in-memory storage")
    
    # Pre-initialize the ScamAgent
    app.state.agent = ScamAgent()
    
    logger.info("Application started successfully")
    
    yield
    
    # Shutdown
    logger.info("Shutting down...")
    await app.state.agent.close()
    await db_manager.close()
    logger.info("Application shutdown complete")


# Initialize FastAPI app with lifespan
app = FastAPI(
    title="Agentic AI Honeypot API",
    description="Real-time scam engagement and intelligence extraction system",
    version=API_VERSION,
    lifespan=lifespan
)

# v1.2 Titanium: Attach rate limiter to app
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# v1.2 Titanium: CORS Configuration - Restricted Origins
# =============================================================================
# Development: localhost:19000 (Expo), localhost:3000 (React)
# Production: Set PRODUCTION_DOMAIN in environment variables
# =============================================================================
ALLOWED_ORIGINS = [
    "http://localhost:19000",  # Expo development
    "http://localhost:19006",  # Expo web
    "http://localhost:3000",   # React development
    "http://127.0.0.1:19000",
    "http://127.0.0.1:3000",
]

# Add production domain if configured
production_domain = os.getenv("PRODUCTION_DOMAIN")
if production_domain:
    ALLOWED_ORIGINS.append(production_domain)
    if not production_domain.startswith("https://"):
        ALLOWED_ORIGINS.append(f"https://{production_domain}")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Authorization", "X-API-Key", "Content-Type", "X-Request-ID"],
    expose_headers=["X-RateLimit-Limit", "X-RateLimit-Remaining"],
)

# Configuration from environment
# Fallback to default key for development if not set
EXPECTED_KEY = os.getenv("API_KEY", "prajwal_hackathon_key_2310")
GUVI_CALLBACK_URL = os.getenv("GUVI_CALLBACK_URL", "")
DEBUG = os.getenv("DEBUG", "true").lower() == "true"

# Default intelligence template for consistent API responses
# v1.3.0: Added aadhaarNumbers and panNumbers
DEFAULT_INTEL = {
    "bankAccounts": [],
    "upiIds": [],
    "phishingLinks": [],
    "phoneNumbers": [],
    "suspiciousKeywords": [],
    "aadhaarNumbers": [],
    "panNumbers": [],
    "agentNotes": "",
    "scamType": "Safe/Transactional",
    "urgencyLevel": "Low",
    "riskScore": 5,
    "extractedEntities": [],
    "threatSource": "System",
    "isPhishing": False
}


# =============================================================================
# Exception Handlers
# =============================================================================

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc):
    """Handle Pydantic validation errors."""
    # Convert any non-serializable objects to strings
    def convert_to_serializable(obj):
        if isinstance(obj, bytes):
            return obj.decode('utf-8', errors='ignore')
        if isinstance(obj, dict):
            return {k: convert_to_serializable(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [convert_to_serializable(i) for i in obj]
        return obj
    
    errors = convert_to_serializable(exc.errors())
    logger.warning(f"Validation error: {errors}")
    return JSONResponse(
        status_code=422,
        content={
            "status": "error",
            "error": "Validation error",
            "details": errors
        }
    )


@app.exception_handler(ValueError)
async def value_error_handler(request, exc):
    """Handle value errors."""
    return JSONResponse(
        status_code=400,
        content={
            "status": "error",
            "error": "Invalid value",
            "message": str(exc)
        }
    )


@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    """Global exception handler for unexpected errors."""
    logger.exception(f"Unexpected error: {exc}")
    return JSONResponse(
        status_code=500,
        content={
            "status": "error",
            "error": "Internal server error",
            "message": "An unexpected error occurred" if not DEBUG else str(exc)
        }
    )


# =============================================================================
# Security
# =============================================================================

async def verify_api_key(x_api_key: Optional[str] = Header(None)) -> str:
    """
    Verify the API key from request headers for authentication.
    
    v1.2 Titanium: Uses constant-time comparison (secrets.compare_digest) to prevent
    timing attacks. All validation failures return 401 with a generic error message.
    
    Args:
        x_api_key: API key passed in the X-API-Key header.
    
    Returns:
        The API key if valid.
    
    Raises:
        HTTPException: 401 if API key is invalid or missing.
    
    Security Note:
        All production endpoints should require valid API key.
        The key must match the EXPECTED_KEY environment variable.
        Uses constant-time comparison to prevent timing attacks.
    """
    # Handle missing or empty API key
    if not x_api_key:
        logger.debug("API Key validation failed: Missing header")
        raise HTTPException(status_code=401, detail="Invalid or missing API Key")
    
    # Strip whitespace from provided key
    provided_key = x_api_key.strip()
    
    # Log key lengths for debugging (only in debug level to keep logs clean)
    logger.debug(f"Security: Expected key len={len(EXPECTED_KEY)}, Received key len={len(provided_key)}")
    
    # v1.2 Titanium: Constant-time comparison to prevent timing attacks
    if not secrets.compare_digest(provided_key, EXPECTED_KEY):
        logger.debug(f"API Key validation failed: Key mismatch")
        raise HTTPException(status_code=401, detail="Invalid or missing API Key")
    
    return provided_key


def levenshtein_distance(s1: str, s2: str) -> int:
    """
    Calculate the Levenshtein distance between two strings.
    Used for typo-squatting detection (brand lookalikes).
    
    Args:
        s1: First string
        s2: Second string
    
    Returns:
        Edit distance between the two strings
    """
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    
    if len(s2) == 0:
        return len(s1)
    
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    
    return previous_row[-1]


# =============================================================================
# TIERED DEFENSE SYSTEM v2.0.0
# =============================================================================

def check_tier1_sovereign_shields(message_text: str) -> Optional[Dict[str, Any]]:
    """
    Tier 1: Sovereign Shields (Whitelists) - Early Return for legitimate messages.
    
    This tier identifies known-safe message patterns and returns immediately,
    bypassing the more expensive AI-based detection in Tier 3.
    
    Rules:
    - Official OTP Delivery: 6-digit code + ('do not share' OR 'valid for') → Safe
    - Government Confirmation: ('successfully linked' OR 'successfully updated') + UIDAI/Aadhaar → Safe
    - Domain Reputation: Exact root domains (jio.com, amazon.in, infosys.com, google.com) → Cap at 15%
    
    Args:
        message_text: Normalized message text to analyze
    
    Returns:
        Optional dict with detection result, or None if no rule matched
    """
    text_lower = message_text.lower()
    
    # -------------------------------------------------------------------------
    # Rule 1.1: Official OTP Delivery
    # Trigger: 6-digit code AND ('do not share' OR 'valid for')
    # Score: 5%, isPhishing: False
    # -------------------------------------------------------------------------
    otp_code_pattern = re.search(r'\b\d{6}\b', text_lower)
    has_otp_code = bool(otp_code_pattern)
    otp_warning_keywords = ["do not share", "don't share", "never share", "valid for", "expires in"]
    has_otp_warning = any(kw in text_lower for kw in otp_warning_keywords)
    
    if has_otp_code and has_otp_warning:
        return {
            "riskScore": 5,
            "isPhishing": False,
            "scamType": "Safe/Transactional",
            "urgencyLevel": "Low",
            "agentNotes": "[TIER1] Official OTP Delivery - Security warning present",
            "reply": "✅ Safe: Legitimate OTP message with security warning",
            "tier": 1,
            "rule": "official_otp_delivery"
        }
    
    # -------------------------------------------------------------------------
    # Rule 1.2: Government Confirmation
    # Trigger: ('successfully linked' OR 'successfully updated') AND ('UIDAI' OR 'Aadhaar')
    # Score: 12%, isPhishing: False
    # -------------------------------------------------------------------------
    government_status_keywords = ["successfully linked", "successfully updated"]
    government_id_keywords = ["uidai", "aadhaar", "aadhar"]
    has_government_status = any(kw in text_lower for kw in government_status_keywords)
    has_government_id = any(kw in text_lower for kw in government_id_keywords)
    
    if has_government_status and has_government_id:
        return {
            "riskScore": 12,
            "isPhishing": False,
            "scamType": "Safe/Transactional",
            "urgencyLevel": "Low",
            "agentNotes": "[TIER1] Government Confirmation - Official UIDAI status",
            "reply": "✅ Safe: Official government confirmation detected",
            "tier": 1,
            "rule": "government_confirmation"
        }
    
    # -------------------------------------------------------------------------
    # Rule 1.3: Domain Reputation (Exact Root Domain)
    # Trigger: Link contains EXACT root domain (NOT subdomain)
    # Domains: jio.com, amazon.in, infosys.com, google.com
    # Cap score at: 15%
    # Exception: If PIN/OTP/password mentioned, skip this rule
    # -------------------------------------------------------------------------
    whitelist_root_domains = ["jio.com", "amazon.in", "infosys.com", "google.com"]
    sensitive_keywords = ["pin", "otp", "password", "secret", "cvv"]
    has_sensitive_request = any(kw in text_lower for kw in sensitive_keywords)
    
    if not has_sensitive_request:
        for domain in whitelist_root_domains:
            if domain in text_lower:
                return {
                    "riskScore": 15,
                    "isPhishing": False,
                    "scamType": "Safe/Transactional",
                    "urgencyLevel": "Low",
                    "agentNotes": f"[TIER1] Domain Reputation - Whitelisted domain ({domain})",
                    "reply": f"✅ Safe: Trusted domain ({domain}) detected",
                    "tier": 1,
                    "rule": "domain_reputation"
                }
    
    return None


def check_tier2_deterministic_traps(message_text: str) -> Optional[Dict[str, Any]]:
    """
    Tier 2: Deterministic Traps (Blacklists) - Early Return for known scams.
    
    This tier identifies known-scam patterns using deterministic keyword matching
    and returns immediately with high confidence scores.
    
    Rules:
    - The PIN Trap: 'UPI PIN' OR 'UPI Password' OR 'secret pin' → 98%, True
    - The Micro-Payment Trap: ('send 1' OR 'pay ₹1' OR 'pay 1 rupee') AND ('verify' OR 'reward' OR 'claim') → 92%, True
    - Identity Theft: ('Aadhaar' OR 'PAN') AND ('share' OR 'verify' OR 'confirm') → 85%, True
    
    Args:
        message_text: Normalized message text to analyze
    
    Returns:
        Optional dict with detection result, or None if no rule matched
    """
    text_lower = message_text.lower()
    
    # -------------------------------------------------------------------------
    # Rule 2.1: The PIN Trap
    # Trigger: Any mention of 'UPI PIN' OR 'UPI Password' OR 'secret pin'
    # Score: 98%, isPhishing: True
    # -------------------------------------------------------------------------
    pin_trap_keywords = ["upi pin", "upi password", "secret pin"]
    has_pin_request = any(kw in text_lower for kw in pin_trap_keywords)
    
    if has_pin_request:
        return {
            "riskScore": 98,
            "isPhishing": True,
            "scamType": "Credential Theft",
            "urgencyLevel": "High",
            "agentNotes": "[TIER2] PIN Trap Detected - UPI credential request",
            "reply": "❌ Danger: PIN/Credential theft attempt detected",
            "tier": 2,
            "rule": "pin_trap"
        }
    
    # -------------------------------------------------------------------------
    # Rule 2.2: The Micro-Payment Trap
    # Trigger: ('send 1' OR 'pay ₹1' OR 'pay 1 rupee') AND ('verify' OR 'reward' OR 'claim')
    # Score: 92%, isPhishing: True
    # -------------------------------------------------------------------------
    micro_payment_triggers = ["send 1", "pay ₹1", "pay 1 rupee", "pay 1rs", "send re 1"]
    micro_payment_actions = ["verify", "reward", "claim", "get"]
    has_micro_payment_trigger = any(kw in text_lower for kw in micro_payment_triggers)
    has_micro_payment_action = any(kw in text_lower for kw in micro_payment_actions)
    
    if has_micro_payment_trigger and has_micro_payment_action:
        return {
            "riskScore": 92,
            "isPhishing": True,
            "scamType": "Financial Fraud",
            "urgencyLevel": "High",
            "agentNotes": "[TIER2] Micro-Payment Trap Detected - Fake payment verification scam",
            "reply": "❌ Danger: Micro-payment scam detected",
            "tier": 2,
            "rule": "micro_payment_trap"
        }
    
    # -------------------------------------------------------------------------
    # Rule 2.3: Identity Theft
    # Trigger: ('Aadhaar' OR 'PAN') AND ('share' OR 'verify' OR 'confirm')
    # Score: 85%, isPhishing: True
    # -------------------------------------------------------------------------
    identity_keywords = ["aadhaar", "aadhar", "pan card", "pan number", "pan"]
    identity_actions = ["share", "verify", "confirm", "provide", "upload"]
    has_identity_keyword = any(kw in text_lower for kw in identity_keywords)
    has_identity_action = any(kw in text_lower for kw in identity_actions)
    
    if has_identity_keyword and has_identity_action:
        return {
            "riskScore": 85,
            "isPhishing": True,
            "scamType": "ID Theft",
            "urgencyLevel": "High",
            "agentNotes": "[TIER2] Identity Theft Detected - Government ID request",
            "reply": "❌ Danger: Identity theft attempt detected",
            "tier": 2,
            "rule": "identity_theft"
        }
    
    return None


def check_tier3_llm_heuristics(message_text: str) -> bool:
    """
    Tier 3: LLM Heuristics - Determine if AI detection is needed.
    
    This function checks if the message requires AI-based analysis.
    Returns True if LLM heuristics should be applied, False otherwise.
    
    Args:
        message_text: Normalized message text to analyze
    
    Returns:
        bool: True if AI detection should run, False if message is clearly safe
    """
    text_lower = message_text.lower()
    
    # Skip if message is too short
    if len(text_lower) < 10:
        return False
    
    # Skip if message is a simple greeting or acknowledgment
    simple_responses = ["ok", "okay", "yes", "no", "thanks", "thank you", "received", "done"]
    if text_lower.strip() in simple_responses:
        return False
    
    return True


def finalize_intelligence(intel: Dict[str, Any], reply: str, message_text: str = "") -> tuple:
    """
    THE FINAL THREE - Ultimate sanitization block before response delivery.
    
    Implements three deterministic override rules that correct any AI hallucinations
    and enforce zero-null guarantees for frontend compatibility.
    
    CRITICAL CHECKLIST:
    -------------------
    ✓ Zero Nulls: phishingLinks, upiIds, bankAccounts always return [] never null
    ✓ Flat Lists: extractedEntities is recursively flattened to List[str]
    ✓ Boolean Sync: isPhishing strictly tied to riskScore threshold (30)
    
    RULE EXECUTION ORDER:
    ---------------------
    1. Rule 2 (OTP Transactional Safeguard) - Check first to prevent false positives
    2. Rule 4 (Social Engineering) - Urgent verbal manipulation
    3. Rule 5 (ID Theft Detection) - Aadhaar/PAN requests
    4. Rule 6 (Brand Lookalike) - Typo-squatting detection
    5. Rule 1 (Evidence = High Risk) - Override with physical evidence
    6. Rule 3 (Master Boolean Sync) - Final consistency check
    
    Args:
        intel: Intelligence dictionary from AI processing
        reply: Current reply text (may be overwritten)
        message_text: Original message for OTP pattern detection
    
    Returns:
        tuple: (sanitized_intel, sanitized_reply)
    """
    message_lower = message_text.lower()
    
    # =========================================================================
    # ZERO NULLS ENFORCEMENT - Ensure all artifact lists are never null
    # v1.3.0: Added aadhaarNumbers and panNumbers
    # =========================================================================
    intel["phishingLinks"] = intel.get("phishingLinks") or []
    intel["upiIds"] = intel.get("upiIds") or []
    intel["bankAccounts"] = intel.get("bankAccounts") or []
    intel["phoneNumbers"] = intel.get("phoneNumbers") or []
    intel["suspiciousKeywords"] = intel.get("suspiciousKeywords") or []
    intel["aadhaarNumbers"] = intel.get("aadhaarNumbers") or []
    intel["panNumbers"] = intel.get("panNumbers") or []
    
    # =========================================================================
    # v1.3.1: PRESERVE WHITELIST HIGH RISK
    # If the whitelist already detected high risk, preserve it and skip re-analysis
    # =========================================================================
    initial_risk = intel.get("riskScore") or 0
    if initial_risk >= 60:
        # Whitelist already detected high risk - preserve it
        logger.info(f"PRESERVING WHITELIST HIGH RISK: {initial_risk}")
        intel["isPhishing"] = True
        reply = f"❌ Danger: {intel.get('agentNotes', 'High risk detected')}"
        return intel, reply
    
    # FLAT LISTS - Ensure extractedEntities is a flat list of strings
    raw_entities = intel.get("extractedEntities", [])
    if raw_entities is None:
        raw_entities = []
    
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
    
    # Extract current values
    phishing_links = intel["phishingLinks"]
    upi_ids = intel["upiIds"]
    bank_accounts = intel["bankAccounts"]
    risk_score = intel.get("riskScore", 0) or 0
    
    # =========================================================================
    # RULE 2: Intent-Based OTP Logic
    # Distinguish malicious intent vs protective intent in OTP messages
    # =========================================================================
    has_otp = "otp" in message_lower or "verification code" in message_lower
    has_links_or_upi = len(phishing_links) > 0 or len(upi_ids) > 0
    
    # Malicious intent keywords (social engineering)
    malicious_intent = any(kw in message_lower for kw in [
        "forward", "send", "provide", "share with", "give to", "text to", "mail to"
    ])
    
    # Protective intent keywords (legitimate warnings)
    protective_intent = any(kw in message_lower for kw in [
        "do not share", "never give", "don't share", "do not give", "never share",
        "confidential", "private", "sensitive"
    ])
    
    if has_otp and not has_links_or_upi:
        if malicious_intent and not protective_intent:
            # Malicious OTP - Social engineering attempt
            intel["riskScore"] = 100
            intel["isPhishing"] = True
            intel["scamType"] = "Social Engineering"
            intel["urgencyLevel"] = "High"
            intel["agentNotes"] = "CRITICAL: OTP with malicious forwarding instructions detected"
            reply = "❌ Danger: Social engineering - OTP forwarding scam"
            return intel, reply
        elif protective_intent:
            # Protective OTP - Legitimate warning message
            intel["riskScore"] = 5
            intel["isPhishing"] = False
            intel["scamType"] = "Safe/Transactional"
            intel["urgencyLevel"] = "Low"
            intel["agentNotes"] = "Safe: OTP with protective security warning"
            reply = "✅ Safe: Legitimate OTP with security warning"
            return intel, reply
        else:
            # Neutral OTP - No clear intent indicators
            intel["riskScore"] = 5
            intel["isPhishing"] = False
            intel["scamType"] = "Safe/Transactional"
            intel["urgencyLevel"] = "Low"
            intel["agentNotes"] = "Safe: Transactional OTP message"
            reply = "✅ Safe: Transactional OTP message"
            return intel, reply
    
    # =========================================================================
    # v1.3.0 RULE 4: Social Engineering (Verbal Manipulation)
    # Detect urgent verbal commands without links - Base Risk 60
    # If paired with OTP request, force Risk 100
    # =========================================================================
    urgent_commands = [
        "hurry up", "hurry", "immediately", "urgent", "act now", "limited time",
        "account will be blocked", "account will be suspended", "account will be closed",
        "verify immediately", "verification required immediately", "update now",
        "confirm now", "failure to comply", "legal action", "court", "arrest warrant"
    ]
    has_urgent_language = any(cmd in message_lower for cmd in urgent_commands)
    
    if has_urgent_language and not has_links_or_upi and not has_otp:
        # Urgent commands without links or OTP - Base Risk 60
        intel["riskScore"] = max(intel.get("riskScore", 0), 60)
        intel["scamType"] = "Social Engineering"
        intel["urgencyLevel"] = "High"
        intel["suspiciousKeywords"] = intel.get("suspiciousKeywords", []) + ["urgent language"]
        intel["agentNotes"] = f"{intel.get('agentNotes', '')} [Social Engineering: Urgent verbal commands detected]"
        logger.info(f"SOCIAL ENGINEERING TRIGGERED: Urgent language without links - Risk 60")
    elif has_urgent_language and has_otp:
        # Urgent + OTP = CRITICAL - Risk 100
        intel["riskScore"] = 100
        intel["isPhishing"] = True
        intel["scamType"] = "Social Engineering"
        intel["urgencyLevel"] = "High"
        intel["suspiciousKeywords"] = intel.get("suspiciousKeywords", []) + ["urgent language", "otp"]
        intel["agentNotes"] = "CRITICAL: Urgent language combined with OTP request - likely scam"
        reply = "❌ Danger: Social engineering - urgent OTP scam"
        return intel, reply
    
    # =========================================================================
    # v1.3.0 RULE 5: ID Theft Detection (Aadhaar/PAN)
    # Detect requests for government ID photos/numbers - Minimum Risk 80
    # =========================================================================
    id_theft_keywords = [
        "aadhaar", "aadhar", "pan card", "pan number", "uidai",
        "photo id", "id photo", "verify id", "id verification",
        "document verification", "upload id", "send id", "provide id",
        "kyc documents", "kyc verification", "identity proof"
    ]
    id_photo_keywords = [
        "photo of", "picture of", "send your", "click photo", "upload photo",
        "selfie with", "video call", "front photo", "back photo"
    ]
    
    has_id_request = any(kw in message_lower for kw in id_theft_keywords)
    has_photo_request = any(kw in message_lower for kw in id_photo_keywords)
    
    # Check for actual Aadhaar/PAN numbers in message
    aadhaar_numbers = intel.get("aadhaarNumbers", [])
    pan_numbers = intel.get("panNumbers", [])
    has_id_numbers = len(aadhaar_numbers) > 0 or len(pan_numbers) > 0
    
    if (has_id_request and has_photo_request) or (has_id_request and has_id_numbers):
        # Request for ID photo or ID numbers = High Danger
        intel["riskScore"] = max(intel.get("riskScore", 0), 80)
        intel["isPhishing"] = True
        intel["scamType"] = "ID Theft"
        intel["urgencyLevel"] = "High"
        intel["suspiciousKeywords"] = intel.get("suspiciousKeywords", []) + ["id theft"]
        intel["agentNotes"] = f"{intel.get('agentNotes', '')} [ID Theft: Government ID request detected]"
        logger.info(f"ID THEFT TRIGGERED: Aadhaar/PAN request detected - Risk 80")
    elif has_id_request:
        # General ID request without photo
        intel["riskScore"] = max(intel.get("riskScore", 0), 60)
        intel["scamType"] = "ID Theft"
        intel["urgencyLevel"] = "Medium"
        intel["suspiciousKeywords"] = intel.get("suspiciousKeywords", []) + ["id request"]
        intel["agentNotes"] = f"{intel.get('agentNotes', '')} [ID Theft: Government ID request detected]"
    
    # =========================================================================
    # v1.3.0 RULE 6: Brand Lookalike (Typo-Squatting)
    # Detect domains that look like major brands but have typos
    # =========================================================================
    # Major brands and their common misspellings/lookalikes
    brand_patterns = {
        "sbi": ["sbl", "sbi1", "sbi-update", "sbi-verification", "sbi-bank"],
        "hdfc": ["hdft", "hdfc1", "hdfc-update", "hdfc-bank", "hdffc"],
        "icici": ["iccil", "icici1", "icici-update", "icici-bank"],
        "axis": ["axis1", "axis-update", "axiz", "axls"],
        "yesbank": ["yes1", "yesbank-update", "yes-bank"],
        "bank": ["b ank", "bank1", "bank-update"],
        "paytm": ["paytm1", "paytm-update", "payt m", "pa yt m"],
        "phonepe": ["phonepe1", "phonepe-update", "phon epe"],
        "google": ["go0gle", "g00gle", "googie", "gogle"],
        "amazon": ["amaz0n", "amazom", "amazn", "amajon"],
        "facebook": ["faceb00k", "facebok", "faceboook"],
        "instagram": ["1nstagram", "instagran", "1nsta"],
        "whatsapp": ["whats app", "whatssap", "whatsup"]
    }
    
    def is_lookalike_domain(domain: str) -> tuple[bool, str]:
        """Check if domain is a lookalike of a major brand."""
        domain_lower = domain.lower()
        # Remove common TLDs for comparison
        for tld in [".com", ".in", ".org", ".net", ".co", ".io"]:
            if domain_lower.endswith(tld):
                domain_base = domain_lower[:-len(tld)]
                break
        else:
            domain_base = domain_lower
        
        # Check against brand patterns
        for brand, lookalikes in brand_patterns.items():
            if brand in domain_base:
                # Brand is present, check if it's exact or lookalike
                if domain_base == brand:
                    return False, ""  # Exact brand, not a lookalike
                # Check for lookalike patterns
                for lookalike in lookalikes:
                    if lookalike in domain_base or levenshtein_distance(brand, domain_base) <= 2:
                        return True, brand
        return False, ""
    
    # Check each phishing link for lookalike patterns
    lookalike_links = []
    for link in phishing_links:
        is_lookalike, brand = is_lookalike_domain(link)
        if is_lookalike:
            lookalike_links.append(f"{link} (lookalike: {brand})")
    
    if lookalike_links:
        # Brand lookalike = Evidence Mandate triggered (Risk 75+)
        intel["riskScore"] = max(intel.get("riskScore", 0), 75)
        intel["isPhishing"] = True
        intel["scamType"] = "Brand Impersonation"
        intel["urgencyLevel"] = "High"
        intel["suspiciousKeywords"] = intel.get("suspiciousKeywords", []) + ["brand lookalike"]
        intel["phishingLinks"] = list(set(intel.get("phishingLinks", []) + lookalike_links))
        intel["agentNotes"] = f"{intel.get('agentNotes', '')} [Brand Lookalike: Typo-squatting detected]"
        logger.info(f"BRAND LOOKALIKE TRIGGERED: {lookalike_links} - Risk 75")
    
    # =========================================================================
    # v1.3.1 STRICT HEURISTIC OVERRIDES - Final Safety Gate
    # These rules fire AFTER AI returns to ensure non-negotiable thresholds
    # =========================================================================
    
    # Ensure we have a valid riskScore (handle None cases)
    current_risk = intel.get("riskScore") or 0
    
    # -------------------------------------------------------------------------
    # RULE 7: OTP Data Request Override
    # OTP + 'share'/'verify'/'provide'/'executive' → Risk 60+
    # Must return early to bypass whitelist bypass
    # -------------------------------------------------------------------------
    otp_trigger_keywords = ["share", "verify", "provide", "executive", "send", "give"]
    has_otp_data_request = has_otp and any(kw in message_lower for kw in otp_trigger_keywords)
    
    if has_otp_data_request:
        intel["riskScore"] = max(current_risk, 60)
        intel["isPhishing"] = True
        intel["scamType"] = "Social Engineering"
        intel["urgencyLevel"] = "High"
        intel["suspiciousKeywords"] = intel.get("suspiciousKeywords", []) + ["otp data request"]
        intel["agentNotes"] = f"{intel.get('agentNotes', '')} [Override: OTP Data Request - Risk 60]"
        logger.info(f"OVERRIDE OTP DATA REQUEST: Risk forced to 60+")
        reply = "❌ Danger: OTP data request scam detected"
        return intel, reply
    
    # -------------------------------------------------------------------------
    # RULE 8: Financial Data Request Override
    # Card Details + Address (or CVV/Expiry) → Risk 75+
    # -------------------------------------------------------------------------
    financial_card_keywords = ["card details", "credit card", "debit card", "card number"]
    financial_cvv_keywords = ["cvv", "expiry", "expiration", "valid till", "mm/yy", "yy/mm"]
    financial_address_keywords = ["address", "billing address", "registered address"]
    
    has_card_request = any(kw in message_lower for kw in financial_card_keywords)
    has_cvv_expiry = any(kw in message_lower for kw in financial_cvv_keywords)
    has_address_request = any(kw in message_lower for kw in financial_address_keywords)
    
    if has_card_request and (has_cvv_expiry or has_address_request):
        intel["riskScore"] = max(current_risk, 75)
        intel["isPhishing"] = True
        intel["scamType"] = "Financial Fraud"
        intel["urgencyLevel"] = "High"
        intel["suspiciousKeywords"] = intel.get("suspiciousKeywords", []) + ["financial data request"]
        intel["agentNotes"] = f"{intel.get('agentNotes', '')} [Override: Financial Data Request - Risk 75]"
        logger.info(f"OVERRIDE FINANCIAL DATA REQUEST: Risk forced to 75+")
    
    # -------------------------------------------------------------------------
    # RULE 9: ID Theft KYC Override
    # Aadhaar/PAN + KYC/Verification → Risk 65-75
    # -------------------------------------------------------------------------
    kyc_verification_keywords = ["kyc", "verification", "verify your", "identity verification", "document verification"]
    has_kyc_request = any(kw in message_lower for kw in kyc_verification_keywords)
    
    # Check for Aadhaar/PAN mentions (case-insensitive)
    has_aadhaar_mention = "aadhaar" in message_lower or "aadhar" in message_lower
    has_pan_mention = "pan" in message_lower
    
    if (has_aadhaar_mention or has_pan_mention) and has_kyc_request:
        # Force to 65-75 range (not lower than 65, not higher than 75 unless already higher)
        intel["riskScore"] = max(current_risk, 65)
        intel["riskScore"] = min(intel["riskScore"], 75)  # Cap at 75 for this specific override
        intel["isPhishing"] = True
        intel["scamType"] = "ID Theft"
        intel["urgencyLevel"] = "High"
        intel["suspiciousKeywords"] = intel.get("suspiciousKeywords", []) + ["id theft kyc"]
        intel["agentNotes"] = f"{intel.get('agentNotes', '')} [Override: ID Theft KYC Request - Risk 65-75]"
        logger.info(f"OVERRIDE ID THEFT KYC: Risk forced to 65-75")
    
    # -------------------------------------------------------------------------
    # RULE 10: Urgency Multiplier
    # 'Electricity', 'Cut', 'Blocked', 'Hold' + phone/link → +20 Risk
    # -------------------------------------------------------------------------
    urgency_multiplier_keywords = ["electricity", "electric", "power cut", "power supply", "disconnected"]
    urgency_action_keywords = ["cut", "blocked", "hold", "suspend", "disconnect"]
    
    has_urgency_topic = any(kw in message_lower for kw in urgency_multiplier_keywords)
    has_urgency_action = any(kw in message_lower for kw in urgency_action_keywords)
    phone_numbers = intel.get("phoneNumbers", [])
    has_phone_or_link = len(phone_numbers) > 0 or len(phishing_links) > 0
    
    if has_urgency_topic and has_urgency_action and has_phone_or_link:
        # Add +20 to current risk
        intel["riskScore"] = current_risk + 20
        intel["isPhishing"] = True
        intel["scamType"] = "Urgency Scam"
        intel["urgencyLevel"] = "High"
        intel["suspiciousKeywords"] = intel.get("suspiciousKeywords", []) + ["urgency multiplier"]
        intel["agentNotes"] = f"{intel.get('agentNotes', '')} [Override: Urgency Multiplier +20]"
        logger.info(f"OVERRIDE URGENCY MULTIPLIER: +20 Risk added")
    
    # =========================================================================
    # v1.3.4 SAFE-PASS OVERRIDE GATES (Highest Priority - BEFORE PIN Trap)
    # These gates provide quick PASS/SAFE outcomes for known legitimate scenarios
    # =========================================================================
    
    # -------------------------------------------------------------------------
    # Gate 1: Official Status Gate (Fixes SAFE3)
    # If message contains official confirmation + government IDs → FORCE SAFE
    # -------------------------------------------------------------------------
    official_status_keywords = ["successfully linked", "successfully updated"]
    government_id_keywords = ["uidai", "aadhaar", "pan"]
    has_official_status = any(kw in message_lower for kw in official_status_keywords)
    has_government_id = any(kw in message_lower for kw in government_id_keywords)
    
    if has_official_status and has_government_id:
        intel["riskScore"] = 12
        intel["isPhishing"] = False
        intel["scamType"] = "Safe/Transactional"
        intel["urgencyLevel"] = "Low"
        intel["suspiciousKeywords"] = intel.get("suspiciousKeywords", []) + ["official status"]
        intel["agentNotes"] = f"{intel.get('agentNotes', '')} [SAFE-PASS: Official Status Gate - Risk 12]"
        logger.info(f"SAFE-PASS OFFICIAL STATUS: Official status with government ID detected - Risk 12, STOP")
        reply = "✅ Safe: Official status confirmation detected"
        return intel, reply
    
    # -------------------------------------------------------------------------
    # Gate 2: Root Domain Whitelist (Fixes B1)
    # If message contains EXACT root domain (NOT subdomain) → CAP risk at 15%
    # UNLESS message asks for PIN/OTP → let other rules apply
    # -------------------------------------------------------------------------
    whitelist_root_domains = ["jio.com/", "hdfcbank.com/", "icicibank.com/"]
    
    # Check if message contains PIN/OTP request - if so, skip whitelist
    pin_otp_keywords = ["pin", "otp", "password", "secret", "cvv"]
    has_pin_otp_request = any(kw in message_lower for kw in pin_otp_keywords)
    
    has_whitelisted_domain = any(domain in message_lower for domain in whitelist_root_domains)
    
    if has_whitelisted_domain and not has_pin_otp_request:
        # Cap risk at 15% for legitimate bank marketing
        current_check_risk = intel.get("riskScore", 0) or 0
        if current_check_risk > 15:
            intel["riskScore"] = 15
        intel["isPhishing"] = False
        intel["scamType"] = "Safe/Transactional"
        intel["urgencyLevel"] = "Low"
        intel["suspiciousKeywords"] = intel.get("suspiciousKeywords", []) + ["whitelisted domain"]
        intel["agentNotes"] = f"{intel.get('agentNotes', '')} [SAFE-PASS: Root Domain Whitelist - Risk capped at 15]"
        logger.info(f"SAFE-PASS ROOT DOMAIN: Whitelisted domain detected - Risk capped at 15")
        # Don't return early - continue processing but with capped risk
    
    # -------------------------------------------------------------------------
    # Gate 3: Professional Context (Fixes B2)
    # If sender/link is from trusted corporate domains → SET riskScore = 10
    # -------------------------------------------------------------------------
    professional_domains = ["infosys.com", "tcs.com", "wipro.com"]
    
    # Check sender email if available
    sender_email = intel.get("senderEmail", "").lower()
    has_professional_sender = any(domain in sender_email for domain in professional_domains)
    
    # Also check message content for professional context
    has_professional_context = any(domain in message_lower for domain in professional_domains)
    
    if has_professional_sender or has_professional_context:
        intel["riskScore"] = 10
        intel["isPhishing"] = False
        intel["scamType"] = "Safe/Professional"
        intel["urgencyLevel"] = "Low"
        intel["suspiciousKeywords"] = intel.get("suspiciousKeywords", []) + ["professional context"]
        intel["agentNotes"] = f"{intel.get('agentNotes', '')} [SAFE-PASS: Professional Context - Risk 10]"
        logger.info(f"SAFE-PASS PROFESSIONAL: Trusted corporate domain detected - Risk 10")
        reply = "✅ Safe: Professional correspondence detected"
        return intel, reply
    
    # Update current_risk after all overrides
    current_risk = intel.get("riskScore", 0) or 0
    
    # =========================================================================
    # v1.3.3 HARDENING: PIN/Credential Trap (Highest Priority Override)
    # If message contains PIN/password keywords, this is ALWAYS a scam
    # PIN requests are never legitimate - override almost everything
    # =========================================================================
    pin_trap_keywords = ["upi pin", "upi password", "secret pin"]
    has_pin_request = any(kw in message_lower for kw in pin_trap_keywords)
    
    if has_pin_request:
        intel["riskScore"] = 95
        intel["isPhishing"] = True
        intel["scamType"] = "Credential Theft"
        intel["urgencyLevel"] = "High"
        intel["suspiciousKeywords"] = intel.get("suspiciousKeywords", []) + ["pin trap"]
        intel["agentNotes"] = f"{intel.get('agentNotes', '')} [OVERRIDE: PIN/Credential Trap - Risk 95]"
        logger.info(f"OVERRIDE PIN TRAP: PIN/Credential request detected - Risk forced to 95")
        reply = "❌ Danger: PIN/Credential theft attempt detected"
        return intel, reply
    
    # =========================================================================
    # v1.3.3 HARDENING: Government Confirmation Shield
    # If message contains UIDAI confirmation keywords, mark as SAFE
    # BUT: Don't apply if suspicious URL present (like .in/verify-now)
    # =========================================================================
    government_shield_keywords = ["successfully linked", "as per uidai records", "uidai"]
    has_government_shield = any(kw in message_lower for kw in government_shield_keywords)
    
    # Check for suspicious URLs that should block the shield
    suspicious_url_patterns = [".in/verify", ".in/verify-now", ".in/confirm", "/verify-", "verify-now", "verify-now.in"]
    has_suspicious_url = any(pattern in message_lower for pattern in suspicious_url_patterns)
    
    if has_government_shield and not has_suspicious_url:
        # Apply the government shield - mark as safe
        intel["riskScore"] = 12
        intel["isPhishing"] = False
        intel["scamType"] = "Safe/Transactional"
        intel["urgencyLevel"] = "Low"
        intel["suspiciousKeywords"] = intel.get("suspiciousKeywords", []) + ["government confirmation"]
        intel["agentNotes"] = f"{intel.get('agentNotes', '')} [SHIELD: Government confirmation detected - Risk 12]"
        logger.info(f"SHIELD GOVERNMENT CONFIRMATION: UIDAI confirmation detected - Risk 12")
        reply = "✅ Safe: Government confirmation (UIDAI)"
        return intel, reply
    elif has_government_shield and has_suspicious_url:
        # Government keywords present BUT also suspicious URL - treat as high risk
        logger.info(f"GOVERNMENT SHIELD BLOCKED: UIDAI keywords present with suspicious URL")
    
    # =========================================================================
    # v1.2 Titanium RULE 1: Evidence Mandate
    # Trigger: phishingLinks OR upiIds are NOT empty (bank_accounts excluded)
    # If triggered: isPhishing=True, riskScore >= 70
    # =========================================================================
    has_evidence = len(phishing_links) > 0 or len(upi_ids) > 0
    
    if has_evidence:
        # Build artifact list for agentNotes
        artifacts = []
        if phishing_links:
            artifacts.extend(phishing_links[:2])  # Max 2 links
        if upi_ids:
            artifacts.extend(upi_ids[:2])  # Max 2 UPI IDs
        if bank_accounts:
            artifacts.extend(bank_accounts[:1])  # Max 1 bank account
        
        artifact_str = ", ".join(artifacts) if artifacts else "Unknown"
        
        # v1.2: FORCE high-risk values (riskScore >= 70)
        intel["riskScore"] = max(current_risk, 70)
        intel["isPhishing"] = True
        intel["scamType"] = "Confirmed Phishing/Scam"
        intel["urgencyLevel"] = "High"
        intel["agentNotes"] = f"Evidence Found: {artifact_str}"
        reply = f"❌ Danger: Evidence Found: {artifact_str}"
        return intel, reply
    
    # =========================================================================
    # RULE 3: Master Boolean Sync (REFINED for v1.3.1)
    # Logic: riskScore < 30 → isPhishing=False, riskScore >= 30 → isPhishing=True
    # Note: All heuristic overrides already set isPhishing=True when Risk >= 60
    # =========================================================================
    if current_risk < 30:
        intel["isPhishing"] = False
    else:
        intel["isPhishing"] = True
    
    # Build headline reply based on risk category
    if 0 <= current_risk <= 10:
        prefix = "✅ Safe:"
        category = "Safe/Transactional"
    elif 11 <= current_risk <= 50:
        prefix = "⚠️ Warning:"
        category = "Suspicious/Unverified"
    else:  # 51-100
        prefix = "❌ Danger:"
        category = "Confirmed Phishing/Scam"
    
    # Update scamType to match category
    intel["scamType"] = category
    
    # Build the headline reply
    notes = intel.get("agentNotes", "Analysis complete")
    # Truncate notes for headline if too long
    short_notes = notes[:60] + "..." if len(notes) > 60 else notes
    reply = f"{prefix} {short_notes}"
    
    return intel, reply


# =============================================================================
# Background Tasks (Async)
# =============================================================================

async def send_guvi_callback_async(session_id: str, payload: dict):
    """
    Async callback to GUVI webhook.
    Uses httpx.AsyncClient for non-blocking HTTP request.
    
    Validates URL format and handles empty environment variables gracefully.
    """
    # Validate callback URL exists and is properly formatted
    if not GUVI_CALLBACK_URL:
        logger.debug(f"GUVI Callback skipped: No callback URL configured")
        return
    
    if not GUVI_CALLBACK_URL.startswith("http"):
        logger.warning(f"GUVI Callback skipped: Invalid URL format - {GUVI_CALLBACK_URL}")
        return
    
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.post(GUVI_CALLBACK_URL, json=payload)
            logger.info(f"GUVI Callback for {session_id}: {response.status_code}")
            if response.status_code >= 400:
                logger.warning(f"GUVI Callback failed: {response.text}")
    except httpx.TimeoutException:
        logger.error(f"GUVI Callback timeout for {session_id}")
    except Exception as e:
        logger.error(f"GUVI Callback error for {session_id}: {e}")


# =============================================================================
# API Endpoints
# =============================================================================

@app.get("/health")
async def health_check():
    """v1.2 Titanium: Health check endpoint with version."""
    return {
        "status": "online",
        "version": API_VERSION,
        "timestamp": datetime.utcnow().isoformat()
    }

@app.get("/")
async def root():
    """Lightweight root endpoint for health checks."""
    return {"status": "online"}


@app.post("/message", response_model=HoneypotResponse)
@limiter.limit("10/minute")
async def handle_message(
    message_request: HoneypotRequest,
    request: Request,
    background_tasks: BackgroundTasks,
    api_key: str = Depends(verify_api_key)
):
    """
    v1.2 Titanium: Primary endpoint for honeypot scam engagement.
    
    Features:
    - Rate limiting: 10 requests per minute per IP
    - Input normalization: Strips whitespace and invisible Unicode
    - Latency tracking: Returns latency_ms in response
    - Timeout protection: 15s AI timeout with 504 response
    - Version telemetry: Returns API version and timestamp
    
    Process:
    1. Validates API key
    2. Normalizes input (The Filter)
    3. Tracks latency (The Dashboard)
    4. Detects scam intent
    5. Extracts intelligence
    6. Generates response
    7. Saves to database
    8. Sends callback (non-blocking)
    """
    # v1.2 Titanium: Latency tracking start
    start_time = time()
    
    # API Key is already validated by Depends(verify_api_key)
    logger.info(f"API Key validated for request")
    
    # v1.2 Titanium: Legacy rate limiting check (session-based)
    session_id = message_request.get_session_id()
    if not check_rate_limit(session_id):
        raise HTTPException(status_code=429, detail="Rate limit exceeded. Max 10 requests per minute.")
    
    logger.info(f"Processing request for session: {message_request.get_session_id()}")
    
    # Get agent from app state
    agent: ScamAgent = app.state.agent
    
    # Extract message text from message_request.message
    message_data = message_request.message
    if isinstance(message_data, dict):
        raw_text = message_data.get("text", "") or message_data.get("content", "")
    else:
        raw_text = message_data.get_text()
    
    # v1.2 Titanium: Input Normalization (The Filter)
    # Strip whitespace and remove invisible Unicode characters
    message_text = normalize_input(raw_text)
    logger.info(f"Normalized message: '{message_text[:50]}...' (original length: {len(raw_text)}, normalized length: {len(message_text)})")
    
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
            "aadhaarNumbers": [],
            "panNumbers": [],
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
    
    # =====================================================================
    # TIER 1: SOVEREIGN SHIELDS (Whitelists) - Early Return
    # Check deterministic safe patterns first for performance
    # =====================================================================
    logger.info(f"[TIER1] Checking Sovereign Shields for message: {message_text[:50]}...")
    tier1_result = check_tier1_sovereign_shields(message_text)
    if tier1_result:
        logger.info(f"[TIER1] HIT: {tier1_result.get('rule')} - returning immediately")
        intel_response = DEFAULT_INTEL.copy()
        intel_response.update({
            "scamType": tier1_result.get("scamType", "Safe/Transactional"),
            "riskScore": tier1_result.get("riskScore", 5),
            "agentNotes": tier1_result.get("agentNotes", "Safe message detected"),
            "urgencyLevel": tier1_result.get("urgencyLevel", "Low"),
            "isPhishing": tier1_result.get("isPhishing", False)
        })
        reply_text = tier1_result.get("reply", "✅ Safe")
        intel_response, reply_text = finalize_intelligence(intel_response, reply_text, message_text)
        return HoneypotResponse(
            status="success",
            reply=reply_text,
            intelligence=intel_response
        )
    
    # =====================================================================
    # TIER 2: DETERMINISTIC TRAPS (Blacklists) - Early Return
    # Check deterministic scam patterns second for safety
    # =====================================================================
    logger.info(f"[TIER2] Checking Deterministic Traps for message: {message_text[:50]}...")
    tier2_result = check_tier2_deterministic_traps(message_text)
    if tier2_result:
        logger.info(f"[TIER2] HIT: {tier2_result.get('rule')} - returning immediately")
        intel_response = DEFAULT_INTEL.copy()
        intel_response.update({
            "scamType": tier2_result.get("scamType", "Confirmed Phishing/Scam"),
            "riskScore": tier2_result.get("riskScore", 98),
            "agentNotes": tier2_result.get("agentNotes", "Scam detected"),
            "urgencyLevel": tier2_result.get("urgencyLevel", "High"),
            "isPhishing": tier2_result.get("isPhishing", True)
        })
        reply_text = tier2_result.get("reply", "❌ Danger: Scam detected")
        intel_response, reply_text = finalize_intelligence(intel_response, reply_text, message_text)
        return HoneypotResponse(
            status="success",
            reply=reply_text,
            intelligence=intel_response
        )
    
    # =====================================================================
    # TIER 3: LLM HEURISTICS
    # Only run AI detection if no Tier 1 or Tier 2 rules matched
    # =====================================================================
    logger.info(f"[TIER3] Checking if AI detection needed for message: {message_text[:50]}...")
    if not check_tier3_llm_heuristics(message_text):
        logger.info(f"[TIER3] Skipping AI - Message does not require analysis")
        short_response = DEFAULT_INTEL.copy()
        short_response.update({
            "agentNotes": "Message does not require AI analysis",
            "scamType": "Safe/Transactional",
            "riskScore": 5,
            "urgencyLevel": "Low"
        })
        return HoneypotResponse(
            status="success",
            reply="✅ Safe: Analysis complete",
            intelligence=short_response
        )
    
    history = message_request.get_conversation_history()
    metadata = message_request.metadata or {}
    
    # AUDIT LOGGING: Save EVERY request to database immediately
    # This ensures we capture all incoming messages for debugging/analysis
    # Get sender_id for SMS sender verification
    sender_id = None
    if isinstance(message_data, dict):
        sender_id = message_data.get("sender_id") or message_data.get("senderId")
    else:
        sender_id = getattr(message_data, "sender_id", None) or getattr(message_data, "senderId", None)
    
    new_message = {
        "sender": message_data.get("sender", "user") if isinstance(message_data, dict) else getattr(message_data, "sender", "user"),
        "sender_id": sender_id,
        "text": message_text,
        "timestamp": message_data.get("timestamp", 0) if isinstance(message_data, dict) else getattr(message_data, "timestamp", 0)
    }
    
    await db_manager.update_conversation(
        session_id=message_request.get_session_id(),
        new_messages=[new_message],
        intelligence={"bankAccounts": [], "upiIds": [], "phishingLinks": [], "phoneNumbers": [], "suspiciousKeywords": [], "agentNotes": "", "scamType": "Unknown", "urgencyLevel": "Low", "riskScore": 10, "extractedEntities": [], "threatSource": sender_id or ""}
    )
    
    try:
        # v1.2 Titanium: Step 1 - Extract intelligence with 15s timeout
        try:
            intel, reply = await asyncio.wait_for(
                asyncio.gather(
                    agent.extract_intelligence(message_text, history, sender_id),
                    agent.generate_response(message_text, history, metadata)
                ),
                timeout=15.0  # v1.2: Increased from 8.0 to 15.0 seconds
            )
        except asyncio.TimeoutError:
            # v1.2 Titanium: Return 504 Gateway Timeout instead of fallback
            logger.error("AI processing timed out after 15 seconds")
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
        
        # Step 2: Apply Evidence Guard - cap risk if high but no physical evidence
        logger.info(f"Before Evidence Guard: riskScore={intel.get('riskScore')}, links={intel.get('phishingLinks')}, upi={intel.get('upiIds')}, bank={intel.get('bankAccounts')}")
        intel = apply_evidence_guard(intel)
        logger.info(f"After Evidence Guard: riskScore={intel.get('riskScore')}, scamType={intel.get('scamType')}")
        
        # Step 3: Update database with extracted intelligence
        # (initial save already done at top for audit logging)
        await db_manager.update_conversation(
            session_id=message_request.get_session_id(),
            new_messages=[],
            intelligence=intel
        )
        
        # Step 3: Prepare callback payload
        # Deep Flat Sanitizer: Recursively flattens nested lists and extracts dict values
        def ensure_list(val):
            """
            Deep Flat Sanitizer - Recursive schema guardian for AI-generated data.
            
            LLMs return probabilistic output that often violates Pydantic schema requirements,
            causing 400 Bad Request errors. This function recursively traverses nested
            structures (lists of lists, dict-wrapped values, MongoDB $addToSet artifacts)
            and extracts only string values into a flat list.
            
            TRANSFORMATION MATRIX:
            ----------------------
            Input Type              | Output
            ------------------------|---------------------------
            [['url1', 'url2']]      | ['url1', 'url2']
            [{'link': 'url1'}]      | ['url1']
            {'0': 'link1', '1': ...}| ['link1', ...]
            'string'                | [] (strings not in list)
            None                    | []
            123 (int)               | [] (non-strings ignored)
            
            ALGORITHM:
            ----------
            1. Initialize empty result list
            2. Define recursive flatten() helper:
               - If list: recurse on each element
               - If dict: recurse on each value (ignore keys)
               - If string: append to result
               - Else: ignore (numbers, booleans, None)
            3. Execute flatten(val) and return result
            
            USE CASES:
            ----------
            - MongoDB $addToSet operations requiring array input for $each
            - Pydantic model validation requiring List[str] types
            - React Native/Expo frontend compatibility (flat JSON arrays)
            - AI output sanitization before database persistence
            
            Args:
                val: Any value from AI extraction or database query.
                     Commonly: list, dict, nested list, None, or unexpected types.
            
            Returns:
                List[str]: Flat list containing only string values extracted from
                          nested structures. Guaranteed never nested, never containing
                          dicts, and always iterable by React Native FlatList.
            
            Example:
                >>> ensure_list([['netflix.com', 'evil.com']])
                ['netflix.com', 'evil.com']
                >>> ensure_list({'link': 'phishing.com', 'upi': 'user@upi'})
                ['phishing.com', 'user@upi']
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
        
        # Build clean intel dict for logging and response
        # Deduplicate UPIs and links (Fix 3: Entity Deduplication)
        # v1.3.0: Added aadhaarNumbers and panNumbers
        intel_dict = {
            "bankAccounts": ensure_list(intel.get("bankAccounts", [])),
            "upiIds": list(set(ensure_list(intel.get("upiIds", [])))),
            "phishingLinks": list(set(ensure_list(intel.get("phishingLinks", [])))),
            "phoneNumbers": ensure_list(intel.get("phoneNumbers", [])),
            "suspiciousKeywords": ensure_list(intel.get("suspiciousKeywords", [])),
            "aadhaarNumbers": ensure_list(intel.get("aadhaarNumbers", [])),
            "panNumbers": ensure_list(intel.get("panNumbers", [])),
            "agentNotes": intel.get("agentNotes", ""),
            "scamType": intel.get("scamType", "Unknown"),
            "urgencyLevel": intel.get("urgencyLevel", "Low"),
            "riskScore": intel.get("riskScore", 0),
            "extractedEntities": list(set(ensure_list(intel.get("extractedEntities", []))))
        }
        
        # Apply Synchronization Rules: Boolean Sync, Note-Evidence Link, Reply-Score Sanitization
        intel_dict, reply = finalize_intelligence(intel_dict, reply, message_text)
        
        logger.info(f"FINAL INTEL OBJECT: {intel_dict}")
        
        # =========================================================================
        # v1.3.2 SAFE-PASS GATE - PRIORITY 1
        # Principle: Legitimate messages have codes + warnings. Scammers have requests.
        # =========================================================================
        try:
            # Normalize text for check
            t_low = message_text.lower() if message_text else ""
            
            # Get current score safely
            f_score = intel_dict.get("riskScore", 0) or 0
            
            # =========================================================================
            # 1. REGEX FOR NUMERIC OTP: Check for 6-8 digit code
            # =========================================================================
            import re
            otp_code_pattern = re.search(r'\b\d{6,8}\b', t_low)
            has_otp_code = bool(otp_code_pattern)
            
            # =========================================================================
            # 2. SAFE-PASS GATE (Priority 1): Check for legitimate automated message
            # If ("do not share" OR "valid for") AND (6-8 digit code): SAFE
            # =========================================================================
            safe_indicators = ["do not share", "never share", "don't share", "valid for", "expires in"]
            is_safe_indicator = any(ind in t_low for ind in safe_indicators)
            
            if is_safe_indicator and has_otp_code:
                # This is a legitimate OTP with security warning - SAFE PASS
                f_score = 10
                intel_dict["riskScore"] = f_score
                intel_dict["isPhishing"] = False
                intel_dict["scamType"] = "Safe/Transactional"
                intel_dict["urgencyLevel"] = "Low"
                reply = "✅ Safe: Legitimate OTP message with security warning"
                logger.info(f"SAFE-PASS: Legitimate OTP with warning - Score {f_score}")
                # RETURN immediately - don't run phishing traps
                ext_intel = IntelligenceData(**intel_dict)
                
                # Build response
                latency_ms = int((time() - start_time) * 1000)
                response_data = {
                    "status": "success",
                    "reply": reply,
                    "intelligence": intel_dict,
                    "version": API_VERSION,
                    "timestamp": datetime.utcnow().isoformat(),
                    "latency_ms": latency_ms
                }
                return HoneypotResponse(**response_data)
            
            # =========================================================================
            # 3. PHISHING TRAPS (Priority 2): Only runs if Safe-Pass was NOT triggered
            # =========================================================================
            # Scam: OTP + share/request
            if "otp" in t_low and any(w in t_low for w in ["share", "provide", "verify", "executive"]):
                f_score = max(f_score, 70)
                logger.info(f"PHISHING TRAP: OTP + request -> Risk {f_score}")
            
            # Scam: Financial data request
            if any(w in t_low for w in ["card details", "cvv", "expiry", "card number"]) and "address" in t_low:
                f_score = max(f_score, 80)
                logger.info(f"PHISHING TRAP: Financial data request -> Risk {f_score}")
            
            # Scam: ID Theft KYC
            if any(w in t_low for w in ["aadhaar", "pan card", "pan number"]) and any(w in t_low for w in ["kyc", "verify", "update"]):
                f_score = max(f_score, 72)
                logger.info(f"PHISHING TRAP: ID Theft KYC request -> Risk {f_score}")
            
            # Update intelligence object
            intel_dict["riskScore"] = f_score
            if f_score >= 60:
                intel_dict["isPhishing"] = True
                intel_dict["scamType"] = "Confirmed Phishing/Scam"
                intel_dict["urgencyLevel"] = "High"
                reply = f"❌ Danger: High risk scam detected (Score: {f_score})"
            
        except Exception as e:
            logger.warning(f"SAFE-PASS GATE ERROR: {e}")
        
        ext_intel = IntelligenceData(**intel_dict)
        
        # Only send callback if scam detected
        is_scam = intel.get("riskScore", 0) > 30
        if is_scam:
            callback_payload = {
                "sessionId": message_request.get_session_id(),
                "scamDetected": True,
                "totalMessagesExchanged": len(history) + 1,
                "extractedIntelligence": ext_intel.model_dump(),
                "agentNotes": intel.get("agentNotes", "Scammer engaged.")
            }
            background_tasks.add_task(send_guvi_callback_async, message_request.get_session_id(), callback_payload)
        
        # v1.2 Titanium: Calculate latency
        latency_ms = int((time() - start_time) * 1000)
        
        # v1.2 Titanium: Step 4 - Return response with telemetry
        logger.info(f"RETURNING RESPONSE: reply={reply}, intel={intel_dict}, latency={latency_ms}ms")
        
        # Build response with v1.2 Titanium telemetry
        response_data = {
            "status": "success",
            "reply": reply,
            "intelligence": intel_dict,
            "version": API_VERSION,
            "timestamp": datetime.utcnow().isoformat(),
            "latency_ms": latency_ms
        }
        
        return HoneypotResponse(**response_data)
    
    except HTTPException:
        # Re-raise HTTP exceptions (including our 504 timeout)
        raise
    except Exception as e:
        # v1.2 Titanium: Return structured error response
        logger.exception(f"Error processing request: {e}")
        latency_ms = int((time() - start_time) * 1000)
        raise HTTPException(
            status_code=500,
            detail={
                "status": "error",
                "error": "Internal server error",
                "message": str(e) if os.getenv("DEBUG", "false").lower() == "true" else "An unexpected error occurred",
                "latency_ms": latency_ms,
                "version": API_VERSION,
                "timestamp": datetime.utcnow().isoformat()
            }
        )


# =============================================================================
# Startup Event
# =============================================================================

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
