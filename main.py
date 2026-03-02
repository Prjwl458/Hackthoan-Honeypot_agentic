from dotenv import load_dotenv
load_dotenv()

"""
FastAPI application entry point for Agentic AI Honeypot.
Production-ready with async HTTP, database integration, and global error handling.
"""

import os
import asyncio
import logging
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Optional, Dict, Any
from collections import defaultdict
from time import time

import httpx
from fastapi import FastAPI, HTTPException, Header, BackgroundTasks, Depends
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import ValidationError

from models import HoneypotRequest, HoneypotResponse, IntelligenceData
from database import db_manager
from agent import ScamAgent, pre_process_message, apply_evidence_guard

# Rate Limiter: 10 requests per minute per session
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
    
    Algorithm:
        1. Get current timestamp
        2. Remove all old timestamps outside the window
        3. If remaining requests >= max_requests, return False
        4. Otherwise, add current timestamp and return True
    """
    now = time()
    # Clean old entries
    rate_limit_store[session_id] = [t for t in rate_limit_store[session_id] if now - t < window_seconds]
    
    if len(rate_limit_store[session_id]) >= max_requests:
        return False
    
    rate_limit_store[session_id].append(now)
    return True

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
    version="2.0.0",
    lifespan=lifespan
)

# CORS Configuration
# =============================================================================
# Allow all origins for development/testing.
# In production, restrict to your actual domains.
# =============================================================================
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global Exception Handler - returns clean 503 JSON on failures
@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    """Catch all unhandled exceptions and return clean 503 response."""
    logger.error(f"Unhandled exception: {exc}")
    return JSONResponse(
        status_code=503,
        content={"status": "error", "detail": "Service temporarily unavailable"}
    )

# Validation error handler
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc):
    """Handle validation errors gracefully."""
    return JSONResponse(
        status_code=422,
        content={"status": "error", "detail": "Invalid request parameters"}
    )

# Configuration from environment
# Fallback to default key for development if not set
EXPECTED_KEY = os.getenv("API_KEY", "prajwal_hackathon_key_2310")
GUVI_CALLBACK_URL = os.getenv("GUVI_CALLBACK_URL", "")
DEBUG = os.getenv("DEBUG", "true").lower() == "true"

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
    
    Args:
        x_api_key: API key passed in the X-API-Key header.
    
    Returns:
        The API key if valid.
    
    Raises:
        HTTPException: 403 if API key is invalid or missing.
    
    Security Note:
        All production endpoints should require valid API key.
        The key must match the EXPECTED_KEY environment variable.
    """
    # Handle missing or empty API key
    if not x_api_key:
        logger.warning("403: Missing API Key header")
        raise HTTPException(status_code=403, detail="Missing API Key")
    
    # Strip whitespace from provided key
    provided_key = x_api_key.strip()
    
    # Log key lengths for debugging
    logger.warning(f"Security: Expected key len={len(EXPECTED_KEY)}, Received key len={len(provided_key)}")
    
    # Compare keys
    if provided_key != EXPECTED_KEY:
        logger.warning(f"403: Invalid API Key provided: {provided_key[:4]}...")
        raise HTTPException(status_code=403, detail="Invalid API Key")
    
    return provided_key


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
    2. Rule 1 (Evidence = High Risk) - Override with physical evidence
    3. Rule 3 (Master Boolean Sync) - Final consistency check
    
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
    # =========================================================================
    intel["phishingLinks"] = intel.get("phishingLinks") or []
    intel["upiIds"] = intel.get("upiIds") or []
    intel["bankAccounts"] = intel.get("bankAccounts") or []
    intel["phoneNumbers"] = intel.get("phoneNumbers") or []
    intel["suspiciousKeywords"] = intel.get("suspiciousKeywords") or []
    
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
    # RULE 2: OTP Transactional Safeguard
    # Trigger: 'OTP' in text AND (phishingLinks empty AND upiIds empty) AND no 'forward'/'share'
    # =========================================================================
    has_otp = "otp" in message_lower
    has_links_or_upi = len(phishing_links) > 0 or len(upi_ids) > 0
    has_forward_share = "forward" in message_lower or "share" in message_lower
    
    if has_otp and not has_links_or_upi and not has_forward_share:
        # FORCE safe transactional classification
        intel["riskScore"] = 5
        intel["isPhishing"] = False
        intel["scamType"] = "Safe/Transactional"
        intel["urgencyLevel"] = "Low"
        intel["agentNotes"] = "Safe: Transactional OTP message"
        reply = "✅ Safe: Transactional OTP message"
        return intel, reply
    
    # =========================================================================
    # RULE 1: Evidence = High Risk
    # Trigger: phishingLinks, upiIds, OR bankAccounts are NOT empty
    # =========================================================================
    has_evidence = len(phishing_links) > 0 or len(upi_ids) > 0 or len(bank_accounts) > 0
    
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
        
        # FORCE high-risk values
        intel["riskScore"] = max(risk_score, 75)
        intel["isPhishing"] = True
        intel["scamType"] = "Confirmed Phishing/Scam"
        intel["urgencyLevel"] = "High"
        intel["agentNotes"] = f"Evidence Found: {artifact_str}"
        reply = f"❌ Danger: Evidence Found: {artifact_str}"
        return intel, reply
    
    # =========================================================================
    # RULE 3: Master Boolean Sync
    # Logic: riskScore < 30 → isPhishing=False, riskScore >= 30 → isPhishing=True
    # =========================================================================
    if risk_score < 30:
        intel["isPhishing"] = False
    else:
        intel["isPhishing"] = True
    
    # Build headline reply based on risk category
    if 0 <= risk_score <= 10:
        prefix = "✅ Safe:"
        category = "Safe/Transactional"
    elif 11 <= risk_score <= 50:
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
    """Simple health check for wake server button."""
    return {"status": "online"}

@app.get("/")
async def root():
    """Health check endpoint."""
    db_status = "connected" if db_manager._connection_verified and not db_manager._use_in_memory else "fallback"
    return {
        "status": "success",
        "service": "Agentic AI Honeypot",
        "version": "2.0.0",
        "database": db_status
    }


@app.post("/message", response_model=HoneypotResponse)
async def handle_message(
    request: HoneypotRequest,
    background_tasks: BackgroundTasks,
    api_key: str = Depends(verify_api_key)
):
    """
    Primary endpoint for honeypot scam engagement.
    
    1. Validates API key
    2. Detects scam intent
    3. Extracts intelligence
    4. Generates tarpitting response
    5. Saves to database
    6. Sends callback (non-blocking)
    """
    # API Key is already validated by Depends(verify_api_key)
    logger.info(f"API Key validated for request")
    
    # Rate limiting check
    session_id = request.get_session_id()
    if not check_rate_limit(session_id):
        raise HTTPException(status_code=429, detail="Rate limit exceeded. Max 10 requests per minute.")
    
    logger.info(f"Processing request for session: {request.get_session_id()}")
    
    # Get agent from app state
    agent: ScamAgent = app.state.agent
    
    # Extract message text from request.message
    message_data = request.message
    if isinstance(message_data, dict):
        message_text = message_data.get("text", "") or message_data.get("content", "")
    else:
        message_text = message_data.get_text()
    
    # =====================================================================
    # THE ENTRY GATE: WHITELIST PRE-PROCESSING (MUST be first!)
    # =====================================================================
    logger.info(f"Checking whitelist for message: {message_text[:50]}...")
    whitelist_result = pre_process_message(message_text)
    if whitelist_result:
        logger.info(f"WHITELIST HIT: {whitelist_result.get('scamType')} - returning immediately")
        # Build full intelligence from template with whitelist values
        intel_response = DEFAULT_INTEL.copy()
        intel_response.update({
            "scamType": whitelist_result.get("scamType", "Safe/Transactional"),
            "riskScore": whitelist_result.get("riskScore", 5),
            "agentNotes": whitelist_result.get("agentNotes", "Safe message detected"),
            "urgencyLevel": whitelist_result.get("urgencyLevel", "Low")
        })
        # Apply synchronization rules (isPhishing, reply-score sync)
        reply_text = intel_response["agentNotes"]
        intel_response, reply_text = finalize_intelligence(intel_response, reply_text, message_text)
        
        # Return complete response matching the AI flow structure
        return HoneypotResponse(
            status="success",
            reply=reply_text,
            intelligence=intel_response
        )
    
    history = request.get_conversation_history()
    metadata = request.metadata or {}
    
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
        session_id=request.get_session_id(),
        new_messages=[new_message],
        intelligence={"bankAccounts": [], "upiIds": [], "phishingLinks": [], "phoneNumbers": [], "suspiciousKeywords": [], "agentNotes": "", "scamType": "Unknown", "urgencyLevel": "Low", "riskScore": 10, "extractedEntities": [], "threatSource": sender_id or ""}
    )
    
    try:
        # Step 1: Extract intelligence and generate verdict (ALWAYS - for all requests)
        try:
            intel, reply = await asyncio.wait_for(
                asyncio.gather(
                    agent.extract_intelligence(message_text, history, sender_id),
                    agent.generate_response(message_text, history, metadata)
                ),
                timeout=8.0
            )
        except asyncio.TimeoutError:
            logger.warning("AI processing timed out, using fallback")
            reply = "Neutral - Analysis inconclusive due to timeout"
            intel = {
                "bankAccounts": [],
                "upiIds": [],
                "phishingLinks": [],
                "phoneNumbers": [],
                "suspiciousKeywords": [],
                "agentNotes": "Processing timed out",
                "scamType": "Unknown",
                "urgencyLevel": "Low",
                "riskScore": 0,
                "extractedEntities": [],
                "threatSource": sender_id or ""
            }
        
        # Step 2: Apply Evidence Guard - cap risk if high but no physical evidence
        logger.info(f"Before Evidence Guard: riskScore={intel.get('riskScore')}, links={intel.get('phishingLinks')}, upi={intel.get('upiIds')}, bank={intel.get('bankAccounts')}")
        intel = apply_evidence_guard(intel)
        logger.info(f"After Evidence Guard: riskScore={intel.get('riskScore')}, scamType={intel.get('scamType')}")
        
        # Step 3: Update database with extracted intelligence
        # (initial save already done at top for audit logging)
        await db_manager.update_conversation(
            session_id=request.get_session_id(),
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
        intel_dict = {
            "bankAccounts": ensure_list(intel.get("bankAccounts", [])),
            "upiIds": ensure_list(intel.get("upiIds", [])),
            "phishingLinks": ensure_list(intel.get("phishingLinks", [])),
            "phoneNumbers": ensure_list(intel.get("phoneNumbers", [])),
            "suspiciousKeywords": ensure_list(intel.get("suspiciousKeywords", [])),
            "agentNotes": intel.get("agentNotes", ""),
            "scamType": intel.get("scamType", "Unknown"),
            "urgencyLevel": intel.get("urgencyLevel", "Low"),
            "riskScore": intel.get("riskScore", 0),
            "extractedEntities": ensure_list(intel.get("extractedEntities", []))
        }
        
        # Apply Synchronization Rules: Boolean Sync, Note-Evidence Link, Reply-Score Sanitization
        intel_dict, reply = finalize_intelligence(intel_dict, reply, message_text)
        
        logger.info(f"FINAL INTEL OBJECT: {intel_dict}")
        
        ext_intel = IntelligenceData(**intel_dict)
        
        # Only send callback if scam detected
        is_scam = intel.get("riskScore", 0) > 30
        if is_scam:
            callback_payload = {
                "sessionId": request.get_session_id(),
                "scamDetected": True,
                "totalMessagesExchanged": len(history) + 1,
                "extractedIntelligence": ext_intel.model_dump(),
                "agentNotes": intel.get("agentNotes", "Scammer engaged.")
            }
            background_tasks.add_task(send_guvi_callback_async, request.get_session_id(), callback_payload)
        
        # Step 4: Return response with full intelligence (ALWAYS)
        logger.info(f"RETURNING RESPONSE: reply={reply}, intel={intel_dict}")
        return HoneypotResponse(
            status="success",
            reply=reply,  # This is now the Summary Verdict
            intelligence=intel_dict
        )
    
    except Exception as e:
        # Let errors propagate so we can see actual traceback in logs
        logger.exception(f"Error processing request: {e}")
        raise


# =============================================================================
# Startup Event
# =============================================================================

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
