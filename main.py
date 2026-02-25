"""
FastAPI application entry point for Agentic AI Honeypot.
Production-ready with async HTTP, database integration, and global error handling.
"""

import os
import asyncio
import logging
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Optional

import httpx
from fastapi import FastAPI, HTTPException, Header, BackgroundTasks
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import ValidationError
from dotenv import load_dotenv

from models import HoneypotRequest, HoneypotResponse, IntelligenceData
from database import db_manager
from agent import ScamAgent

# Load environment variables
load_dotenv()

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

# TODO: Restrict this before production deployment with mobile app
# Example: CORSMiddleware(app, allow_origins=["https://yourapp.com"])
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins for now
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configuration from environment
API_KEY = os.getenv("API_KEY")
GUVI_CALLBACK_URL = os.getenv(
    "GUVI_CALLBACK_URL",
    "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"
)
DEBUG = os.getenv("DEBUG", "true").lower() == "true"


# =============================================================================
# Exception Handlers
# =============================================================================

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc):
    """Handle Pydantic validation errors."""
    logger.warning(f"Validation error: {exc.errors()}")
    return JSONResponse(
        status_code=422,
        content={
            "status": "error",
            "error": "Validation error",
            "details": exc.errors()
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
    """Verify the API key from request headers."""
    if x_api_key != API_KEY:
        raise HTTPException(status_code=403, detail="Invalid API Key")
    return x_api_key


# =============================================================================
# Background Tasks (Async)
# =============================================================================

async def send_guvi_callback_async(session_id: str, payload: dict):
    """
    Async callback to GUVI webhook.
    Uses httpx.AsyncClient for non-blocking HTTP request.
    """
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

@app.get("/")
async def root():
    """Health check endpoint."""
    return {
        "status": "success",
        "service": "Agentic AI Honeypot",
        "version": "2.0.0"
    }


@app.post("/", response_model=HoneypotResponse)
async def handle_message(
    request: HoneypotRequest,
    background_tasks: BackgroundTasks,
    x_api_key: str = Header(None)
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
    # API Key validation
    if x_api_key != API_KEY:
        logger.warning(f"Blocked: Invalid API key attempt from client")
        raise HTTPException(status_code=403, detail="Invalid API Key")
    
    logger.info(f"Processing request for session: {request.sessionId}")
    
    # Get agent from app state
    agent: ScamAgent = app.state.agent
    
    # Extract message text
    message_text = request.message.text
    history = [msg.model_dump() for msg in request.conversationHistory]
    metadata = request.metadata.model_dump() if request.metadata else {}
    
    try:
        # Step 1: Detect scam intent
        is_scam = await agent.detect_scam(message_text, history)
        
        if not is_scam:
            return HoneypotResponse(
                status="success",
                reply="Hello! How can I help you today?"
            )
        
        # Step 2: Extract intelligence and generate response (with timeout)
        try:
            intel, reply = await asyncio.wait_for(
                asyncio.gather(
                    agent.extract_intelligence(message_text, history),
                    agent.generate_response(message_text, history, metadata)
                ),
                timeout=8.0
            )
        except asyncio.TimeoutError:
            logger.warning("AI processing timed out, using fallback")
            reply = "I'm not sure I understand. Could you please explain what I need to do?"
            intel = {
                "bankAccounts": [],
                "upiIds": [],
                "phishingLinks": [],
                "phoneNumbers": [],
                "suspiciousKeywords": [],
                "agentNotes": "Processing timed out"
            }
        
        # Step 3: Save to database (with fallback to in-memory)
        new_message = {
            "sender": request.message.sender,
            "text": message_text,
            "timestamp": request.message.timestamp
        }
        
        await db_manager.update_conversation(
            session_id=request.sessionId,
            new_messages=[new_message],
            intelligence=intel
        )
        
        # Step 4: Prepare callback payload
        ext_intel = IntelligenceData(
            bankAccounts=intel.get("bankAccounts", []),
            upiIds=intel.get("upiIds", []),
            phishingLinks=intel.get("phishingLinks", []),
            phoneNumbers=intel.get("phoneNumbers", []),
            suspiciousKeywords=intel.get("suspiciousKeywords", []),
            agentNotes=intel.get("agentNotes", "")
        )
        
        callback_payload = {
            "sessionId": request.sessionId,
            "scamDetected": True,
            "totalMessagesExchanged": len(history) + 1,
            "extractedIntelligence": ext_intel.model_dump(),
            "agentNotes": intel.get("agentNotes", "Scammer engaged.")
        }
        
        # Step 5: Send non-blocking callback
        background_tasks.add_task(send_guvi_callback_async, request.sessionId, callback_payload)
        
        return HoneypotResponse(status="success", reply=reply)
        
    except Exception as e:
        logger.exception(f"Error processing request: {e}")
        # Don't let errors break the engagement - return fallback response
        return HoneypotResponse(
            status="success",
            reply="I'm having some trouble connecting. Please try again in a moment."
        )


@app.post("/message", response_model=HoneypotResponse)
async def handle_message_v1(
    request: HoneypotRequest,
    background_tasks: BackgroundTasks,
    x_api_key: str = Header(None)
):
    """
    Backward-compatible endpoint for /message.
    Routes to the same logic as root endpoint.
    """
    return await handle_message(request, background_tasks, x_api_key)


# =============================================================================
# Startup Event
# =============================================================================

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
