from fastapi import FastAPI, HTTPException, Header, Depends, BackgroundTasks, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import List, Optional, Union, Dict
import os
import time
import requests
import traceback
from datetime import datetime
from dotenv import load_dotenv
from agent import ScamAgent

load_dotenv()

# Initialize Agent
agent = ScamAgent()

app = FastAPI(title="Agentic Honey-Pot API")

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Log the raw request body on validation error"""
    body = await request.body()
    print(f"ERROR: Validation failed for request. Raw body: {body.decode()}")
    return JSONResponse(
        status_code=422,
        content={"detail": exc.errors(), "body": body.decode()},
    )

# Configuration
API_KEY = os.getenv("YOUR_SECRET_API_KEY", "default_secret_key")
GUVI_CALLBACK_URL = os.getenv("GUVI_CALLBACK_URL", "https://hackathon.guvi.in/api/updateHoneyPotFinalResult")

# Security
async def verify_api_key(x_api_key: str = Header(None)):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=403, detail="Invalid API Key")
    return x_api_key

def send_guvi_callback(session_id: str, payload: dict):
    """Background task to send intelligence to GUVI with detailed logging"""
    try:
        response = requests.post(
            GUVI_CALLBACK_URL,
            json=payload,
            timeout=15
        )
        print(f"DEBUG: GUVI Callback for {session_id} returned {response.status_code}: {response.text}")
    except Exception as e:
        print(f"ERROR: GUVI Callback for {session_id} failed: {e}")

@app.post("/message")
async def handle_message(
    request: Request, 
    background_tasks: BackgroundTasks,
    api_key: str = Depends(verify_api_key)
):
    try:
        # 0. Raw Body Access & Logging
        body = await request.json()
        print(f"RAW REQUEST: {body}")

        # 1. Manual Field Extraction with case-insensitive fallback
        # Spec says 'sessionId' but some bots might send 'sessionID'
        session_id = body.get('sessionId') or body.get('sessionID') or "unknown_session"
        
        latest_message_obj = body.get('message', {})
        text = latest_message_obj.get('text', "")
        
        # conversationHistory handling
        history = body.get('conversationHistory') or []
        # Ensure history is a list for the agent
        if not isinstance(history, list):
            history = []
            
        metadata = body.get('metadata') or {}
        
        # 1. Detect Scam
        is_scam = agent.detect_scam(text, history)
        
        if not is_scam:
            return {"status": "success", "reply": "Hello! How can I help you today?"}

        # 2. Extract Intelligence
        intel = agent.extract_intelligence(text, history)
        
        # 3. Generate Agent Response (Engagement)
        agent_reply = agent.generate_response(text, history, metadata)
        
        # 4. Mandatory Callback (Non-blocking via BackgroundTasks)
        ext_intel = {
            "bankAccounts": intel.get("bankAccounts", []),
            "upiIds": intel.get("upiIds", []), 
            "phishingLinks": intel.get("phishingLinks", []), 
            "phoneNumbers": intel.get("phoneNumbers", []),
            "suspiciousKeywords": intel.get("suspiciousKeywords", [])
        }
        
        has_entities = any(len(v) > 0 for v in ext_intel.values())
        if not has_entities:
            print(f"WARNING: Scam detected for session {session_id} but no entities extracted.")

        callback_payload = {
            "sessionId": session_id,
            "scamDetected": True,
            "totalMessagesExchanged": len(history) + 1,
            "extractedIntelligence": ext_intel,
            "agentNotes": intel.get("agentNotes", "Scammer engaged.")
        }
        
        background_tasks.add_task(send_guvi_callback, session_id, callback_payload)

        return {
            "status": "success",
            "reply": agent_reply
        }

    except Exception as e:
        print(f"CRITICAL ERROR in handle_message: {e}")
        print(traceback.format_exc())
        return JSONResponse(
            status_code=200, # Return 200 to keep the bot engaged even on error
            content={"status": "error", "reply": "I'm sorry, can you repeat that?"}
        )

if __name__ == "__main__":
    import uvicorn
    import os
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
