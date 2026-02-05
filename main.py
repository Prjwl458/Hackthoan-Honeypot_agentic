from fastapi import FastAPI, HTTPException, Header, Depends, BackgroundTasks, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import List, Optional, Union, Dict
import os
import time
import requests
import traceback
import asyncio
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
# Updated to match specific hackathon requirement
API_KEY = "prajwal_hackathon_key_2310"
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

@app.post("/")
async def handle_message_root(
    request: Request, 
    background_tasks: BackgroundTasks,
    x_api_key: str = Header(None)
):
    # Manual API Key check to ensure it matches the specific requirement
    if x_api_key != API_KEY:
        raise HTTPException(status_code=403, detail="Invalid API Key")

    try:
        # 0. Raw Body Access & Logging
        body = await request.json()
        print(f"RAW REQUEST: {body}")

        # 1. Manual Field Extraction
        session_id = body.get('sessionId') or body.get('sessionID') or "unknown_session"
        latest_message_obj = body.get('message', {})
        text = latest_message_obj.get('text', "")
        history = body.get('conversationHistory') or []
        if not isinstance(history, list):
            history = []
        metadata = body.get('metadata') or {}
        
        # 2. Process with AI (with a timeout/fallback mechanism)
        try:
            # We wrap the AI call in a timeout to ensure quick response
            # detect_scam is usually fast, but generate_response/extract_intelligence might take time
            # For a hackathon, let's prioritize the response.
            
            # Simple check for scam intent
            is_scam = agent.detect_scam(text, history)
            
            if not is_scam:
                return {"status": "success", "reply": "Hello! How can I help you today?"}

            # Wrap the heavy AI parts in a wait with timeout
            # We'll try to get a response within 8 seconds
            async def get_ai_response():
                intel = agent.extract_intelligence(text, history)
                reply = agent.generate_response(text, history, metadata)
                return intel, reply

            try:
                intel, agent_reply = await asyncio.wait_for(asyncio.to_thread(lambda: (
                    agent.extract_intelligence(text, history),
                    agent.generate_response(text, history, metadata)
                )), timeout=8.0)
            except asyncio.TimeoutError:
                print("AI Processing timed out, using fallback reply")
                agent_reply = "I'm not sure I understand. Could you please explain what I need to do?"
                intel = {"bankAccounts": [], "upiIds": [], "phishingLinks": [], "phoneNumbers": [], "suspiciousKeywords": [], "agentNotes": "Processing timed out"}

            # 3. Mandatory Callback (Non-blocking)
            ext_intel = {
                "bankAccounts": intel.get("bankAccounts", []),
                "upiIds": intel.get("upiIds", []), 
                "phishingLinks": intel.get("phishingLinks", []), 
                "phoneNumbers": intel.get("phoneNumbers", []),
                "suspiciousKeywords": intel.get("suspiciousKeywords", [])
            }
            
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

        except Exception as ai_err:
            print(f"AI Logic Error: {ai_err}")
            return {"status": "success", "reply": "I'm sorry, I'm a bit confused. Can you tell me more?"}

    except Exception as e:
        print(f"CRITICAL ERROR in handle_message: {e}")
        print(traceback.format_exc())
        return {"status": "success", "reply": "I'm having some trouble connecting. Please try again in a moment."}

# Keeping /message for backward compatibility if needed, but routing to same logic
@app.post("/message")
async def handle_message_v1(request: Request, background_tasks: BackgroundTasks, x_api_key: str = Header(None)):
    return await handle_message_root(request, background_tasks, x_api_key)

if __name__ == "__main__":
    import uvicorn
    import os
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
