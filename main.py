from fastapi import FastAPI, HTTPException, Header, Depends, BackgroundTasks, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import List, Optional, Union, Dict
import os
import time
import requests
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

# Models
class Message(BaseModel):
    sender: str
    text: str
    timestamp: Union[int, float] # Flexible: accepts int or float

class Metadata(BaseModel):
    channel: Optional[str] = "SMS"
    language: Optional[str] = "English"
    locale: Optional[str] = "IN"

class ScamRequest(BaseModel):
    sessionId: str # exact camelCase
    message: Message
    conversationHistory: Optional[List[Message]] = Field(default_factory=list)
    metadata: Optional[Union[Metadata, Dict]] = Field(default_factory=dict) # Flexible dict or Metadata model

class ExtractedIntelligence(BaseModel):
    bankAccounts: List[str] = []
    upiIds: List[str] = []
    phishingLinks: List[str] = []
    phoneNumbers: List[str] = []
    suspiciousKeywords: List[str] = []

class ScamResponse(BaseModel):
    status: str
    reply: str # Updated response format

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

@app.post("/message", response_model=ScamResponse)
async def handle_message(
    request: ScamRequest, 
    background_tasks: BackgroundTasks,
    api_key: str = Depends(verify_api_key)
):
    # Convert conversation history to simple dict list for the agent
    history_list = [{"sender": m.sender, "text": m.text} for m in request.conversationHistory]
    
    # 1. Detect Scam
    is_scam = agent.detect_scam(request.message.text, history_list)
    
    if not is_scam:
        return ScamResponse(status="success", reply="Hello! How can I help you today?")

    # 2. Extract Intelligence
    intel = agent.extract_intelligence(request.message.text, history_list)
    
    # 3. Generate Agent Response (Engagement)
    metadata_dict = request.metadata if isinstance(request.metadata, dict) else request.metadata.model_dump()
    agent_reply = agent.generate_response(request.message.text, history_list, metadata_dict)
    
    # 4. Mandatory Callback (Non-blocking via BackgroundTasks)
    # Using Option 1: Live Updates for maximum data persistence.
    
    # Intelligence validation
    ext_intel = {
        "bankAccounts": intel.get("bankAccounts", []),
        "upiIds": intel.get("upiIds", []), 
        "phishingLinks": intel.get("phishingLinks", []), 
        "phoneNumbers": intel.get("phoneNumbers", []),
        "suspiciousKeywords": intel.get("suspiciousKeywords", [])
    }
    
    has_entities = any(len(v) > 0 for v in ext_intel.values())
    if not has_entities:
        print(f"WARNING: Scam detected for session {request.sessionId} but no entities extracted.")

    callback_payload = {
        "sessionId": request.sessionId,
        "scamDetected": True,
        "totalMessagesExchanged": len(request.conversationHistory) + 1,
        "extractedIntelligence": ext_intel,
        "agentNotes": intel.get("agentNotes", "Scammer engaged.")
    }
    
    background_tasks.add_task(send_guvi_callback, request.sessionId, callback_payload)

    return ScamResponse(
        status="success",
        reply=agent_reply
    )

if __name__ == "__main__":
    import uvicorn
    import os
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
