from fastapi import FastAPI, HTTPException, Header, Depends, BackgroundTasks
from pydantic import BaseModel, Field
from typing import List, Optional
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

# Configuration
API_KEY = os.getenv("YOUR_SECRET_API_KEY", "default_secret_key")

# Models
class Message(BaseModel):
    sender: str
    text: str
    timestamp: int # Updated to Epoch time format in ms

class Metadata(BaseModel):
    channel: Optional[str] = "SMS"
    language: Optional[str] = "English"
    locale: Optional[str] = "IN"

class ScamRequest(BaseModel):
    sessionId: str # Mandatory sessionId
    message: Message
    conversationHistory: Optional[List[Message]] = Field(default_factory=list)
    metadata: Optional[Metadata] = None

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

def send_guvi_callback(payload: dict):
    """Background task to send intelligence to GUVI"""
    try:
        requests.post(
            "https://hackathon.guvi.in/api/updateHoneyPotFinalResult",
            json=payload,
            timeout=10
        )
    except Exception as e:
        print(f"GUVI Callback failed: {e}")

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
    agent_reply = agent.generate_response(request.message.text, history_list, request.metadata.model_dump() if request.metadata else {})
    
    # 4. Mandatory Callback (Non-blocking via BackgroundTasks)
    # Using Option 1: Live Updates for maximum data persistence.
    callback_payload = {
        "sessionId": request.sessionId,
        "scamDetected": True,
        "totalMessagesExchanged": len(request.conversationHistory) + 1, # Accurate count (History + Current)
        "extractedIntelligence": {
            "bankAccounts": intel.get("bankAccounts", []),
            "upiIds": intel.get("upiIds", []), # camelCase validated
            "phishingLinks": intel.get("phishingLinks", []), # camelCase validated
            "phoneNumbers": intel.get("phoneNumbers", []),
            "suspiciousKeywords": intel.get("suspiciousKeywords", [])
        },
        "agentNotes": intel.get("agentNotes", "Scammer engaged.")
    }
    
    background_tasks.add_task(send_guvi_callback, callback_payload)

    return ScamResponse(
        status="success",
        reply=agent_reply
    )

if __name__ == "__main__":
    import uvicorn
    import os
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
