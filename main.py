from fastapi import FastAPI, HTTPException, Header, Depends
from pydantic import BaseModel, Field
from typing import List, Optional
import os
import time
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
    timestamp: str

class Metadata(BaseModel):
    channel: Optional[str] = "SMS"
    language: Optional[str] = "English"
    locale: Optional[str] = "IN"

class ScamRequest(BaseModel):
    message: Message
    conversationHistory: Optional[List[Message]] = []
    metadata: Optional[Metadata] = None

class EngagementMetrics(BaseModel):
    engagementDurationSeconds: int
    totalMessagesExchanged: int

class ExtractedIntelligence(BaseModel):
    bankAccounts: List[str] = []
    upiIds: List[str] = []
    phishingLinks: List[str] = []

class ScamResponse(BaseModel):
    status: str
    scamDetected: bool
    engagementMetrics: EngagementMetrics
    extractedIntelligence: ExtractedIntelligence
    agentNotes: str

# Security
async def verify_api_key(x_api_key: str = Header(None)):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=403, detail="Invalid API Key")
    return x_api_key

@app.post("/message", response_model=ScamResponse)
async def handle_message(request: ScamRequest, api_key: str = Depends(verify_api_key)):
    start_time = time.time()
    
    # Convert conversation history to simple dict list for the agent
    history_list = [{"sender": m.sender, "text": m.text} for m in request.conversationHistory]
    
    # 1. Detect Scam
    is_scam = agent.detect_scam(request.message.text, history_list)
    
    if not is_scam:
        return ScamResponse(
            status="success",
            scamDetected=False,
            engagementMetrics=EngagementMetrics(
                engagementDurationSeconds=0,
                totalMessagesExchanged=len(request.conversationHistory) + 1
            ),
            extractedIntelligence=ExtractedIntelligence(),
            agentNotes="No scam detected."
        )

    # 2. Extract Intelligence
    intel = agent.extract_intelligence(request.message.text, history_list)
    
    # 3. Generate Agent Response (Engagement)
    # The requirement says "return a structured JSON response", 
    # and the evaluation flow says "The Agent continues the conversation".
    # Typically this means the response should include the agent's message.
    # I'll add the agent's message to the agentNotes or a new field if allowed.
    # Looking at the requirement "Expected Output Format", there's no "reply" field.
    # However, to "engage", the system must produce a reply.
    # I will put the reply in a logical place if not specified, 
    # but I'll stick to the exact schema provided.
    # Wait, the prompt says "Returns a structured JSON response" but doesn't explicitly show where the reply goes in the example.
    # I'll include the reply in 'agentNotes' as part of the intelligence/notes.
    
    agent_reply = agent.generate_response(request.message.text, history_list, request.metadata.model_dump() if request.metadata else {})
    
    return ScamResponse(
        status="success",
        scamDetected=True,
        engagementMetrics=EngagementMetrics(
            engagementDurationSeconds=int(time.time() - start_time), # This is per-request duration in this context
            totalMessagesExchanged=len(request.conversationHistory) + 1
        ),
        extractedIntelligence=ExtractedIntelligence(
            bankAccounts=intel.get("bankAccounts", []),
            upiIds=intel.get("upiIds", []),
            phishingLinks=intel.get("phishingLinks", [])
        ),
        agentNotes=f"Agent Reply: {agent_reply}\n\nTactics: {intel.get('agentNotes', '')}"
    )

if __name__ == "__main__":
    import uvicorn
    import os
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
