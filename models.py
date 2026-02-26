"""
Pydantic models for request/response validation.
Ensures clean and predictable API for mobile app integration.
"""

from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any, Union


class MessageContent(BaseModel):
    """Individual message content structure."""
    content: str = Field(..., description="Message text content")
    type: str = Field(default="text", description="Message type: text, image, etc.")
    timestamp: int = Field(..., description="Unix timestamp in milliseconds")
    sender: str = Field(default="user", description="Message sender: scammer, user, honeypot")
    
    class Config:
        extra = "allow"


class ConversationMessage(BaseModel):
    """Historical conversation message."""
    content: str
    type: str = "text"
    timestamp: int
    sender: str = "user"
    
    class Config:
        extra = "allow"


class HoneypotRequest(BaseModel):
    """Incoming request schema for honeypot engagement."""
    session_id: Optional[str] = Field(default=None, description="Unique session identifier (snake_case)")
    sessionId: Optional[str] = Field(default=None, description="Unique session identifier (camelCase)")
    message: Union[Dict[str, Any], MessageContent] = Field(..., description="Current incoming message")
    conversation_history: Optional[List[Dict[str, Any]]] = Field(
        default_factory=list,
        description="Array of previous messages (snake_case)"
    )
    conversationHistory: Optional[List[Dict[str, Any]]] = Field(
        default_factory=list,
        description="Array of previous messages (camelCase)"
    )
    metadata: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Optional metadata for future app data"
    )
    
    class Config:
        extra = "allow"
    
    def get_session_id(self) -> str:
        """Get session_id preferring snake_case, fallback to camelCase."""
        return self.session_id or self.sessionId or ""
    
    def get_conversation_history(self) -> List[Dict[str, Any]]:
        """Get conversation history preferring snake_case, fallback to camelCase."""
        return self.conversation_history or self.conversationHistory or []


class HoneypotResponse(BaseModel):
    """Standard API response schema."""
    status: str = Field(..., description="Response status: 'success' or 'error'")
    reply: str = Field(..., description="AI-generated response to engage the scammer")
    intelligence: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Extracted intelligence from scammer messages"
    )
    
    class Config:
        extra = "allow"


class IntelligenceData(BaseModel):
    """Extracted intelligence from scammer messages."""
    bank_accounts: List[str] = Field(
        default_factory=list,
        description="Extracted bank account numbers"
    )
    upi_ids: List[str] = Field(
        default_factory=list,
        description="Extracted UPI payment IDs"
    )
    phishing_links: List[str] = Field(
        default_factory=list,
        description="Extracted suspicious URLs"
    )
    phone_numbers: List[str] = Field(
        default_factory=list,
        description="Extracted phone numbers"
    )
    suspicious_keywords: List[str] = Field(
        default_factory=list,
        description="Identified pressure words or phrases"
    )
    agent_notes: str = Field(
        default="",
        description="AI-generated summary of scam intent"
    )
    
    # Aliases for camelCase compatibility
    bankAccounts: List[str] = Field(default_factory=list, alias="bankAccounts")
    upiIds: List[str] = Field(default_factory=list, alias="upiIds")
    phishingLinks: List[str] = Field(default_factory=list, alias="phishingLinks")
    phoneNumbers: List[str] = Field(default_factory=list, alias="phoneNumbers")
    suspiciousKeywords: List[str] = Field(default_factory=list, alias="suspiciousKeywords")
    agentNotes: str = Field(default="", alias="agentNotes")
    
    class Config:
        populate_by_name = True
        extra = "allow"


class CallbackPayload(BaseModel):
    """Payload sent to external webhook (GUVI)."""
    session_id: str
    scam_detected: bool
    total_messages_exchanged: int
    extracted_intelligence: IntelligenceData
    agent_notes: str = ""
    
    class Config:
        extra = "allow"


class ErrorResponse(BaseModel):
    """Standard error response schema."""
    status: str = "error"
    error: str
    message: str
