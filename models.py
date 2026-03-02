"""
Pydantic models for request/response validation.
Ensures clean and predictable API for mobile app integration.
"""

from pydantic import BaseModel, Field, field_validator
from typing import List, Optional, Dict, Any, Union


class MessageContent(BaseModel):
    """Individual message content structure."""
    text: Optional[str] = Field(default=None, validation_alias='text', description="Message text content")
    content: Optional[str] = Field(default=None, validation_alias='content', description="Message text content")
    type: str = Field(default="text", description="Message type: text, image, etc.")
    timestamp: int = Field(..., description="Unix timestamp in milliseconds")
    sender: str = Field(default="user", description="Message sender: scammer, user, honeypot")
    sender_id: Optional[str] = Field(default=None, validation_alias='sender_id', description="Sender's phone number or ID (e.g., +91xxxxxxxxxx)")
    senderId: Optional[str] = Field(default=None, validation_alias='senderId', description="Sender's phone number or ID")
    
    @field_validator('text', 'content', mode='before')
    @classmethod
    def merge_text_content(cls, v, info):
        if v is not None:
            return v
        # If neither text nor content is provided, check the other field
        data = info.data
        if info.field_name == 'text' and 'content' in data:
            return data['content']
        if info.field_name == 'content' and 'text' in data:
            return data['text']
        return v
    
    def get_text(self) -> str:
        """Get the message text, preferring text over content."""
        return self.text or self.content or ""
    
    def get_sender_id(self) -> Optional[str]:
        """Get sender ID (phone number), preferring sender_id over senderId."""
        return self.sender_id or self.senderId
    
    class Config:
        extra = "allow"


class ConversationMessage(BaseModel):
    """Historical conversation message."""
    text: Optional[str] = Field(default=None)
    content: Optional[str] = Field(default=None)
    type: str = "text"
    timestamp: int
    sender: str = "user"
    
    class Config:
        extra = "allow"


class HoneypotRequest(BaseModel):
    """Incoming request schema for honeypot engagement."""
    session_id: Optional[str] = Field(default=None, validation_alias='session_id', description="Unique session identifier")
    sessionId: Optional[str] = Field(default=None, validation_alias='sessionId', description="Unique session identifier")
    message: Union[Dict[str, Any], MessageContent] = Field(..., description="Current incoming message")
    conversation_history: Optional[List[Dict[str, Any]]] = Field(
        default=None,
        validation_alias='conversation_history',
        description="Array of previous messages"
    )
    conversationHistory: Optional[List[Dict[str, Any]]] = Field(
        default=None,
        validation_alias='conversationHistory',
        description="Array of previous messages"
    )
    metadata: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Optional metadata for future app data"
    )
    
    @field_validator('session_id', 'sessionId', mode='before')
    @classmethod
    def merge_session_ids(cls, v, info):
        if v is not None:
            return v
        data = info.data
        if info.field_name == 'session_id' and 'sessionId' in data:
            return data['sessionId']
        if info.field_name == 'sessionId' and 'session_id' in data:
            return data['session_id']
        return v
    
    @field_validator('conversation_history', 'conversationHistory', mode='before')
    @classmethod
    def merge_conversation_history(cls, v, info):
        if v is not None:
            return v
        data = info.data
        if info.field_name == 'conversation_history' and 'conversationHistory' in data:
            return data['conversationHistory']
        if info.field_name == 'conversationHistory' and 'conversation_history' in data:
            return data['conversation_history']
        return v
    
    def get_session_id(self) -> str:
        return self.session_id or self.sessionId or ""
    
    def get_conversation_history(self) -> List[Dict[str, Any]]:
        return self.conversation_history or self.conversationHistory or []
    
    class Config:
        extra = "allow"


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
    bankAccounts: List[str] = Field(default_factory=list)
    upiIds: List[str] = Field(default_factory=list)
    phishingLinks: List[str] = Field(default_factory=list)
    phoneNumbers: List[str] = Field(default_factory=list)
    suspiciousKeywords: List[str] = Field(default_factory=list)
    agentNotes: str = ""
    # Enhanced fields with explicit defaults
    scamType: str = "Unknown"
    urgencyLevel: str = "Low"
    riskScore: int = 0
    extractedEntities: List[str] = Field(default_factory=list)
    threatSource: str = ""  # Sender's phone number/ID for blocked list
    isPhishing: bool = False  # True if any suspicious pattern detected (riskScore > 0)
    
    class Config:
        extra = "allow"


class CallbackPayload(BaseModel):
    """Payload sent to external webhook (GUVI)."""
    sessionId: str
    scamDetected: bool
    totalMessagesExchanged: int
    extractedIntelligence: IntelligenceData
    agentNotes: str = ""
    
    class Config:
        extra = "allow"


class ErrorResponse(BaseModel):
    """Standard error response schema."""
    status: str = "error"
    error: str
    message: str
