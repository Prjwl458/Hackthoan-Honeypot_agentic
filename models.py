"""
Pydantic models for request/response validation.
Ensures clean and predictable API for mobile app integration.
"""

from pydantic import BaseModel, Field
from typing import List, Optional


class MessageContent(BaseModel):
    """Individual message content structure."""
    sender: str = Field(..., description="Message sender: 'scammer' or 'user'")
    text: str = Field(..., description="Message text content")
    timestamp: int = Field(..., description="Unix timestamp in milliseconds")


class ConversationMessage(BaseModel):
    """Historical conversation message."""
    sender: str
    text: str
    timestamp: int


class Metadata(BaseModel):
    """Optional metadata about the conversation channel."""
    channel: str = Field(default="SMS", description="Communication channel: SMS, WhatsApp, etc.")
    language: str = Field(default="English", description="Message language")
    locale: str = Field(default="IN", description="Country locale code")


class HoneypotRequest(BaseModel):
    """Incoming request schema for honeypot engagement."""
    sessionId: str = Field(..., description="Unique session identifier")
    message: MessageContent = Field(..., description="Current incoming message")
    conversationHistory: List[ConversationMessage] = Field(
        default_factory=list,
        description="Array of previous messages in the conversation"
    )
    metadata: Metadata = Field(
        default_factory=Metadata,
        description="Optional metadata about the channel"
    )


class HoneypotResponse(BaseModel):
    """Standard API response schema."""
    status: str = Field(..., description="Response status: 'success' or 'error'")
    reply: str = Field(..., description="AI-generated response to engage the scammer")


class IntelligenceData(BaseModel):
    """Extracted intelligence from scammer messages."""
    bankAccounts: List[str] = Field(
        default_factory=list,
        description="Extracted bank account numbers"
    )
    upiIds: List[str] = Field(
        default_factory=list,
        description="Extracted UPI payment IDs"
    )
    phishingLinks: List[str] = Field(
        default_factory=list,
        description="Extracted suspicious URLs"
    )
    phoneNumbers: List[str] = Field(
        default_factory=list,
        description="Extracted phone numbers"
    )
    suspiciousKeywords: List[str] = Field(
        default_factory=list,
        description="Identified pressure words or phrases"
    )
    agentNotes: str = Field(
        default="",
        description="AI-generated summary of scam intent"
    )


class CallbackPayload(BaseModel):
    """Payload sent to external webhook (GUVI)."""
    sessionId: str
    scamDetected: bool
    totalMessagesExchanged: int
    extractedIntelligence: IntelligenceData
    agentNotes: str = ""


class ErrorResponse(BaseModel):
    """Standard error response schema."""
    status: str = "error"
    error: str
    message: str
