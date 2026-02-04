from pydantic import BaseModel, Field
from typing import List, Optional, Literal

class Message(BaseModel):
    sender: Literal["scammer", "user"]  # scammer or user
    text: str  # Message content
    timestamp: int  # Epoch time format in ms

class Metadata(BaseModel):
    channel: Optional[str] = None  # SMS / WhatsApp / Email / Chat
    language: Optional[str] = None  # Language used
    locale: Optional[str] = None  # Country or region

class IncomingRequest(BaseModel):
    sessionId: str  # Unique session identifier
    message: Message  # The latest incoming message (Required)
    conversationHistory: List[Message] = []  # Previous messages (Empty for first message, Required for follow-up)
    metadata: Optional[Metadata] = None  # Channel, language, locale info (Optional but Recommended)

class AgentResponse(BaseModel):
    status: str  # Always "success" for valid responses
    reply: str  # AI agent's human-like response

class ExtractedIntelligence(BaseModel):
    bankAccounts: List[str] = Field(default_factory=list)
    upiIds: List[str] = Field(default_factory=list)
    phishingLinks: List[str] = Field(default_factory=list)
    phoneNumbers: List[str] = Field(default_factory=list)
    suspiciousKeywords: List[str] = Field(default_factory=list)

class FinalResultPayload(BaseModel):
    sessionId: str
    scamDetected: bool
    totalMessagesExchanged: int
    extractedIntelligence: ExtractedIntelligence
    agentNotes: str
