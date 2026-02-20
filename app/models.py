from pydantic import BaseModel, Field
from typing import List, Optional, Literal


class Message(BaseModel):
    sender: Literal["scammer", "user"]  # scammer or user
    text: str  # Message content
    timestamp: Optional[int] = None  # Epoch time format in ms (optional for compatibility)


class Metadata(BaseModel):
    channel: Optional[str] = None  # SMS / WhatsApp / Email / Chat
    language: Optional[str] = None  # Language used
    locale: Optional[str] = None  # Country or region


class IncomingRequest(BaseModel):
    sessionId: str  # Unique session identifier
    message: Message  # The latest incoming message (Required)
    conversationHistory: List[Message] = []  # Previous messages
    metadata: Optional[Metadata] = None  # Channel, language, locale info


class AgentResponse(BaseModel):
    status: str  # Always "success" for valid responses
    reply: str  # AI agent's human-like response


class ExtractedIntelligence(BaseModel):
    bankAccounts: List[str] = Field(default_factory=list)
    upiIds: List[str] = Field(default_factory=list)
    phishingLinks: List[str] = Field(default_factory=list)
    phoneNumbers: List[str] = Field(default_factory=list)
    emailAddresses: List[str] = Field(default_factory=list)   # NEW — required by scoring
    suspiciousKeywords: List[str] = Field(default_factory=list)
    caseIds: List[str] = Field(default_factory=list)          # case/reference IDs
    policyNumbers: List[str] = Field(default_factory=list)    # insurance/policy numbers
    orderNumbers: List[str] = Field(default_factory=list)     # order IDs


class FinalResultPayload(BaseModel):
    sessionId: str
    scamDetected: bool
    totalMessagesExchanged: int
    engagementDurationSeconds: int = 0          # Required for engagement scoring
    extractedIntelligence: ExtractedIntelligence
    agentNotes: str = ""
    scamType: Optional[str] = None              # Optional — +1 pt
    confidenceLevel: Optional[float] = None     # Optional — +1 pt
