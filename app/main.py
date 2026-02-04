from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from typing import Dict, Any
from .models import IncomingRequest, AgentResponse, Message, ExtractedIntelligence, FinalResultPayload
from .auth import get_api_key
from .scam_detector import ScamDetector
from .agent_controller import AgentController
from .intelligence_extractor import IntelligenceExtractor
from .callback_client import send_final_result
import time
import json

app = FastAPI(title="Scam Honeypot API", version="1.0.0")

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins for testing
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],)

# In-memory session state (for "Free" architecture)
# Map sessionId -> { "intelligence": ExtractedIntelligence(), "scamDetected": bool, "history": [] }
sessions: Dict[str, Dict] = {}

scam_detector = ScamDetector()
agent_controller = AgentController()
intelligence_extractor = IntelligenceExtractor()

# Root endpoint for API tester compatibility
@app.post("/", response_model=AgentResponse)
async def root_handler(request: IncomingRequest, api_key: str = Depends(get_api_key)):
    """Root endpoint that forwards to chat handler for tester compatibility"""
    return await chat_handler(request, api_key)

@app.post("/chat", response_model=AgentResponse)
async def chat_handler(request: IncomingRequest, api_key: str = Depends(get_api_key)):
    try:
        # Get session ID from request (required field)
        session_id = request.sessionId
        
        # Validate required fields - must match exact API specification
        if not request.message or not request.message.text:
            raise HTTPException(
                status_code=400, 
                detail="Invalid request: 'message' field with 'text' is required"
            )
        
        if not session_id:
            raise HTTPException(
                status_code=400,
                detail="Invalid request: 'sessionId' field is required"
            )
        
        # Init session if new
        if session_id not in sessions:
            sessions[session_id] = {
                "intelligence": ExtractedIntelligence(),
                "scamDetected": False,
                "message_count": 0,
                "mission_complete": False
            }
        
        session = sessions[session_id]
        
        # Calculate total messages exchanged properly
        # conversation_history + current_message + our_upcoming_reply
        current_msg_count = len(request.conversationHistory) + 2  # +1 for incoming, +1 for our reply
        session["message_count"] = current_msg_count
        
        # 1. Extract intelligence from ALL messages (history + current) if first time
        if len(request.conversationHistory) == 0:  # First message
            session["intelligence"] = intelligence_extractor.extract(
                request.message.text, 
                session["intelligence"]
            )
        else:
            # Extract from current message only (history already processed)
            session["intelligence"] = intelligence_extractor.extract(
                request.message.text, 
                session["intelligence"]
            )
        
        # 2. Check Scam Detection (if not already detected)
        if not session["scamDetected"]:
            detection_result = await scam_detector.detect(
                request.message.text, 
                request.conversationHistory,
                session_id  # Pass session_id for state tracking
            )
            if detection_result.get("scamDetected"):
                session["scamDetected"] = True
                print(f"SCAM DETECTED for session {session_id} with confidence {detection_result.get('confidence', 0)}")
        
        # 3. Agent always generates response to maintain human persona
        # The agent should engage naturally regardless of detection status
        # to avoid revealing the honeypot nature
        reply_text = await agent_controller.generate_response(
            request.message.text,
            request.conversationHistory,
            session["intelligence"],
            session["scamDetected"],
            session_id  # Pass session_id for state-aware responses
        )
        
        # 4. Check if mission complete (Extraction finished + Scam Detected)
        # Only report if we actually think it's a scam and haven't reported yet
        if session["scamDetected"] and not session["mission_complete"]:
            mission_complete = await agent_controller.check_mission_complete(session["intelligence"])
            
            if mission_complete:
                session["mission_complete"] = True
                # Send Callback as per specification
                agent_notes = f"Scammer engaged over {session['message_count']} messages. Intelligence extracted successfully."
                payload = FinalResultPayload(
                    sessionId=session_id,
                    scamDetected=True,  # Always True when sending callback
                    totalMessagesExchanged=session["message_count"],
                    extractedIntelligence=session["intelligence"],
                    agentNotes=agent_notes
                )
                # Await callback to ensure it's sent (mandatory for evaluation)
                callback_success = await send_final_result(payload)
                if callback_success:
                    print(f"✅ Mission Complete & Final Result Reported for session {session_id}")
                else:
                    print(f"❌ Failed to send mandatory callback for session {session_id}")
        
        # Return response in exact format specified
        return AgentResponse(
            status="success",  # Always "success" as per specification
            reply=reply_text
        )
        
    except Exception as e:
        print(f"Error in chat_handler: {e}")
        import traceback
        traceback.print_exc()
        return AgentResponse(
            status="error",
            reply="I'm having trouble understanding your message. Could you rephrase it?"
        )
