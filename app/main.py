"""
MAIN API - FastAPI application with refactored stateful pipeline
REFACTORED to implement the new architecture

PIPELINE ORDER:
Message → Light Signal Extraction → Risk Score Update (cumulative) →
Scam Stage Update → LLM Reasoning Judge → Decision Engine →
Agent Controller → Heavy Intelligence Extraction → Mission Completion Check

API REQUEST/RESPONSE FORMAT IS UNCHANGED
"""

from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from typing import Dict
from .models import IncomingRequest, AgentResponse, ExtractedIntelligence, FinalResultPayload
from .auth import get_api_key
from .scam_detector import ScamDetector
from .agent_controller import AgentController
from .intelligence_extractor import intelligence_extractor
from .callback_client import send_final_result
from .risk_engine import risk_engine, ScamStage

app = FastAPI(title="Scam Honeypot API", version="2.0.0")

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize components
scam_detector = ScamDetector()
agent_controller = AgentController()


@app.post("/", response_model=AgentResponse)
async def root_handler(request: IncomingRequest, api_key: str = Depends(get_api_key)):
    """Root endpoint that forwards to chat handler for tester compatibility"""
    return await chat_handler(request, api_key)


@app.post("/chat", response_model=AgentResponse)
async def chat_handler(request: IncomingRequest, api_key: str = Depends(get_api_key)):
    """
    Main chat endpoint - implements the stateful detection pipeline.
    
    PIPELINE:
    1. Light Signal Extraction
    2. Risk Score Update (cumulative)
    3. Scam Stage Update
    4. LLM Reasoning Judge (conditional)
    5. Decision Engine
    6. Agent Controller
    7. Heavy Intelligence Extraction (at THREAT+ stages)
    8. Mission Completion Check
    """
    try:
        session_id = request.sessionId
        
        # Validate required fields
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
        
        # Get or create session state
        session = risk_engine.get_or_create_session(session_id)
        
        # Track message count
        current_msg_count = len(request.conversationHistory) + 2
        
        # =====================================================================
        # STEP 1-5: Detection Pipeline (runs on every turn)
        # Handles: Light extraction, Risk scoring, Stage update, LLM judge
        # =====================================================================
        detection_result = await scam_detector.detect(
            request.message.text, 
            request.conversationHistory,
            session_id
        )
        
        # Log detection result
        print(f"[{session_id}] Turn {session.turn_count}: "
              f"Risk={detection_result['risk_score']}, "
              f"Stage={detection_result['scam_stage']}, "
              f"Detected={detection_result['scamDetected']}")
        
        # =====================================================================
        # STEP 6: Agent Controller - Generate response based on scam stage
        # Agent behavior is driven by scamStage, NOT scamDetected boolean
        # =====================================================================
        
        # Build intelligence object for agent
        intel = ExtractedIntelligence(
            upiIds=session.upi_ids.copy(),
            bankAccounts=session.bank_accounts.copy(),
            phoneNumbers=session.phone_numbers.copy(),
            phishingLinks=session.phishing_links.copy(),
            suspiciousKeywords=session.suspicious_keywords.copy(),
        )
        
        reply_text = await agent_controller.generate_response(
            request.message.text,
            request.conversationHistory,
            intel,
            detection_result["scamDetected"],
            session_id
        )
        
        # =====================================================================
        # STEP 7: Heavy Intelligence Extraction (at THREAT+ stages)
        # Light extraction already happened in detection pipeline
        # =====================================================================
        current_stage = ScamStage(detection_result["scam_stage"])
        
        intel = intelligence_extractor.extract(
            request.message.text,
            intel,
            session_id,
            scam_stage=current_stage
        )
        
        # Sync extracted intel back to session
        session.upi_ids = intel.upiIds.copy()
        session.bank_accounts = intel.bankAccounts.copy()
        session.phone_numbers = intel.phoneNumbers.copy()
        session.phishing_links = intel.phishingLinks.copy()
        session.suspicious_keywords = intel.suspiciousKeywords.copy()
        
        # =====================================================================
        # STEP 8: Mission Completion Check
        # Only send callback when mission is truly complete
        # =====================================================================
        if detection_result["scamDetected"] and not session.callback_sent:
            mission_complete = await agent_controller.check_mission_complete(
                intel, session_id
            )
            
            if mission_complete:
                session.callback_sent = True
                
                # Generate agent notes
                agent_notes = agent_controller.get_agent_notes(session_id)
                
                # Build payload
                payload = FinalResultPayload(
                    sessionId=session_id,
                    scamDetected=True,
                    totalMessagesExchanged=current_msg_count,
                    extractedIntelligence=intel,
                    agentNotes=agent_notes
                )
                
                # Send callback
                callback_success = await send_final_result(payload)
                if callback_success:
                    print(f"✅ Mission Complete for session {session_id}")
                    print(f"   Risk Score: {detection_result['risk_score']}")
                    print(f"   Stage: {detection_result['scam_stage']}")
                    print(f"   Intel: UPI={len(intel.upiIds)}, "
                          f"Bank={len(intel.bankAccounts)}, "
                          f"Phone={len(intel.phoneNumbers)}")
                else:
                    print(f"❌ Callback failed for session {session_id}")
                    session.callback_sent = False  # Allow retry
        
        # Return response (format unchanged)
        return AgentResponse(
            status="success",
            reply=reply_text
        )
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error in chat_handler: {e}")
        import traceback
        traceback.print_exc()
        return AgentResponse(
            status="error",
            reply="I'm having trouble understanding. Could you repeat that?"
        )


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "version": "2.0.0"}


@app.get("/session/{session_id}")
async def get_session_info(session_id: str, api_key: str = Depends(get_api_key)):
    """Debug endpoint to view session state"""
    session = risk_engine.sessions.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    return session.to_dict()
