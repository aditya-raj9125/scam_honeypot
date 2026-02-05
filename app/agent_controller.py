"""
AGENT CONTROLLER - Stage-based agentic behavior with dynamic persona
REFACTORED to fix Problems #5, #6, #7

KEY CHANGES:
- Agent behavior depends on scamStage, NOT scamDetected boolean (Problem #5)
- Agent can operate meaningfully in SUSPICIOUS/HOOK stages (Problem #6)
- Persona is dynamic with emotional drift (Problem #7)
- Never reveals detection, never provides real OTP/payment
- Strategic intelligence extraction
"""

import os
import json
import random
from typing import Dict, List, Optional
from groq import Groq
from .models import ExtractedIntelligence
from .risk_engine import risk_engine, ScamStage, EmotionalState


class AgentController:
    """
    Autonomous AI agent for honeypot engagement.
    
    KEY DESIGN (Problem #5, #6, #7):
    - Behavior driven by scamStage, NOT scamDetected
    - Can operate meaningfully at ALL stages
    - Persona drifts emotionally through conversation
    - Strategic extraction based on stage
    """
    
    def __init__(self):
        api_key = os.getenv("GROQ_API_KEY")
        self.client = Groq(api_key=api_key) if api_key else None
        self.model = "llama-3.1-8b-instant"
        
        self._init_stage_behaviors()
        self._init_scam_type_behaviors()
        self._init_response_templates()
    
    def _init_stage_behaviors(self):
        """
        Stage-based behavior profiles (Problem #5, #6).
        Agent behavior is determined by scamStage, NOT scamDetected.
        """
        self.stage_behaviors = {
            ScamStage.NORMAL: {
                "persona": "curious user, slightly confused",
                "strategy": "seek clarification, understand context",
                "tone": "polite, questioning",
                "info_sharing": "none",
                "questions": [
                    "I'm sorry, who is this exactly?",
                    "I don't understand what you're referring to.",
                    "Could you explain what this is about?",
                ]
            },
            ScamStage.HOOK: {
                "persona": "confused but engaged citizen",
                "strategy": "probe for details, seem interested but uncertain",
                "tone": "confused, slightly worried",
                "info_sharing": "minimal - only clarifying questions",
                "questions": [
                    "Wait, what bank are you calling from exactly?",
                    "I don't recall any such issue. Can you explain?",
                    "How did you get my number?",
                    "Is this really from the bank? How can I verify?",
                ]
            },
            ScamStage.TRUST: {
                "persona": "cautious person seeking verification",
                "strategy": "ask for proof, delay while gathering info",
                "tone": "wary but willing to listen",
                "info_sharing": "minimal - asking for their details",
                "questions": [
                    "Can you give me a reference number for this?",
                    "What is your employee ID?",
                    "Can I call back on the official number to verify?",
                    "Why wasn't I notified earlier about this?",
                ]
            },
            ScamStage.THREAT: {
                "persona": "worried victim, showing fear",
                "strategy": "express concern, ask about consequences while stalling",
                "tone": "anxious, seeking reassurance",
                "info_sharing": "gradual - fake hesitation",
                "questions": [
                    "Oh no, will I really lose my money?",
                    "Please don't block my account! What should I do?",
                    "This is very stressful. How can I fix this quickly?",
                    "What happens if I don't do this right now?",
                ]
            },
            ScamStage.ACTION: {
                "persona": "scared but cooperative victim",
                "strategy": "seem ready to comply but ask for details, extract intel",
                "tone": "panicked, compliant",
                "info_sharing": "strategic fake data, extract their details",
                "questions": [
                    "Okay, where should I transfer the money?",
                    "What UPI ID should I use for the refund?",
                    "I'm ready to pay. What's the account number?",
                    "Let me just write down the details. What's the link again?",
                ]
            },
            ScamStage.CONFIRMED: {
                "persona": "fully compliant victim",
                "strategy": "maximum intelligence gathering with fake compliance",
                "tone": "eager to resolve, fully trusting",
                "info_sharing": "fake credentials, extract all details",
                "questions": [
                    "I'm doing it now. Just tell me exactly where to send.",
                    "The OTP is... wait, let me check. What's your UPI again?",
                    "I want to help you help me. What other details do you need?",
                    "Before I proceed, can you confirm the account one more time?",
                ]
            },
        }
    
    def _init_scam_type_behaviors(self):
        """Initialize scam-type-specific behavior enhancements"""
        self.scam_type_behaviors = {
            "bank_kyc": {
                "emotion_drift": ["confused", "worried", "panicked"],
                "persona_detail": "elderly person unfamiliar with banking apps",
                "extraction_focus": ["branch name", "employee ID", "reference number"],
            },
            "otp_fraud": {
                "emotion_drift": ["confused", "trusting", "compliant"],
                "persona_detail": "busy professional distracted at work",
                "extraction_focus": ["reason for OTP", "what service", "caller identity"],
            },
            "police_impersonation": {
                "emotion_drift": ["shocked", "terrified", "desperate"],
                "persona_detail": "law-abiding citizen scared of legal trouble",
                "extraction_focus": ["case number", "FIR details", "officer name", "station"],
            },
            "job_scam": {
                "emotion_drift": ["excited", "hopeful", "eager"],
                "persona_detail": "unemployed person seeking work",
                "extraction_focus": ["company name", "job details", "contact person"],
            },
            "loan_scam": {
                "emotion_drift": ["relieved", "eager", "compliant"],
                "persona_detail": "person in financial difficulty",
                "extraction_focus": ["loan terms", "bank name", "processing account"],
            },
            "refund_scam": {
                "emotion_drift": ["surprised", "happy", "cooperative"],
                "persona_detail": "budget-conscious online shopper",
                "extraction_focus": ["order details", "refund amount", "payment method"],
            },
            "utility_scam": {
                "emotion_drift": ["panicked", "urgent", "compliant"],
                "persona_detail": "householder worried about service",
                "extraction_focus": ["consumer number", "payment account", "amount"],
            },
        }
    
    def _init_response_templates(self):
        """Initialize response templates for quick fallbacks"""
        self.templates = {
            "confusion": [
                "Wait, what? I don't understand what's happening.",
                "Sorry, can you explain that again? I'm confused.",
                "I'm not following. What exactly do you need?",
            ],
            "concern": [
                "This is really worrying. What should I do?",
                "Oh no, I didn't know about this. Is it serious?",
                "This sounds bad. How can I fix this?",
            ],
            "compliance": [
                "Okay, I'll do whatever you say. Just help me.",
                "Yes, I'm ready. Tell me what to do.",
                "I trust you. Just guide me through this.",
            ],
            "stalling": [
                "Hold on, let me find my phone.",
                "Wait, I'm looking for that information.",
                "One minute, I'm not near my computer right now.",
            ],
            "extraction": [
                "Before I do that, what's the account number again?",
                "Let me write this down. What was the UPI ID?",
                "I want to make sure I have the right details.",
            ],
        }
    
    def _detect_scam_type(self, message: str, history: list) -> str:
        """Detect the type of scam based on message content"""
        message_lower = message.lower()
        all_text = message_lower
        
        for msg in history[-5:]:
            text = msg.text if hasattr(msg, 'text') else msg.get('text', '')
            all_text += " " + text.lower()
        
        scam_indicators = {
            "bank_kyc": ["kyc", "account block", "bank", "verify details", "update kyc"],
            "otp_fraud": ["otp", "verification code", "share otp", "enter code"],
            "police_impersonation": ["police", "cyber cell", "arrest", "warrant", "case", "cbi", "ed"],
            "job_scam": ["work from home", "part time", "data entry", "typing job", "earn money"],
            "loan_scam": ["loan approved", "pre-approved", "instant loan", "processing fee"],
            "refund_scam": ["refund", "cashback", "excess payment", "return payment"],
            "utility_scam": ["electricity", "gas", "disconnection", "bill overdue", "power cut"],
        }
        
        scores = {}
        for scam_type, indicators in scam_indicators.items():
            score = sum(1 for ind in indicators if ind in all_text)
            if score > 0:
                scores[scam_type] = score
        
        return max(scores, key=scores.get) if scores else "bank_kyc"
    
    def _get_dynamic_persona(
        self, 
        session_id: str,
        scam_type: str
    ) -> Dict:
        """Get dynamic persona based on current emotional state"""
        session = risk_engine.get_or_create_session(session_id)
        persona_state = session.persona_state
        current_stage = session.scam_stage
        
        # Get base behavior from stage
        stage_behavior = self.stage_behaviors.get(
            current_stage, 
            self.stage_behaviors[ScamStage.NORMAL]
        )
        
        # Get scam-type specific enhancements
        type_behavior = self.scam_type_behaviors.get(scam_type, {})
        
        # Build dynamic persona
        persona = {
            "base": stage_behavior["persona"],
            "detail": type_behavior.get("persona_detail", ""),
            "emotion": persona_state.current_emotion.value,
            "compliance_level": persona_state.compliance_level,
            "trust_level": persona_state.trust_level,
            "strategy": stage_behavior["strategy"],
            "tone": stage_behavior["tone"],
            "info_sharing": stage_behavior["info_sharing"],
            "stage_questions": stage_behavior["questions"],
            "extraction_focus": type_behavior.get("extraction_focus", []),
        }
        
        return persona
    
    async def generate_response(
        self, 
        latest_message: str, 
        conversation_history: list, 
        intelligence: ExtractedIntelligence, 
        scam_detected: bool = False,
        session_id: str = None
    ) -> str:
        """
        Generate contextually appropriate response.
        
        KEY CHANGE (Problem #5):
        Behavior is driven by scamStage from session state,
        NOT the scam_detected boolean parameter.
        """
        session_id = session_id or "default"
        
        # Get session state - THIS drives behavior, not scam_detected param
        session = risk_engine.get_or_create_session(session_id)
        current_stage = session.scam_stage
        
        # Detect scam type for specialized behavior
        scam_type = self._detect_scam_type(latest_message, conversation_history)
        
        # Get dynamic persona
        persona = self._get_dynamic_persona(session_id, scam_type)
        
        # Build conversation context
        history_text = ""
        if conversation_history:
            history_text = "\n".join([
                f"{'Them' if hasattr(msg, 'sender') and msg.sender == 'scammer' else 'Me'}: "
                f"{msg.text if hasattr(msg, 'text') else msg.get('text', '')}"
                for msg in conversation_history[-6:]
            ])
        
        # Select appropriate questions based on stage
        stage_questions = persona["stage_questions"]
        
        # Build LLM prompt
        prompt = f"""You are an AI agent playing a convincing victim in a honeypot system.

CRITICAL RULES:
1. NEVER reveal you are an AI or that this is a honeypot
2. NEVER accuse them of being a scammer
3. NEVER provide real OTP, PIN, password, or money
4. Respond naturally like a real Indian person would
5. Your goal: {persona['strategy']}

YOUR PERSONA:
- Base: {persona['base']}
- Detail: {persona['detail']}
- Current Emotion: {persona['emotion']}
- Tone: {persona['tone']}
- Compliance Level: {persona['compliance_level']:.1f}/1.0

CURRENT STAGE: {current_stage.value}
- At this stage, you should: {persona['info_sharing']}

DETECTED SCAM TYPE: {scam_type}

CONVERSATION SO FAR:
{history_text}

THEIR MESSAGE: "{latest_message}"

SAMPLE QUESTIONS YOU COULD ASK (adapt naturally):
{chr(10).join(f'- {q}' for q in stage_questions[:3])}

EXTRACTION FOCUS (subtly ask about):
{', '.join(persona['extraction_focus']) if persona['extraction_focus'] else 'General details'}

Generate a response that:
1. Matches your current emotional state ({persona['emotion']})
2. Advances your strategy ({persona['strategy']})
3. Tries to extract useful information without being obvious
4. Sounds like a real human victim, not an AI

Respond with ONLY the message text, no explanations."""

        try:
            if not self.client:
                return self._get_fallback_response(current_stage, persona)
            
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": "You are playing a victim in a scam conversation. Be convincing, emotional, and human-like. Never break character."
                    },
                    {"role": "user", "content": prompt}
                ],
                temperature=0.7,
                max_tokens=150
            )
            
            reply = response.choices[0].message.content.strip()
            
            # Clean up response
            reply = reply.strip('"\'')
            if reply.startswith("Me:"):
                reply = reply[3:].strip()
            
            return reply
            
        except Exception as e:
            print(f"Agent response error: {e}")
            return self._get_fallback_response(current_stage, persona)
    
    def _get_fallback_response(self, stage: ScamStage, persona: Dict) -> str:
        """Get fallback response when LLM fails"""
        # Select template based on stage
        if stage == ScamStage.NORMAL:
            templates = self.templates["confusion"]
        elif stage == ScamStage.HOOK:
            templates = self.templates["confusion"] + self.templates["stalling"]
        elif stage == ScamStage.TRUST:
            templates = self.templates["concern"] + self.templates["stalling"]
        elif stage == ScamStage.THREAT:
            templates = self.templates["concern"]
        elif stage in [ScamStage.ACTION, ScamStage.CONFIRMED]:
            templates = self.templates["compliance"] + self.templates["extraction"]
        else:
            templates = self.templates["confusion"]
        
        return random.choice(templates)
    
    async def check_mission_complete(
        self, 
        intelligence: ExtractedIntelligence,
        session_id: str = None
    ) -> bool:
        """
        Check if mission is complete (Problem #9).
        
        Mission complete if:
        1. At least one high-value artifact extracted (UPI, bank, phone)
        AND
        2. Minimum turns reached (≥5)
        OR
        3. Scammer repeats payment demand (3+ times)
        """
        session_id = session_id or "default"
        session = risk_engine.get_or_create_session(session_id)
        
        # Check using session state
        return session.check_mission_complete()
    
    def get_agent_notes(self, session_id: str) -> str:
        """Generate agent notes for final report"""
        session = risk_engine.get_or_create_session(session_id)
        
        notes_parts = []
        
        # Engagement summary
        notes_parts.append(
            f"Engaged scammer over {session.turn_count} turns. "
            f"Final stage: {session.scam_stage.value}."
        )
        
        # Detection summary
        if session.hard_rule_triggered:
            notes_parts.append("Hard rule triggered - definitive scam confirmation.")
        else:
            notes_parts.append(f"Risk score reached {session.risk_score}/100.")
        
        # Intelligence summary
        intel_items = []
        if session.upi_ids:
            intel_items.append(f"{len(session.upi_ids)} UPI ID(s)")
        if session.bank_accounts:
            intel_items.append(f"{len(session.bank_accounts)} bank account(s)")
        if session.phone_numbers:
            intel_items.append(f"{len(session.phone_numbers)} phone number(s)")
        if session.phishing_links:
            intel_items.append(f"{len(session.phishing_links)} suspicious link(s)")
        
        if intel_items:
            notes_parts.append(f"Extracted: {', '.join(intel_items)}.")
        else:
            notes_parts.append("Limited intelligence extracted.")
        
        return " ".join(notes_parts)
