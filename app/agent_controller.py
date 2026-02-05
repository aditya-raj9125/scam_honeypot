"""
AGENT CONTROLLER - Natural Human-like Honeypot Agent

PHILOSOPHY:
Agent behaves like an ORDINARY, CONFUSED, NON-TECHNICAL Indian user.
Intelligence extraction is PASSIVE - handled by the extractor, NOT the agent.
Agent simply continues a natural conversation; scammer reveals info voluntarily.

KEY RULES:
1. Agent NEVER provides sensitive data (OTP, PIN, bank details)
2. Agent NEVER sounds like an investigator or interrogator
3. Agent asks SIMPLE, NATURAL clarification questions
4. Agent uses ONE consistent language per session (no switching)
5. Agent exits gracefully when conversation stalls

PERSONA (SINGLE, STABLE):
"An ordinary non-technical Indian user who is confused but polite"
- Not smart, not authoritative, not aggressive
- Slightly worried, cooperative, easily confused
- Asks incidental questions, NOT probing ones
"""

import os
import re
import random
import logging
from typing import Dict, List, Optional, Tuple

from groq import Groq
from .models import ExtractedIntelligence
from .risk_engine import risk_engine, ScamStage, AgentMemory

logger = logging.getLogger(__name__)


# ==============================================================================
# SAFETY VALIDATOR
# ==============================================================================

class SafetyValidator:
    """Validates agent output and blocks unsafe content."""
    
    FORBIDDEN_PATTERNS = [
        re.compile(r'\b(?:otp|o\.t\.p)\s*(?:is|:)?\s*\d{4,8}\b', re.I),
        re.compile(r'\b(?:pin|mpin|upi\s*pin)\s*(?:is|:)?\s*\d{4,6}\b', re.I),
        re.compile(r'\b(?:account|a/c)\s*(?:number|no\.?)?\s*(?:is|:)?\s*\d{9,18}\b', re.I),
        re.compile(r'\b(?:upi|vpa)\s*(?:id|:)?\s*\S+@\S+\b', re.I),
    ]
    
    AUTHORITY_PATTERNS = [
        re.compile(r'\bi\s+am\s+(?:a\s+)?(?:police|inspector|officer)\b', re.I),
        re.compile(r'\bi\s+am\s+(?:from\s+)?(?:cid|cbi|bank)\b', re.I),
    ]
    
    @classmethod
    def validate_output(cls, text: str) -> Tuple[bool, List[str], str]:
        """Check if output is safe. Returns (is_safe, violations, text)."""
        violations = []
        for pattern in cls.FORBIDDEN_PATTERNS:
            if pattern.search(text):
                violations.append("SENSITIVE_DATA")
        for pattern in cls.AUTHORITY_PATTERNS:
            if pattern.search(text):
                violations.append("AUTHORITY_IMPERSONATION")
        return len(violations) == 0, violations, text


# ==============================================================================
# AGENT CONTROLLER
# ==============================================================================

class AgentController:
    """
    Natural human-like honeypot agent.
    
    - Single persona: confused, polite, non-technical user
    - Language locked per session
    - 1-2 sentence replies maximum
    - NO interrogation, NO forced extraction
    """
    
    def __init__(self):
        api_key = os.getenv("GROQ_API_KEY")
        self.client = Groq(api_key=api_key) if api_key else None
        self.model = "llama-3.1-8b-instant"
        self._init_templates()
    
    def _init_templates(self):
        """Initialize all response templates."""
        
        # Language-specific natural responses
        self.templates = {
            "hindi": {
                "confusion": [
                    "Samajh nahi aaya.",
                    "Kya matlab?",
                    "Arre, mujhe confuse ho raha hai.",
                    "Thoda slow bolo na.",
                    "Acha acha, phir?",
                ],
                "stalling": [
                    "Ek second ruko.",
                    "Haan haan, suno.",
                    "Achha theek hai.",
                    "Hmm, phir?",
                ],
                "followup": [
                    "Iske baad kya karna hai?",
                    "Phir kya hoga?",
                    "Aur kuch karna padega?",
                    "Kitna time lagega?",
                    "Aap batayenge na kya karna hai?",
                    "Koi problem toh nahi hogi na?",
                    "Safe hai na yeh?",
                    "Sahi se ho jayega na?",
                    "Achha, phir?",
                    "Theek hai, aage batao.",
                ],
                "termination": [
                    "Theek hai, thodi der baad karta hoon.",
                    "Abhi phone charge pe lagata hoon.",
                    "Baad mein baat karte hain.",
                    "Achha theek hai, sochta hoon.",
                ],
            },
            "english": {
                "confusion": [
                    "Sorry, didn't understand.",
                    "What do you mean?",
                    "I'm confused.",
                    "Can you say that again?",
                    "Okay okay, then?",
                ],
                "stalling": [
                    "One second.",
                    "Yes yes, go on.",
                    "Okay, fine.",
                    "Hmm, then?",
                ],
                "followup": [
                    "What do I do after that?",
                    "Then what happens?",
                    "Anything else I need to do?",
                    "How long will it take?",
                    "You'll tell me what to do right?",
                    "There won't be any problem right?",
                    "This is safe right?",
                    "Okay, then?",
                    "Alright, go on.",
                ],
                "termination": [
                    "Okay, I'll do it later.",
                    "Let me charge my phone first.",
                    "Talk later, bye.",
                    "Okay let me think about it.",
                ],
            }
        }
        
        # Semantic intent mapping for anti-loop
        self.SEMANTIC_INTENT_MAP = {
            "identity_verification": ["naam", "name", "who", "kaun", "employee", "officer"],
            "payment_method": ["upi", "transfer", "payment", "paise", "pay", "money", "gpay", "phonepe"],
            "next_action_step": ["step", "next", "kaise", "process", "phir", "then", "how"],
            "contact_method": ["call", "phone", "number", "whatsapp", "message"],
            "delay_excuse": ["wait", "ruko", "busy", "network", "battery", "later"],
            "account_details": ["account", "bank", "ifsc", "branch"],
            "app_or_link": ["app", "link", "download", "install", "qr"],
        }
    
    def _detect_language(self, text: str) -> str:
        """Detect Hindi vs English from text."""
        text_lower = text.lower()
        hindi_words = [
            'kya', 'hai', 'hain', 'mujhe', 'aap', 'hoon', 'nahi', 'bhai', 
            'beta', 'ji', 'accha', 'theek', 'batao', 'bhejo', 'abhi'
        ]
        if re.search(r'[\u0900-\u097F]', text):
            return "hindi"
        if sum(1 for w in hindi_words if w in text_lower) >= 2:
            return "hindi"
        return "english"
    
    def _extract_intent(self, response: str) -> str:
        """Map response to semantic intent for anti-loop."""
        response_lower = response.lower()
        for intent, keywords in self.SEMANTIC_INTENT_MAP.items():
            if any(kw in response_lower for kw in keywords):
                return intent
        return "generic"
    
    def _get_natural_question(self, session, language: str) -> Tuple[str, str]:
        """Get a natural follow-up question that hasn't been asked."""
        templates = self.templates.get(language, self.templates["hindi"])
        questions = templates["followup"]
        
        for q in questions:
            intent = self._extract_intent(q)
            if not session.is_question_blocked(q, intent):
                return q, intent
        
        # All exhausted - use simple acknowledgment
        stalling = templates["stalling"]
        for s in stalling:
            if s.lower() not in [sq.lower() for sq in session.recent_questions]:
                return s, "acknowledgment"
        
        return "Phir?" if language == "hindi" else "Then?", "acknowledgment"
    
    def _get_fallback(self, stage: ScamStage, language: str) -> str:
        """Get fallback response."""
        templates = self.templates.get(language, self.templates["hindi"])
        if stage in [ScamStage.NORMAL, ScamStage.HOOK]:
            return random.choice(templates["confusion"])
        elif stage in [ScamStage.TRUST, ScamStage.THREAT]:
            return random.choice(templates["confusion"] + templates["followup"])
        else:
            return random.choice(templates["followup"] + templates["stalling"])
    
    async def generate_response(
        self, 
        latest_message: str, 
        conversation_history: list, 
        intelligence: ExtractedIntelligence, 
        scam_detected: bool = False,
        session_id: str = None
    ) -> str:
        """
        Generate a natural, human-like response.
        
        PHILOSOPHY:
        - Agent is a confused ordinary user, NOT an investigator
        - Extraction is passive (extractor handles scammer messages)
        - Keep responses SHORT (1-2 sentences max)
        - Never repeat questions
        """
        session_id = session_id or "default"
        session = risk_engine.get_or_create_session(session_id)
        current_stage = session.scam_stage
        
        # Language lock (should already be set in main.py)
        if session.locked_language is None:
            session.lock_language(self._detect_language(latest_message))
        language = session.get_locked_language() or "hindi"
        
        # Record scammer message
        session.add_turn("scammer", latest_message, "incoming")
        
        # Build agent memory
        agent_memory: AgentMemory = session.build_agent_memory()
        
        logger.info(f"🧠 Turn={agent_memory.turn_count}, Stage={current_stage.value}, Lang={language}")
        
        # ==================================================================
        # TERMINATION CHECK: Exit gracefully if stalled
        # ==================================================================
        if agent_memory.should_terminate:
            templates = self.templates.get(language, self.templates["hindi"])
            response = random.choice(templates["termination"])
            session.add_turn("agent", response, "termination")
            logger.info(f"🛑 Graceful exit: {response}")
            return response
        
        # ==================================================================
        # POST-DETECTION: Use natural questions (not interrogation)
        # ==================================================================
        if scam_detected or current_stage in [ScamStage.THREAT, ScamStage.ACTION, ScamStage.CONFIRMED]:
            question, intent = self._get_natural_question(session, language)
            session.add_question(question, intent)
            session.check_stall()
            session.add_turn("agent", question, intent)
            logger.info(f"💬 Natural response: {question}")
            return question
        
        # ==================================================================
        # PRE-DETECTION: Use LLM for natural confused response
        # ==================================================================
        if not self.client:
            fallback = self._get_fallback(current_stage, language)
            session.add_turn("agent", fallback, "fallback")
            return fallback
        
        lang_instruction = "Respond in Hindi (Romanized)" if language == "hindi" else "Respond in English"
        
        prompt = f"""You are a CONFUSED, NON-TECHNICAL Indian user. {lang_instruction}.

You are NOT an investigator. You are an ordinary person who doesn't understand what's happening.

RULES:
- MAX 10 WORDS total
- 1 short sentence ONLY  
- Sound confused, not smart
- Ask simple clarification like "phir kya?" or "samjha nahi"
- NEVER ask for employee ID, branch name, account details
- NEVER sound investigative or probing
- Just be a confused person

Message: "{latest_message[:80]}"

Reply with 1 very short confused response:"""

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": f"Confused ordinary user. {lang_instruction}. MAX 10 words."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.4,
                max_tokens=25
            )
            
            reply = response.choices[0].message.content.strip().strip('"\'')
            if reply.startswith("Me:"):
                reply = reply[3:].strip()
            
            # Truncate to 1 sentence
            sentences = re.split(r'(?<=[.!?।])\s+', reply)
            reply = sentences[0] if sentences else reply
            
            # Safety check
            is_safe, _, _ = SafetyValidator.validate_output(reply)
            if not is_safe:
                reply = self._get_fallback(current_stage, language)
            
            intent = self._extract_intent(reply)
            session.add_question(reply, intent)
            session.add_turn("agent", reply, intent)
            
            logger.info(f"✅ Response: {reply}")
            return reply
            
        except Exception as e:
            logger.error(f"LLM error: {e}")
            fallback = self._get_fallback(current_stage, language)
            session.add_turn("agent", fallback, "fallback")
            return fallback
    
    async def check_mission_complete(
        self, 
        intelligence: ExtractedIntelligence,
        session_id: str = None
    ) -> bool:
        """Check if mission is complete (enough intel extracted)."""
        session_id = session_id or "default"
        session = risk_engine.get_or_create_session(session_id)
        return session.check_mission_complete()
    
    def get_agent_notes(self, session_id: str) -> str:
        """Generate agent notes for final report."""
        session = risk_engine.get_or_create_session(session_id)
        
        notes = [f"Engaged scammer over {session.turn_count} turns. Final stage: {session.scam_stage.value}."]
        
        if session.hard_rule_triggered:
            notes.append("Hard rule triggered - definitive scam confirmation.")
        else:
            notes.append(f"Risk score reached {session.risk_score}/100.")
        
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
            notes.append(f"Extracted from scammer: {', '.join(intel_items)}.")
        else:
            notes.append("Limited intelligence extracted.")
        
        return " ".join(notes)
