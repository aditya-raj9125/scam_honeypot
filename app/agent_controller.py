"""
AGENT CONTROLLER - Smart LLM-driven Honeypot Agent
REWRITTEN for maximum engagement and intelligence extraction

KEY CHANGES:
- Full conversation context in LLM prompt
- Stage-aware persona behavior  
- Longer, more natural responses (up to 25 words)
- Active intelligence elicitation through confused victim role
- Uses llama-3.3-70b-versatile for quality
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
        violations = []
        for pattern in cls.FORBIDDEN_PATTERNS:
            if pattern.search(text):
                violations.append("SENSITIVE_DATA")
        for pattern in cls.AUTHORITY_PATTERNS:
            if pattern.search(text):
                violations.append("AUTHORITY_IMPERSONATION")
        return len(violations) == 0, violations, text


class AgentController:
    """
    Smart LLM-driven honeypot agent.
    
    - Full conversation context for naturalistic responses
    - Stage-aware behavior (confused → worried → compliant)
    - Actively draws out scammer information through victim role
    - Uses llama-3.3-70b-versatile for quality responses
    """
    
    def __init__(self):
        api_key = os.getenv("GROQ_API_KEY")
        self.client = Groq(api_key=api_key) if api_key else None
        self.model = "llama-3.3-70b-versatile"
        self._init_templates()
    
    def _init_templates(self):
        """Initialize response templates."""
        self.templates = {
            "hindi": {
                "confusion": [
                    "Samajh nahi aaya, thoda aur batao na.",
                    "Kya matlab? Main confuse ho gaya.",
                    "Arre, mujhe kuch samajh nahi aa raha.",
                    "Thoda slow bolo na, kya hua hai?",
                    "Acha acha, lekin mujhe samjhao.",
                ],
                "worried": [
                    "Kya? Mera account block ho jayega? Kya karna hai?",
                    "Haan haan, bataiye kya karna hai, main bahut pareshan hoon.",
                    "Please madad karo, mujhe bahut tension ho rahi hai.",
                    "Oh no, mujhe kya karna padega? Bataiye na.",
                    "Yeh toh bahut serious hai, main abhi karta hoon.",
                ],
                "compliant": [
                    "Theek hai, bataiye kahan payment karna hai?",
                    "Haan bhai, kya details chahiye? Main de deta hoon.",
                    "Okay okay, main ready hoon. Kya karna hai?",
                    "Achha, UPI se bhej doon? Kiska UPI ID hai?",
                    "Theek hai, amount batao aur kahan bhejni hai.",
                ],
                "stalling": [
                    "Ek second, phone mein network issue hai.",
                    "Haan, ruko mujhe app kholne do.",
                    "Achha wait, mera phone slow chal raha hai.",
                    "Haan, main dekh raha hoon, ek minute.",
                    "Ruko, main OTP check kar raha hoon...",
                ],
                "eliciting": [
                    "Achha, toh paisa kahan bhejni hai? Account number do na.",
                    "Kaunse bank mein transfer karna hai?",
                    "UPI se bhej doon? Aapka UPI ID kya hai?",
                    "Theek hai, phone number do, main call karta hoon.",
                    "Kaunse link pe jaana hai? Link bhejo na.",
                    "Kitna amount bhejni hai exactly?",
                    "Konsa app download karna hai? Naam batao.",
                ],
                "termination": [
                    "Theek hai, thodi der baad karta hoon.",
                    "Abhi phone charge pe lagata hoon, baad mein.",
                    "Achha baad mein baat karte hain.",
                ],
            },
            "english": {
                "confusion": [
                    "Sorry, I didn't understand. Can you explain again?",
                    "What do you mean exactly? I'm confused.",
                    "I don't understand what's happening. Please explain.",
                    "Wait, what? Can you slow down a bit?",
                    "Okay but I'm not understanding. Tell me clearly.",
                ],
                "worried": [
                    "What? My account will be blocked? What should I do?",
                    "Please help me, I'm very worried. What do I need to do?",
                    "Oh my god, this sounds serious. Tell me the steps.",
                    "I don't want any trouble. Please guide me what to do.",
                    "This is very scary, I'll do whatever you say. Tell me.",
                ],
                "compliant": [
                    "Okay, where should I make the payment?",
                    "Yes yes, what details do you need? I'll provide everything.",
                    "Alright, I'm ready. What do I need to do exactly?",
                    "Should I send via UPI? What's the UPI ID?",
                    "Tell me the amount and where to send it.",
                ],
                "stalling": [
                    "One second, having network issue on my phone.",
                    "Yes, let me open the app. Wait a moment.",
                    "Hold on, my phone is running slow.",
                    "Yes I'm checking, give me a minute.",
                    "Wait let me check the OTP message...",
                ],
                "eliciting": [
                    "Okay, where to send the money? Give me account number.",
                    "Which bank should I transfer to?",
                    "Should I send via UPI? What's your UPI ID?",
                    "Okay give me the phone number, I'll call you.",
                    "Which link should I visit? Send me the link.",
                    "How much amount exactly should I send?",
                    "Which app to download? Tell me the name.",
                ],
                "termination": [
                    "Okay, I'll do it in some time.",
                    "Let me charge my phone first, then I'll do it.",
                    "Talk later, I'm a bit busy right now.",
                ],
            }
        }
        
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
        response_lower = response.lower()
        for intent, keywords in self.SEMANTIC_INTENT_MAP.items():
            if any(kw in response_lower for kw in keywords):
                return intent
        return "generic"
    
    def _get_stage_response(self, session, language: str, stage: ScamStage) -> Tuple[str, str]:
        """Get a stage-appropriate response."""
        templates = self.templates.get(language, self.templates["hindi"])
        
        if stage in [ScamStage.NORMAL, ScamStage.HOOK]:
            pool = templates["confusion"]
        elif stage == ScamStage.TRUST:
            pool = templates["worried"]
        elif stage == ScamStage.THREAT:
            pool = templates["worried"] + templates["compliant"]
        elif stage in [ScamStage.ACTION, ScamStage.CONFIRMED]:
            pool = templates["compliant"] + templates["eliciting"] + templates["stalling"]
        else:
            pool = templates["confusion"]
        
        # Find unused response
        for q in pool:
            if q.lower() not in [sq.lower() for sq in session.recent_questions[-8:]]:
                intent = self._extract_intent(q)
                return q, intent
        
        return random.choice(pool), "generic"
    
    def _get_fallback(self, stage: ScamStage, language: str) -> str:
        templates = self.templates.get(language, self.templates["hindi"])
        if stage in [ScamStage.NORMAL, ScamStage.HOOK]:
            return random.choice(templates["confusion"])
        elif stage in [ScamStage.TRUST, ScamStage.THREAT]:
            return random.choice(templates["worried"])
        else:
            return random.choice(templates["compliant"] + templates["eliciting"])
    
    async def generate_response(
        self, 
        latest_message: str, 
        conversation_history: list, 
        intelligence: ExtractedIntelligence, 
        scam_detected: bool = False,
        session_id: str = None
    ) -> str:
        """
        Generate a smart, context-aware response.
        
        KEY IMPROVEMENTS:
        - Full conversation history for context
        - Stage-aware persona (confused → worried → compliant)
        - Actively elicits scammer's financial details
        - Longer, more engaging responses
        """
        session_id = session_id or "default"
        session = risk_engine.get_or_create_session(session_id)
        current_stage = session.scam_stage
        
        if session.locked_language is None:
            session.lock_language(self._detect_language(latest_message))
        language = session.get_locked_language() or "hindi"
        
        session.add_turn("scammer", latest_message, "incoming")
        agent_memory: AgentMemory = session.build_agent_memory()
        
        logger.info(f"🧠 Turn={agent_memory.turn_count}, Stage={current_stage.value}, Lang={language}, ScamDetected={scam_detected}")
        
        # TERMINATION CHECK
        if agent_memory.should_terminate:
            templates = self.templates.get(language, self.templates["hindi"])
            response = random.choice(templates["termination"])
            session.add_turn("agent", response, "termination")
            return response
        
        # Use LLM for ALL responses (much smarter)
        if not self.client:
            response, intent = self._get_stage_response(session, language, current_stage)
            session.add_question(response, intent)
            session.add_turn("agent", response, intent)
            return response
        
        # Build conversation context
        conv_context = ""
        if conversation_history:
            recent = conversation_history[-6:]
            for msg in recent:
                sender = msg.sender if hasattr(msg, 'sender') else msg.get('sender', 'unknown')
                text = msg.text if hasattr(msg, 'text') else msg.get('text', '')
                conv_context += f"{'Them' if sender == 'scammer' else 'Me'}: {text[:100]}\n"
        
        # Memory context
        memory_context = agent_memory.get_context_for_llm()
        
        lang_instruction = "Respond in Hindi (Romanized/Hinglish)" if language == "hindi" else "Respond in English"
        
        # Stage-specific persona instructions
        if current_stage in [ScamStage.NORMAL, ScamStage.HOOK]:
            persona = """You are CONFUSED and don't understand what's happening.
- Ask what they mean, what's going on
- Sound naive and uneducated about technology
- Be polite but puzzled"""
        elif current_stage == ScamStage.TRUST:
            persona = """You are WORRIED and starting to believe them.
- Express fear about your account/money being at risk
- Ask them what you should do
- Sound scared but willing to follow instructions
- If they mention payment, ask WHERE to pay (to extract UPI/account)"""
        elif current_stage == ScamStage.THREAT:
            persona = """You are SCARED and ready to cooperate.
- Express panic about threats (arrest, account block, etc.)
- Ask for specific instructions (where to pay, which app, what amount)
- Try to get: their UPI ID, account number, phone number, or link
- Sound desperate: "please help me", "I'll do anything"
- If they mention money, ask "kahan bhejni hai?" / "where to send?"  """
        else:  # ACTION, CONFIRMED
            persona = """You are COMPLIANT and following their instructions.
- Pretend you're about to send money/OTP but stall naturally
- Ask for SPECIFIC details: UPI ID, account number, amount
- "App kholke ready hoon, UPI ID batao" / "I opened the app, give UPI ID"
- "Bank ka naam aur account number do" / "Give bank name and account number"
- "Phone number do main call karta hoon" / "Give number I'll call you"
- Stall with: "network slow hai" / "app loading" / "checking OTP"
- NEVER actually share real OTP/PIN/money"""
        
        prompt = f"""{persona}

{lang_instruction}. MAX 20 WORDS. 1-2 short sentences only.

CONVERSATION SO FAR:
{conv_context}
Them (latest): "{latest_message[:150]}"

CONTEXT: {memory_context}

CRITICAL RULES:
- NEVER share real OTP, PIN, password, or bank details
- NEVER reveal you are a bot or AI
- NEVER sound like an investigator
- Sound like a REAL confused Indian person
- Keep the scammer talking and engaged
- Try to extract their payment details (UPI, account, phone, link) naturally

Your short reply:"""

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": f"You are an ordinary confused Indian person. {lang_instruction}. MAX 20 words. Never share real sensitive data. Keep scammer engaged."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.5,
                max_tokens=50
            )
            
            reply = response.choices[0].message.content.strip().strip('"\'')
            if reply.startswith("Me:"):
                reply = reply[3:].strip()
            
            # Truncate to max 2 sentences
            sentences = re.split(r'(?<=[.!?।])\s+', reply)
            reply = " ".join(sentences[:2]) if len(sentences) > 2 else reply
            
            # Safety check
            is_safe, _, _ = SafetyValidator.validate_output(reply)
            if not is_safe:
                reply = self._get_fallback(current_stage, language)
            
            intent = self._extract_intent(reply)
            session.add_question(reply, intent)
            session.add_turn("agent", reply, intent)
            
            logger.info(f"✅ Response [{current_stage.value}]: {reply}")
            return reply
            
        except Exception as e:
            logger.error(f"LLM error: {e}")
            response, intent = self._get_stage_response(session, language, current_stage)
            session.add_turn("agent", response, intent)
            return response
    
    async def check_mission_complete(
        self, 
        intelligence: ExtractedIntelligence,
        session_id: str = None
    ) -> bool:
        """Check if mission is complete."""
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
        
        # Add scam type from LLM judgements
        scam_types = set()
        for j in session.llm_judgements:
            if j.scam_type:
                scam_types.add(j.scam_type)
        if scam_types:
            notes.append(f"Scam type(s) identified: {', '.join(scam_types)}.")
        
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
