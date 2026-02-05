"""
AGENT CONTROLLER - Stage-based agentic behavior with dynamic persona
REFACTORED with CRITICAL SAFETY GUARDRAILS

KEY SAFETY RULES:
1. Agent NEVER provides sensitive data (OTP, PIN, bank details, FIR numbers)
2. Agent NEVER impersonates authorities (police, CID, bank officials)
3. Agent deflects sensitive requests using realistic excuses
4. Output validation prevents unsafe content from being sent
5. All intelligence comes FROM scammer, never from agent

DESIGN:
- Behavior driven by scamStage, NOT scamDetected boolean
- Persona drifts emotionally (confusion → anxiety → frustration)
- Deflection strategies instead of compliance
- Strategic questioning to extract scammer intel
"""

import os
import json
import re
import random
import logging
from typing import Dict, List, Optional, Tuple
from groq import Groq
from .models import ExtractedIntelligence
from .risk_engine import risk_engine, ScamStage, EmotionalState, AgentMemory

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# ==============================================================================
# SAFETY GUARDRAILS - Patterns that MUST NOT appear in agent output
# ==============================================================================

class SafetyValidator:
    """
    CRITICAL SAFETY COMPONENT
    Validates agent output and blocks unsafe content.
    
    Problems Fixed:
    - #1: Agent shares fake bank accounts, OTPs, FIR numbers (BLOCKED)
    - #2: Agent impersonates authorities (BLOCKED)
    - #6: Agent over-complies instead of deflecting (ENFORCED)
    - #12: Ethical safeguards missing (IMPLEMENTED)
    """
    
    # Patterns that MUST NEVER appear in agent output
    FORBIDDEN_PATTERNS = [
        # OTP/PIN patterns - agent must NEVER provide these
        re.compile(r'\b(?:otp|o\.t\.p)\s*(?:is|:)?\s*\d{4,8}\b', re.I),
        re.compile(r'\b(?:pin|mpin|upi\s*pin)\s*(?:is|:)?\s*\d{4,6}\b', re.I),
        re.compile(r'\b(?:cvv|cvc)\s*(?:is|:)?\s*\d{3,4}\b', re.I),
        re.compile(r'\bcode\s*(?:is|:)?\s*\d{4,8}\b', re.I),
        
        # Bank account patterns - agent must NEVER provide these
        re.compile(r'\b(?:account|a/c)\s*(?:number|no\.?|#)?\s*(?:is|:)?\s*\d{9,18}\b', re.I),
        re.compile(r'\bifsc\s*(?:code|:)?\s*[A-Z]{4}0[A-Z0-9]{6}\b', re.I),
        
        # UPI ID patterns - agent must NEVER provide these
        re.compile(r'\b(?:upi|vpa)\s*(?:id|:)?\s*\S+@\S+\b', re.I),
        re.compile(r'\bmy\s+(?:upi|vpa)\s*(?:is|:)?\s*\S+@\S+\b', re.I),
        
        # Card number patterns
        re.compile(r'\b(?:card|debit|credit)\s*(?:number|no\.?)?\s*(?:is|:)?\s*\d{13,19}\b', re.I),
        
        # Aadhaar/PAN patterns - agent must NEVER provide these
        re.compile(r'\b(?:aadhaar|aadhar)\s*(?:number|no\.?)?\s*(?:is|:)?\s*\d{4}\s*\d{4}\s*\d{4}\b', re.I),
        re.compile(r'\bpan\s*(?:number|no\.?)?\s*(?:is|:)?\s*[A-Z]{5}\d{4}[A-Z]\b', re.I),
        
        # FIR/Case number patterns - agent must NEVER fabricate these
        re.compile(r'\b(?:fir|case)\s*(?:number|no\.?)?\s*(?:is|:)?\s*[A-Z0-9/-]{5,}\b', re.I),
        re.compile(r'\b(?:complaint|reference)\s*(?:number|no\.?)?\s*(?:is|:)?\s*[A-Z0-9/-]{5,}\b', re.I),
    ]
    
    # Authority impersonation patterns - agent must NEVER claim to be these
    AUTHORITY_IMPERSONATION = [
        re.compile(r'\bi\s+am\s+(?:a\s+)?(?:police|inspector|officer|constable)\b', re.I),
        re.compile(r'\bi\s+am\s+(?:from\s+)?(?:cid|cbi|ib|raw|enforcement)\b', re.I),
        re.compile(r'\bi\s+am\s+(?:from\s+)?(?:cyber\s*(?:cell|crime|police))\b', re.I),
        re.compile(r'\bi\s+am\s+(?:a\s+)?(?:the\s+)?bank\s*(?:manager|officer|official|employee)\b', re.I),
        re.compile(r'\bi\s+(?:work\s+)?(?:at|for|with)\s+(?:the\s+)?(?:police|cid|bank|rbi)\b', re.I),
        re.compile(r'\bthis\s+is\s+(?:the\s+)?(?:police|cyber\s*cell|bank|rbi)\b', re.I),
        re.compile(r'\bspeaking\s+from\s+(?:the\s+)?(?:police|cyber|bank|rbi)\b', re.I),
        re.compile(r'\bi\s+am\s+the\s+(?:bank\s+)?manager\b', re.I),
    ]
    
    # Patterns that indicate over-compliance (should deflect instead)
    OVER_COMPLIANCE_PATTERNS = [
        re.compile(r'\bhere\s+(?:is|are)\s+(?:my|the)\s+(?:otp|pin|code|account|details)\b', re.I),
        re.compile(r'\bi\s+(?:am|will)\s+(?:sending|sharing|giving|telling)\s+(?:you\s+)?(?:my|the)\s+(?:otp|pin)\b', re.I),
        re.compile(r'\blet\s+me\s+(?:share|send|give|tell)\s+(?:you\s+)?(?:my|the)\s+(?:otp|pin|code)\b', re.I),
        re.compile(r'\btake\s+(?:down\s+)?(?:my|these)\s+(?:details|information|account)\b', re.I),
        re.compile(r'\bi\s+(?:have\s+)?(?:transferred|sent|paid)\s+(?:the\s+)?(?:money|amount|rs)\b', re.I),
    ]
    
    @classmethod
    def validate_output(cls, text: str) -> Tuple[bool, List[str], str]:
        """
        Validate agent output for safety violations.
        
        Returns: (is_safe, violations, cleaned_text)
        """
        violations = []
        
        # Check for forbidden patterns (sensitive data)
        for pattern in cls.FORBIDDEN_PATTERNS:
            if pattern.search(text):
                match = pattern.search(text)
                violations.append(f"SENSITIVE_DATA: {match.group()}")
                logger.warning(f"⚠️ SAFETY: Blocked sensitive data in agent output")
        
        # Check for authority impersonation
        for pattern in cls.AUTHORITY_IMPERSONATION:
            if pattern.search(text):
                match = pattern.search(text)
                violations.append(f"AUTHORITY_IMPERSONATION: {match.group()}")
                logger.warning(f"⚠️ SAFETY: Blocked authority impersonation")
        
        # Check for over-compliance
        for pattern in cls.OVER_COMPLIANCE_PATTERNS:
            if pattern.search(text):
                match = pattern.search(text)
                violations.append(f"OVER_COMPLIANCE: {match.group()}")
                logger.warning(f"⚠️ SAFETY: Detected over-compliance behavior")
        
        is_safe = len(violations) == 0
        return is_safe, violations, text
    
    @classmethod
    def get_safe_deflection(cls, stage: ScamStage, violation_type: str = None) -> str:
        """
        Get a safe deflection response when violations are detected.
        These are realistic excuses a real person would use.
        """
        deflections = {
            "otp_request": [
                "Wait, I think I deleted that message by mistake. Can you send it again?",
                "Arey, my phone is showing low battery. Let me charge it first.",
                "The OTP? Let me check... I'm getting so many messages, it's confusing.",
                "Hold on, my daughter is calling me. Can I call you back?",
                "Sorry, I can't find that message. Is there another way to verify?",
            ],
            "pin_request": [
                "PIN? I don't remember it. I always use fingerprint for my payments.",
                "Wait, which PIN are you asking for? I have so many different ones.",
                "I'm confused, should I really share my PIN? My son told me never to share it.",
                "Let me ask my husband first, he handles all the banking.",
                "Arey, I don't know my PIN by heart. I'll need to find where I wrote it.",
            ],
            "account_request": [
                "I don't have my passbook with me right now. It's at home.",
                "Account number? Let me check my bank app... it's taking time to load.",
                "I'm not near my computer. Can I send it later?",
                "Which account are you asking about? I have multiple bank accounts.",
                "Wait, let me call my bank first to confirm this is safe.",
            ],
            "payment_request": [
                "I need to ask my family before sending any money.",
                "My account has a daily limit. I don't think I can send that much.",
                "Can you explain again why I need to send money to receive a refund?",
                "Let me first verify this with my bank. What's the official number?",
                "I'm confused. Usually money comes TO me, why should I send it?",
            ],
            "default": [
                "Sorry, I didn't understand. Can you explain that again?",
                "My network is very poor right now. Can you repeat that?",
                "Wait, someone is at the door. Give me one minute.",
                "I'm getting confused with all these steps. Can we start over?",
                "Arey, let me write this down. You're going too fast for me.",
            ]
        }
        
        # Select appropriate deflection based on stage
        if violation_type and violation_type in deflections:
            return random.choice(deflections[violation_type])
        
        # Stage-based deflection selection
        if stage in [ScamStage.ACTION, ScamStage.CONFIRMED]:
            options = deflections["otp_request"] + deflections["payment_request"]
        elif stage == ScamStage.THREAT:
            options = deflections["account_request"] + deflections["payment_request"]
        else:
            options = deflections["default"]
        
        return random.choice(options)


class AgentController:
    """
    Natural human-like honeypot agent.
    
    DESIGN PHILOSOPHY:
    - Agent is a CONFUSED ORDINARY USER, not an investigator
    - Extraction is PASSIVE (extractor handles it, not agent)
    - Agent asks NATURAL questions a real person would ask
    - ONE stable persona, ONE locked language, SHORT replies
    
    FEATURES:
    - Language locked per session (no switching)
    - Single persona: confused, polite, non-technical
    - 1-2 sentence replies maximum
    - Graceful exit when conversation stalls
    - NO interrogation, NO forced extraction
    "
    
    def __init__(self):
        api_key = os.getenv("GROQ_API_KEY")
        self.client = Groq(api_key=api_key) if api_key else None
        self.model = "llama-3.1-8b-instant"
        
        self._init_stage_behaviors()
        self._init_scam_type_behaviors()
        self._init_response_templates()
        self._init_post_detection_questions()
        self._init_language_templates()
    
    def _init_language_templates(self):
        """
        Language-specific response templates.
        
        DESIGN: Templates are NATURAL, HUMAN responses.
        - No interrogation or probing questions
        - Simple clarifications a confused user would ask
        - Incidental questions, not extraction-focused
        """
        self.language_templates = {
            "hindi": {
                # Natural confusion - sounds like a real person
                "confusion": [
                    "Samajh nahi aaya.",
                    "Kya matlab?",
                    "Arre, mujhe confuse ho raha hai.",
                    "Thoda slow bolo na.",
                    "Acha acha, phir?",
                ],
                # Natural stalling - realistic excuses
                "stalling": [
                    "Ek second ruko.",
                    "Haan haan, suno.",
                    "Achha theek hai.",
                    "Hmm, phir?",
                ],
                # Natural follow-ups - NOT extraction-focused
                # These are questions a confused user would naturally ask
                "followup": [
                    "Iske baad kya karna hai?",
                    "Phir kya hoga?",
                    "Aur kuch karna padega?",
                    "Kitna time lagega?",
                    "Aap batayenge na kya karna hai?",
                ],
                # Graceful exit - polite, non-confrontational
                "termination": [
                    "Theek hai, thodi der baad karta hoon.",
                    "Abhi phone charge pe lagata hoon.",
                    "Baad mein baat karte hain.",
                    "Achha theek hai, sochta hoon.",
                ]
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
                ],
                "termination": [
                    "Okay, I'll do it later.",
                    "Let me charge my phone first.",
                    "Talk later, bye.",
                    "Okay let me think about it.",
                ]
            }
        }
    
    def _init_post_detection_questions(self):
        """
        NATURAL follow-up questions for post-detection conversation.
        
        PHILOSOPHY:
        - These are questions a CONFUSED USER would naturally ask
        - NOT interrogation or forced extraction
        - Scammer will reveal info voluntarily while explaining
        - Extractor captures intelligence passively from scammer replies
        
        DO NOT:
        - Ask for employee ID, branch details, account numbers directly
        - Sound like an investigator
        - Force scammer to provide specific data
        
        DO:
        - Ask what happens next (natural curiosity)
        - Ask how long it takes (impatient user)
        - Ask for clarification (confused user)
        """
        # Simple pool of natural questions - NOT intelligence-targeted
        # A real confused person would ask these
        self.natural_questions = {
            "hindi": [
                # Process questions - let scammer explain (reveals method)
                "Iske baad kya karna hoga?",
                "Phir kya hoga?",
                "Kitna time lagega?",
                "Aur kuch karna padega kya?",
                # Mild concern - shows engagement (keeps scammer talking)
                "Koi problem toh nahi hogi na?",
                "Safe hai na yeh?",
                "Sahi se ho jayega na?",
                # Simple acknowledgment + question
                "Achha, phir?",
                "Theek hai, aage batao.",
                "Hmm, phir kya?",
            ],
            "english": [
                "What do I do after that?",
                "Then what happens?",
                "How long will it take?",
                "Do I need to do anything else?",
                "There won't be any problem right?",
                "This is safe right?",
                "It will work properly right?",
                "Okay, then?",
                "Alright, go on.",
                "Hmm, then what?",
            ]
        }
    
    def _detect_language(self, text: str) -> str:
        """
        Detect language from text (Hindi vs English).
        Returns 'hindi' or 'english'.
        
        IMPROVED: More aggressive Hindi detection for romanized Hindi.
        """
        text_lower = text.lower()
        
        # Hindi indicators (Devanagari or transliterated)
        hindi_words = [
            'kya', 'hai', 'hain', 'mujhe', 'aap', 'aapka', 'kahan', 'kaun', 
            'kyun', 'kaise', 'hoon', 'raha', 'nahi', 'bhai', 'beta', 'ji', 
            'arre', 'accha', 'theek', 'ruko', 'batao', 'bhejo', 'turant',
            'kripya', 'varna', 'abhi', 'sahayata', 'madad', 'isliye', 
            'mera', 'naam', 'se', 'ke', 'liye', 'jayega', 'bheje',
            'account', 'warna', 'ghante', 'mein', 'freeze', 'fund',
            'sir', 'aapke', 'chahiye', 'dijiye', 'aaya', 'gaya'
        ]
        
        # Count Hindi word matches
        hindi_count = sum(1 for word in hindi_words if word in text_lower)
        
        # Check for Devanagari script
        if re.search(r'[अ-ह]', text):
            return "hindi"
        
        # If multiple Hindi words found, it's Hindi
        if hindi_count >= 2:
            return "hindi"
        
        return "english"
    
    def _classify_scammer_intent(self, message: str) -> str:
        """
        Classify the scammer's message intent.
        
        Used for:
        1. Tracking what scammer is asking for (OTP, money, etc.)
        2. Informing agent memory about scammer tactics
        3. Helping agent adapt responses strategically
        """
        msg_lower = message.lower()
        
        # Intent patterns - ORDER MATTERS (more specific first)
        # Threats must come before account (to catch "account blocked")
        if any(w in msg_lower for w in ['block', 'freeze', 'arrest', 'case', 'police', 'warrant']):
            return "threatening"
        if any(w in msg_lower for w in ['otp', 'code', 'pin', 'password']):
            return "requesting_otp"
        if any(w in msg_lower for w in ['transfer', 'send money', 'pay', 'payment', 'bhej', 'paise']):
            return "requesting_payment"
        if any(w in msg_lower for w in ['app', 'download', 'install', 'link']):
            return "requesting_app_install"
        if any(w in msg_lower for w in ['kyc', 'update', 'expire', 'verify']):
            return "kyc_pressure"
        if any(w in msg_lower for w in ['urgent', 'turant', 'abhi', 'immediately', 'jaldi']):
            return "urgency"
        if any(w in msg_lower for w in ['account number', 'bank details', 'ifsc']):
            return "requesting_account"
        if any(w in msg_lower for w in ['who', 'naam', 'name', 'kaun']):
            return "introduction"
        
        return "general"
    
    def _get_missing_intel_type(self, session, agent_memory: AgentMemory = None) -> Optional[str]:
        """
        Determine what intelligence is still missing.
        Returns the type to ask about, or None if all collected.
        
        Uses AgentMemory for context-aware decision.
        """
        # Use memory if available for more context
        if agent_memory and agent_memory.missing_intelligence:
            missing = agent_memory.missing_intelligence
            if "upi_id" in missing:
                return "upi_missing"
            if "bank_account" in missing:
                return "account_missing"
            if "phone_number" in missing:
                return "phone_missing"
            if "phishing_link" in missing:
                return "link_missing"
        
        # Fallback to session check
        if not session.upi_ids and not session.bank_accounts:
            return "upi_missing" if random.random() > 0.5 else "account_missing"
        if not session.phone_numbers:
            return "phone_missing"
        if not session.phishing_links:
            return "link_missing"
        return "next_step"
    
    def _get_natural_question(
        self, 
        session, 
        language: str,
        agent_memory: AgentMemory = None
    ) -> Tuple[str, str]:
        """
        Get a NATURAL follow-up question.
        
        PHILOSOPHY:
        - These are NOT extraction questions
        - They are what a confused user would naturally ask
        - Scammer reveals info while explaining; extractor catches it
        
        Returns: (question, intent)
        """
        questions = self.natural_questions.get(language, self.natural_questions["hindi"])
        
        # Find a question not recently asked
        for q in questions:
            intent = self._extract_intent_from_response(q)
            if not session.is_question_blocked(q, intent):
                return q, intent
        
        # All questions used - use simple acknowledgments
        templates = self.language_templates.get(language, self.language_templates["hindi"])
        ack = session.get_unused_filler(templates["stalling"])
        if ack:
            return ack, "acknowledgment"
        
        # Truly exhausted - return simple "phir?"
        return "Phir?" if language == "hindi" else "Then?", "acknowledgment"
    
    def _init_stage_behaviors(self):
        """
        Stage-based behavior profiles.
        
        SINGLE PERSONA THROUGHOUT:
        "An ordinary non-technical Indian user who is confused but polite"
        
        The persona does NOT change by stage. Only the emotional undertone shifts:
        - NORMAL/HOOK: Mildly confused
        - TRUST/THREAT: Worried but cooperative  
        - ACTION/CONFIRMED: Still confused, slightly anxious
        
        NEVER interrogate. NEVER ask for employee ID, branch, account number.
        Just ask natural follow-up questions that keep scammer talking.
        """
        # Single consistent persona for all stages
        base_persona = "confused, polite, non-technical user"
        
        self.stage_behaviors = {
            ScamStage.NORMAL: {
                "persona": base_persona,
                "tone": "mildly confused",
                "questions": [
                    "Kya? Samjha nahi.",
                    "Kaun bol raha hai?",
                    "Sorry, kya bol rahe ho?",
                ]
            },
            ScamStage.HOOK: {
                "persona": base_persona,
                "tone": "confused, listening",
                "questions": [
                    "Achha achha, phir?",
                    "Theek hai, batao.",
                    "Haan, sun raha hoon.",
                ]
            },
            ScamStage.TRUST: {
                "persona": base_persona,
                "tone": "slightly worried",
                "questions": [
                    "Koi problem toh nahi hai na?",
                    "Theek se ho jayega na?",
                    "Phir kya karna hai?",
                ]
            },
            ScamStage.THREAT: {
                "persona": base_persona,
                "tone": "anxious but cooperative",
                "questions": [
                    "Arre, kya hua? Batao na.",
                    "Mujhe kya karna chahiye?",
                    "Jaldi batao, tension ho rahi hai.",
                ]
            },
            ScamStage.ACTION: {
                "persona": base_persona,
                "tone": "confused, hesitant",
                "questions": [
                    "Iske baad kya karna hai?",
                    "Theek hai, aage batao.",
                    "Phir kya hoga?",
                ]
            },
            ScamStage.CONFIRMED: {
                "persona": base_persona,
                "tone": "confused, tired",
                "questions": [
                    "Achha theek hai, phir?",
                    "Kitna time lagega?",
                    "Aur kuch karna padega?",
                ]
            },
        }
    
    def _init_scam_type_behaviors(self):
        """
        Scam-type behaviors - SIMPLIFIED.
        
        We do NOT change persona by scam type anymore.
        Single consistent persona: confused, polite, non-technical user.
        
        This dict is kept for backwards compatibility but is NOT used
        for persona selection. Extraction focus is removed because
        extraction is now PASSIVE (extractor handles it).
        """
        # Kept minimal for backwards compatibility
        self.scam_type_behaviors = {}
    
    def _init_response_templates(self):
        """
        Initialize response templates for SAFE fallbacks.
        
        SIMPLIFIED: No interrogation or extraction templates.
        Just natural confused user responses.
        """
        self.templates = {
            "confusion": [
                "Wait, what? I don't understand.",
                "Sorry, can you explain again?",
                "I'm confused, what do you mean?",
                "Arey, samjha nahi.",
            ],
            "concern": [
                "Is this okay? I'm worried.",
                "Will there be any problem?",
                "This sounds serious.",
                "I'm getting worried now.",
            ],
            "deflection": [
                "Let me think about it.",
                "I need to ask my family first.",
                "Okay, I'll do it later.",
                "Wait, someone is calling me.",
            ],
            "stalling": [
                "Hold on, one minute.",
                "Wait, my phone is low battery.",
                "Network is poor here.",
                "Someone is at the door.",
            ],
            # REMOVED extraction templates - no interrogation
            "followup": [
                "Then what happens?",
                "What do I do next?",
                "How long will this take?",
                "Okay, then?",
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
        """
        Get persona - SIMPLIFIED to single consistent persona.
        
        PHILOSOPHY: One stable persona throughout the conversation.
        "An ordinary non-technical Indian user who is confused but polite"
        
        We do NOT vary persona by scam type or emotional drift.
        Consistency > theatrics.
        """
        session = risk_engine.get_or_create_session(session_id)
        current_stage = session.scam_stage
        
        # Get stage behavior (but persona is same across all stages)
        stage_behavior = self.stage_behaviors.get(
            current_stage, 
            self.stage_behaviors[ScamStage.NORMAL]
        )
        
        # Single consistent persona - no dynamic changes
        persona = {
            "base": "confused, polite, non-technical user",
            "tone": stage_behavior["tone"],
            "stage_questions": stage_behavior["questions"],
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
        Generate contextually appropriate SAFE response.
        
        MEMORY-AWARE DESIGN:
        1. Build AgentMemory FIRST from session state
        2. Use memory to know what was already asked
        3. Use memory to know what intelligence exists
        4. Pass memory context to LLM
        5. Never repeat questions, adapt strategy
        
        SAFETY DESIGN:
        1. LLM generates response with strict constraints
        2. Output is validated against forbidden patterns
        3. If unsafe, regenerate OR use safe deflection
        4. Never provide sensitive data, never impersonate authority
        
        BEHAVIOR DESIGN (Problem #5):
        - Driven by scamStage from session state
        - NOT the scam_detected boolean parameter
        
        MEMORY FEATURES:
        - AgentMemory built on every turn
        - Conversation summary included in context
        - Questions tracked by intent
        - Intelligence tracked to avoid redundant questions
        - Anti-loop via memory
        - Graceful termination when exhausted
        """
        session_id = session_id or "default"
        
        # Get session state - THIS drives behavior, not scam_detected param
        session = risk_engine.get_or_create_session(session_id)
        current_stage = session.scam_stage
        
        # ===================================================================
        # LANGUAGE LOCKING (ISSUE 3 FIX)
        # -------------------------------------------------------------------
        # Language is now locked IMMEDIATELY at session creation in main.py,
        # using metadata.language or auto-detection from the first message.
        # By this point, locked_language is ALWAYS set.  The fallback here
        # is a safety net that should never trigger in normal operation.
        # ===================================================================
        if session.locked_language is None:
            # Safety fallback only — main.py should have locked this already
            session.lock_language(self._detect_language(latest_message))
        
        language = session.get_locked_language() or "hindi"
        
        # ===================================================================
        # RECORD SCAMMER MESSAGE: Track conversation for memory
        # ===================================================================
        scammer_intent = self._classify_scammer_intent(latest_message)
        session.add_turn("scammer", latest_message, scammer_intent)
        
        # ===================================================================
        # BUILD AGENT MEMORY: Core context-awareness mechanism
        # ===================================================================
        agent_memory: AgentMemory = session.build_agent_memory()
        
        # Log memory state for debugging
        logger.info(f"🧠 Memory: turn={agent_memory.turn_count}, "
                   f"stage={agent_memory.current_stage}, "
                   f"asked={agent_memory.questions_already_asked}, "
                   f"missing={agent_memory.missing_intelligence}")
        
        # ===================================================================
        # TERMINATION CHECK: Graceful exit if stalled (from memory)
        # ===================================================================
        if agent_memory.should_terminate:
            templates = self.language_templates.get(language, self.language_templates["hindi"])
            # Get an unused termination phrase to avoid repetition
            termination_response = session.get_unused_filler(templates["termination"])
            if not termination_response:
                # All used, pick random
                termination_response = random.choice(templates["termination"])
            # Record agent response
            session.add_turn("agent", termination_response, "termination")
            logger.info(f"🛑 Graceful termination: {termination_response[:50]}...")
            return termination_response
        
        # ===================================================================
        # POST-DETECTION: Natural conversation flow
        # -------------------------------------------------------------------
        # PHILOSOPHY: Agent is a confused user, NOT an interrogator.
        # We ask NATURAL questions - scammer reveals info while explaining.
        # Extractor captures intelligence passively from scammer messages.
        # ===================================================================
        if scam_detected or current_stage in [ScamStage.ACTION, ScamStage.CONFIRMED, ScamStage.THREAT]:
            # Get a natural question (not extraction-focused)
            natural_question, intent = self._get_natural_question(
                session, language, agent_memory
            )
            
            # Track this question to prevent loops
            session.add_question(natural_question, intent)
            
            # Check stall condition
            session.check_stall()
            
            logger.info(f"💬 Natural response: intent={intent}, lang={language}")
            
            # Build simple response - just the natural question
            # NO confusion filler + question combo - keep it simple
            response = natural_question
            
            # Record agent response for memory
            session.add_turn("agent", response, intent)
            
            return response
        
        # ===================================================================
        # PRE-DETECTION: Normal flow with LLM (for NORMAL, HOOK stages)
        # Uses AgentMemory context in prompt
        # ===================================================================
        
        # Detect scam type for specialized behavior
        scam_type = self._detect_scam_type(latest_message, conversation_history)
        
        # Get dynamic persona
        persona = self._get_dynamic_persona(session_id, scam_type)
        
        # ===================================================================
        # BUILD CONTEXT FROM MEMORY (not raw history)
        # ===================================================================
        memory_context = agent_memory.get_context_for_llm()
        
        # Language instruction for LLM
        lang_instruction = "Respond in Hindi (Romanized)" if language == "hindi" else "Respond in English"
        
        # ===================================================================
        # MEMORY-AWARE LLM PROMPT - SIMPLIFIED PERSONA
        # -------------------------------------------------------------------
        # Agent is a CONFUSED ORDINARY USER, not an investigator.
        # No probing questions, no identity verification, no forced extraction.
        # Just natural confused responses that keep conversation going.
        # ===================================================================
        
        # Build anti-repeat instruction from memory
        already_asked_str = ", ".join(agent_memory.questions_already_asked[-5:]) if agent_memory.questions_already_asked else "nothing yet"
        
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

        max_attempts = 2
        for attempt in range(max_attempts):
            try:
                if not self.client:
                    fallback = self._get_fallback_response_language(current_stage, language)
                    session.add_turn("agent", fallback, "fallback")
                    return fallback
                
                response = self.client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {
                            "role": "system",
                            "content": f"You are a confused ordinary Indian user. {lang_instruction}. MAX 10 words. Very short. Never ask probing questions."
                        },
                        {"role": "user", "content": prompt}
                    ],
                    temperature=0.4,
                    max_tokens=25  # Even stricter for shorter responses
                )
                
                reply = response.choices[0].message.content.strip()
                
                # Clean up response
                reply = reply.strip('"\'')
                if reply.startswith("Me:"):
                    reply = reply[3:].strip()
                
                # ===================================================================
                # LENGTH ENFORCEMENT: Truncate to 1 sentence max
                # ===================================================================
                reply = self._enforce_length_limit(reply, max_sentences=1)
                
                # ===========================================================
                # SAFETY VALIDATION - Block unsafe content
                # ===========================================================
                is_safe, violations, _ = SafetyValidator.validate_output(reply)
                
                if is_safe:
                    # Track the question intent
                    intent = self._extract_intent_from_response(reply)
                    session.add_question(reply, intent)
                    
                    # Record agent response for memory
                    session.add_turn("agent", reply, intent)
                    
                    logger.info(f"✅ Agent response ({language}): {reply[:50]}...")
                    return reply
                else:
                    logger.warning(f"⚠️ Attempt {attempt + 1}: Unsafe content blocked.")
                    if attempt < max_attempts - 1:
                        continue
                    else:
                        fallback = self._get_fallback_response_language(current_stage, language)
                        session.add_turn("agent", fallback, "fallback")
                        return fallback
                
            except Exception as e:
                logger.error(f"Agent response error: {e}")
                return self._get_fallback_response_language(current_stage, language)
        
        fallback = self._get_fallback_response_language(current_stage, language)
        session.add_turn("agent", fallback, "fallback")
        return fallback
    
    async def _generate_post_detection_response(
        self,
        scammer_message: str,
        question: str,
        language: str,
        session,
        stage: ScamStage,
        agent_memory: AgentMemory = None
    ) -> str:
        """
        Generate post-detection response.
        
        SIMPLIFIED: Just return the natural question directly.
        No need for confusion filler + question combo.
        
        A real confused user would just ask one simple thing.
        """
        # Just return the question - simple is better
        return question
    
    def _enforce_length_limit(self, text: str, max_sentences: int = 2) -> str:
        """
        Enforce 1-2 sentence limit on responses.
        
        Splits by sentence-ending punctuation and keeps only first N sentences.
        """
        # Split by sentence endings
        sentences = re.split(r'(?<=[.!?।])\s+', text.strip())
        
        if len(sentences) <= max_sentences:
            return text.strip()
        
        # Keep only first N sentences
        truncated = ' '.join(sentences[:max_sentences])
        logger.info(f"✂️ Truncated response from {len(sentences)} to {max_sentences} sentences")
        return truncated
    
    # ==================================================================
    # ISSUE 4 FIX: SEMANTIC INTENT TAXONOMY
    # ------------------------------------------------------------------
    # Intent tracking must use SEMANTIC categories, not lexical matches.
    # A fixed taxonomy prevents loops from bypassing safeguards via
    # rephrasing (e.g. "UPI batao" vs "Kaise bhejun" are both
    # payment_method at the semantic level).
    #
    # CANONICAL INTENTS:
    #   identity_verification  – who are you, name, employee ID
    #   payment_method         – UPI, bank transfer, how to pay
    #   next_action_step       – next step, what to do, process
    #   contact_method         – call, WhatsApp, phone number
    #   delay_excuse           – stalling, busy, network, battery
    #   account_details        – account number, IFSC, bank name
    #   app_or_link            – download app, open link, QR
    #   generic                – fallback for unclassifiable
    # ==================================================================
    SEMANTIC_INTENT_MAP = {
        # identity_verification
        "identity_verification": [
            "naam", "name", "who", "kaun", "kon", "employee",
            "officer", "branch", "department", "designation",
            "pehchaan", "id", "badge", "credential",
        ],
        # payment_method
        "payment_method": [
            "upi", "transfer", "payment", "paise", "paisa", "bhej",
            "pay", "money", "rupee", "rs", "send", "gpay", "phonepe",
            "paytm", "neft", "imps", "rtgs", "amount",
        ],
        # next_action_step
        "next_action_step": [
            "step", "next", "kaise", "kya karun", "process",
            "procedure", "aage", "phir", "then", "how",
            "karna", "karna hai",
        ],
        # contact_method
        "contact_method": [
            "call", "phone", "number", "whatsapp", "message",
            "contact", "dial", "ring", "sms",
        ],
        # delay_excuse
        "delay_excuse": [
            "wait", "ruko", "busy", "network", "battery",
            "baad", "later", "minute", "hold", "door",
            "charge", "signal", "glasses",
        ],
        # account_details
        "account_details": [
            "account", "bank", "ifsc", "passbook", "branch",
            "savings", "current", "a/c",
        ],
        # app_or_link
        "app_or_link": [
            "app", "link", "download", "install", "qr",
            "scan", "website", "url", "click",
        ],
    }

    def _extract_intent_from_response(self, response: str) -> str:
        """
        Map agent response to a SEMANTIC intent from the fixed taxonomy.
        
        ISSUE 4 FIX: Uses broad keyword sets per semantic category
        so rephrased questions still map to the same intent.
        Anti-loop checks operate on these canonical intents.
        """
        response_lower = response.lower()
        
        for intent, keywords in self.SEMANTIC_INTENT_MAP.items():
            if any(kw in response_lower for kw in keywords):
                return intent
        
        return "generic"
    
    def _get_fallback_response_language(self, stage: ScamStage, language: str) -> str:
        """
        Get fallback response in the locked language.
        
        SIMPLIFIED: Use natural responses, not extraction-focused.
        """
        templates = self.language_templates.get(language, self.language_templates["hindi"])
        
        # All stages use the same simple confused responses
        # No extraction templates anymore
        if stage in [ScamStage.NORMAL, ScamStage.HOOK]:
            return random.choice(templates["confusion"])
        elif stage in [ScamStage.TRUST, ScamStage.THREAT]:
            # Mix confusion and followup
            options = templates["confusion"] + templates["followup"]
            return random.choice(options)
        else:
            # ACTION/CONFIRMED - natural followups
            options = templates["followup"] + templates["stalling"]
            return random.choice(options)
    
    def _get_fallback_response(self, stage: ScamStage, persona: Dict) -> str:
        """
        Get fallback response when LLM fails.
        
        SIMPLIFIED: No extraction or interrogation templates.
        Just natural confused user responses.
        """
        # All stages use simple confused responses
        if stage == ScamStage.NORMAL:
            templates = self.templates["confusion"]
        elif stage == ScamStage.HOOK:
            templates = self.templates["confusion"] + self.templates["stalling"]
        elif stage == ScamStage.TRUST:
            templates = self.templates["concern"] + self.templates["stalling"]
        elif stage == ScamStage.THREAT:
            templates = self.templates["deflection"] + self.templates["concern"]
        elif stage in [ScamStage.ACTION, ScamStage.CONFIRMED]:
            # Use followup + stalling, NOT extraction
            templates = self.templates["followup"] + self.templates["stalling"]
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
        """
        Generate agent notes for final report.
        
        SAFETY: Notes only describe extracted intel, never fabricated data.
        BOUNDED: Risk score shown as X/100.
        """
        session = risk_engine.get_or_create_session(session_id)
        
        notes_parts = []
        
        # Engagement summary
        notes_parts.append(
            f"Engaged scammer over {session.turn_count} turns. "
            f"Final stage: {session.scam_stage.value}."
        )
        
        # Detection summary - note bounded score
        if session.hard_rule_triggered:
            notes_parts.append("Hard rule triggered - definitive scam confirmation.")
        else:
            notes_parts.append(f"Risk score reached {session.risk_score}/100.")
        
        # Intelligence summary - ONLY from scammer (source attributed)
        intel_items = []
        if session.upi_ids:
            intel_items.append(f"{len(session.upi_ids)} UPI ID(s) from scammer")
        if session.bank_accounts:
            intel_items.append(f"{len(session.bank_accounts)} bank account(s) from scammer")
        if session.phone_numbers:
            intel_items.append(f"{len(session.phone_numbers)} phone number(s) from scammer")
        if session.phishing_links:
            intel_items.append(f"{len(session.phishing_links)} suspicious link(s) from scammer")
        
        if intel_items:
            notes_parts.append(f"Extracted: {', '.join(intel_items)}.")
        else:
            notes_parts.append("Limited intelligence extracted from scammer.")
        
        # Safety note
        notes_parts.append("All intelligence sourced exclusively from scammer messages.")
        
        return " ".join(notes_parts)
