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
from .risk_engine import risk_engine, ScamStage, EmotionalState

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
    Autonomous AI agent for honeypot engagement.
    
    KEY DESIGN (Problem #5, #6, #7):
    - Behavior driven by scamStage, NOT scamDetected
    - Can operate meaningfully at ALL stages
    - Persona drifts emotionally through conversation
    - Strategic extraction based on stage
    
    NEW FEATURES (Anti-loop, Language lock, Post-detection):
    - Language locked per session (no random switching)
    - Post-detection: switches to HIGH-YIELD extraction questions
    - Anti-loop: tracks questions, blocks repetition
    - Termination: graceful exit when stalled
    - Response length: enforced 1-2 sentences max
    """
    
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
        LANGUAGE LOCK: Agent uses ONLY the locked language.
        """
        self.language_templates = {
            "hindi": {
                "confusion": [
                    "Kya baat hai? Samajh nahi aaya.",
                    "Beta, thoda dhire bolo, samajh nahi aa raha.",
                    "Arey, kya keh rahe ho? Mujhe confusion ho raha hai.",
                ],
                "stalling": [
                    "Ek minute ruko, phone charge par laga raha hoon.",
                    "Abhi busy hoon, thodi der baad baat karte hain.",
                    "Ruko, koi door par aaya hai.",
                ],
                "extraction": [
                    "Aapka naam kya bola? Aur kahan se call kar rahe ho?",
                    "Paise kahan bhejne hain? Account number batao.",
                    "UPI se bhejun ya bank transfer se?",
                    "Kaunsa app kholna hoga?",
                ],
                "termination": [
                    "Accha beta, baad mein baat karte hain. Mera phone ki battery khatam ho rahi hai.",
                    "Theek hai, main apne bete ko bula kar puchh leta hoon. Bye.",
                    "Mujhe samajh nahi aa raha, main bank jaake puchhunga. Bye.",
                ]
            },
            "english": {
                "confusion": [
                    "Sorry, I don't understand. Can you explain again?",
                    "What are you saying? I'm confused.",
                    "Wait, what? I didn't get that.",
                ],
                "stalling": [
                    "Hold on, let me charge my phone.",
                    "Someone is at the door, one minute.",
                    "My network is very poor, can you repeat?",
                ],
                "extraction": [
                    "What's your name again? Which branch are you calling from?",
                    "Where should I send the money? What's the account number?",
                    "Should I pay via UPI or bank transfer?",
                    "Which app do I need to open?",
                ],
                "termination": [
                    "Okay, let me call you back. My phone battery is low.",
                    "Let me ask my son first. Bye for now.",
                    "I don't understand, I'll go to the bank and ask. Bye.",
                ]
            }
        }
    
    def _init_post_detection_questions(self):
        """
        HIGH-YIELD questions for post-detection intelligence extraction.
        
        POST-DETECTION STRATEGY:
        - STOP identity verification questions
        - SWITCH to action-oriented extraction
        - Ask about payment methods, apps, next steps
        """
        self.post_detection_questions = {
            "upi_missing": {
                "intent": "payment_method",
                "questions_hindi": [
                    "Paise UPI se bhejun ya bank transfer se?",
                    "Kaunsa UPI ID par bhejna hai?",
                    "PhonePe se bhejun ya GPay se?",
                ],
                "questions_english": [
                    "Should I pay via UPI or bank transfer?",
                    "What UPI ID should I send to?",
                    "Should I use PhonePe or GPay?",
                ]
            },
            "phone_missing": {
                "intent": "contact_method",
                "questions_hindi": [
                    "Aap call karoge ya main karun?",
                    "Kaunsa number par call karna hai?",
                    "WhatsApp par baat karein ya call par?",
                ],
                "questions_english": [
                    "Will you call me or should I call you?",
                    "What number should I call?",
                    "Should we talk on WhatsApp or call?",
                ]
            },
            "link_missing": {
                "intent": "process_steps",
                "questions_hindi": [
                    "Kaunsa app kholna hoga?",
                    "Link bhejo, main click karunga.",
                    "Kya download karna padega?",
                ],
                "questions_english": [
                    "Which app do I need to open?",
                    "Send me the link, I'll click it.",
                    "Do I need to download something?",
                ]
            },
            "account_missing": {
                "intent": "account_details",
                "questions_hindi": [
                    "Paise kahan bhejne hain? Account number batao.",
                    "Kaunse bank mein transfer karna hai?",
                    "Account number aur IFSC code bolo.",
                ],
                "questions_english": [
                    "Where should I send the money? Tell me account number.",
                    "Which bank should I transfer to?",
                    "Tell me the account number and IFSC code.",
                ]
            },
            "next_step": {
                "intent": "next_steps",
                "questions_hindi": [
                    "OTP bhejne ke baad kya karna hoga?",
                    "Paise bhejne ke baad aage kya step hai?",
                    "Phir main kya karun?",
                ],
                "questions_english": [
                    "After sending OTP, what's the next step?",
                    "After sending money, what do I do next?",
                    "What should I do then?",
                ]
            }
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
    
    def _get_missing_intel_type(self, session) -> Optional[str]:
        """
        Determine what intelligence is still missing.
        Returns the type to ask about, or None if all collected.
        """
        if not session.upi_ids and not session.bank_accounts:
            return "upi_missing" if random.random() > 0.5 else "account_missing"
        if not session.phone_numbers:
            return "phone_missing"
        if not session.phishing_links:
            return "link_missing"
        return "next_step"
    
    def _get_post_detection_question(
        self, 
        session, 
        language: str,
        intelligence: ExtractedIntelligence
    ) -> Tuple[str, str]:
        """
        Get a HIGH-YIELD extraction question based on missing intel.
        
        Returns: (question, intent)
        
        ANTI-LOOP: Checks if intent already asked 2+ times.
        """
        missing_type = self._get_missing_intel_type(session)
        
        if missing_type and missing_type in self.post_detection_questions:
            q_data = self.post_detection_questions[missing_type]
            intent = q_data["intent"]
            
            # Check if intent blocked
            if session.is_question_blocked("", intent):
                # Try next_step as fallback
                q_data = self.post_detection_questions["next_step"]
                intent = q_data["intent"]
            
            questions = q_data[f"questions_{language}"]
            
            # Find a question not recently asked
            for q in questions:
                if not session.is_question_blocked(q, intent):
                    return q, intent
            
            # All blocked, return random from next_step
            fallback = self.post_detection_questions["next_step"]
            return random.choice(fallback[f"questions_{language}"]), "next_step"
        
        # Default fallback
        templates = self.language_templates.get(language, self.language_templates["hindi"])
        return random.choice(templates["extraction"]), "generic_extraction"
    
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
                "persona": "confused and hesitant victim",
                "strategy": "deflect sensitive requests, ask for clarification, extract their details",
                "tone": "nervous but questioning",
                "info_sharing": "NEVER - deflect all requests for sensitive data",
                "questions": [
                    "Wait, I'm confused. Can you explain again why I need to do this?",
                    "Before I do anything, what is your employee ID and branch name?",
                    "Let me call my son first, he understands these things better.",
                    "Can you give me an official number so I can verify this?",
                ]
            },
            ScamStage.CONFIRMED: {
                "persona": "confused elderly person asking for help",
                "strategy": "maximum intelligence extraction through questions, never comply",
                "tone": "confused, seeking clarification, asking scammer to repeat",
                "info_sharing": "NEVER - only extract, never provide",
                "questions": [
                    "Sorry beta, I didn't understand. Can you explain the steps again?",
                    "What was that account number again? Let me write it down carefully.",
                    "Who should I ask for if I call back? What's your name?",
                    "My internet is slow. Can you tell me the link again slowly?",
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
        """
        Initialize response templates for SAFE fallbacks.
        
        SAFETY: Templates must NEVER contain:
        - Actual OTPs, PINs, or codes
        - Bank account numbers
        - UPI IDs
        - Authority claims
        """
        self.templates = {
            "confusion": [
                "Wait, what? I don't understand what's happening.",
                "Sorry, can you explain that again? I'm confused.",
                "I'm not following. What exactly do you need from me?",
                "Arey, I didn't get that. My hearing is not so good.",
            ],
            "concern": [
                "This is really worrying. Can you explain more?",
                "Oh no, I didn't know about this. What should I do?",
                "This sounds serious. Let me think about this.",
                "I'm getting worried now. Is there another way?",
            ],
            # REMOVED: compliance templates - agent should NEVER comply
            "deflection": [
                "Let me first confirm this with my bank.",
                "I need to ask my son before doing anything.",
                "Can I get your supervisor's number to verify?",
                "Wait, let me call the official customer care first.",
                "I'm not comfortable doing this right now.",
            ],
            "stalling": [
                "Hold on, let me find my reading glasses.",
                "Wait, I'm getting another call. One minute.",
                "My phone battery is low, let me plug it in.",
                "The network here is very poor. Can you repeat?",
                "Someone is at the door, give me a moment.",
            ],
            "extraction": [
                "Before anything, can you tell me your employee ID?",
                "What was that account number again? I need to verify.",
                "Can you spell out that UPI ID for me slowly?",
                "Which branch are you calling from exactly?",
                "What's the reference number for this case?",
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
        Generate contextually appropriate SAFE response.
        
        SAFETY DESIGN:
        1. LLM generates response with strict constraints
        2. Output is validated against forbidden patterns
        3. If unsafe, regenerate OR use safe deflection
        4. Never provide sensitive data, never impersonate authority
        
        BEHAVIOR DESIGN (Problem #5):
        - Driven by scamStage from session state
        - NOT the scam_detected boolean parameter
        
        NEW FEATURES:
        - LANGUAGE LOCK: Detect and lock language on first reply
        - POST-DETECTION: Switch to high-yield extraction questions
        - ANTI-LOOP: Block repetitive questions
        - TERMINATION: Graceful exit when stalled
        - LENGTH: Enforce 1-2 sentences max
        """
        session_id = session_id or "default"
        
        # Get session state - THIS drives behavior, not scam_detected param
        session = risk_engine.get_or_create_session(session_id)
        current_stage = session.scam_stage
        
        # ===================================================================
        # LANGUAGE LOCKING: Detect and lock language for session
        # ===================================================================
        if session.locked_language is None:
            # Detect from first scammer message or conversation history
            detected_lang = self._detect_language(latest_message)
            # Check history for language hints
            if conversation_history:
                for msg in conversation_history[-3:]:
                    text = msg.text if hasattr(msg, 'text') else msg.get('text', '')
                    if self._detect_language(text) == "hindi":
                        detected_lang = "hindi"
                        break
            session.lock_language(detected_lang)
        
        language = session.get_locked_language() or "hindi"
        
        # ===================================================================
        # TERMINATION CHECK: Graceful exit if stalled
        # ===================================================================
        if session.should_gracefully_terminate():
            templates = self.language_templates.get(language, self.language_templates["hindi"])
            termination_response = random.choice(templates["termination"])
            logger.info(f"🛑 Graceful termination: {termination_response[:50]}...")
            return termination_response
        
        # ===================================================================
        # POST-DETECTION STRATEGY: Switch to high-yield extraction
        # ===================================================================
        if scam_detected or current_stage in [ScamStage.ACTION, ScamStage.CONFIRMED, ScamStage.THREAT]:
            # Use post-detection extraction questions instead of identity verification
            extraction_question, intent = self._get_post_detection_question(session, language, intelligence)
            
            # Track this question to prevent loops
            session.add_question(extraction_question, intent)
            
            # Check stall condition
            session.check_stall()
            
            # Use template-based response for consistency (no LLM randomness)
            logger.info(f"🎯 Post-detection mode: intent={intent}, lang={language}")
            
            # Build a short, focused response
            response = await self._generate_post_detection_response(
                latest_message, 
                extraction_question, 
                language, 
                session, 
                current_stage
            )
            
            return response
        
        # ===================================================================
        # PRE-DETECTION: Normal flow with LLM (for NORMAL, HOOK stages)
        # ===================================================================
        
        # Detect scam type for specialized behavior
        scam_type = self._detect_scam_type(latest_message, conversation_history)
        
        # Get dynamic persona
        persona = self._get_dynamic_persona(session_id, scam_type)
        
        # Build conversation context (only from last 4 messages for brevity)
        history_text = ""
        if conversation_history:
            history_text = "\n".join([
                f"{'Them' if hasattr(msg, 'sender') and msg.sender == 'scammer' else 'Me'}: "
                f"{msg.text if hasattr(msg, 'text') else msg.get('text', '')}"
                for msg in conversation_history[-4:]
            ])
        
        # Select appropriate questions based on stage (limit to 2)
        stage_questions = persona["stage_questions"][:2]
        
        # Language instruction for LLM
        lang_instruction = "Respond in Hindi (Romanized/Hinglish)" if language == "hindi" else "Respond in English"
        
        # ==================================================================
        # SAFE LLM PROMPT - with explicit constraints
        # ==================================================================
        prompt = f"""You are playing a CONFUSED, NON-TECHNICAL victim in a scam honeypot.

ABSOLUTE RULES:
1. NEVER provide OTP, PIN, CVV, account numbers, or any codes
2. NEVER claim to be police, bank official, or any authority
3. ALWAYS deflect sensitive requests with excuses
4. {lang_instruction} - DO NOT switch languages
5. Keep response to 1-2 SENTENCES ONLY (MAX 30 words)

DEFLECTION EXCUSES:
- "My phone battery is low"
- "Let me ask my son first"
- "Can you repeat? Network is poor"

CONVERSATION:
{history_text if history_text else "(just started)"}

THEIR MESSAGE: "{latest_message}"

Ask ONE of these (pick the most relevant):
- {stage_questions[0] if stage_questions else "Who is this?"}

Generate 1-2 sentence response ONLY:"""

        max_attempts = 2
        for attempt in range(max_attempts):
            try:
                if not self.client:
                    return self._get_fallback_response_language(current_stage, language)
                
                response = self.client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {
                            "role": "system",
                            "content": f"You are a confused victim. {lang_instruction}. Keep responses to 1-2 sentences. NEVER provide codes or numbers."
                        },
                        {"role": "user", "content": prompt}
                    ],
                    temperature=0.6,
                    max_tokens=60  # Enforce short responses
                )
                
                reply = response.choices[0].message.content.strip()
                
                # Clean up response
                reply = reply.strip('"\'')
                if reply.startswith("Me:"):
                    reply = reply[3:].strip()
                
                # ===================================================================
                # LENGTH ENFORCEMENT: Truncate to 2 sentences max
                # ===================================================================
                reply = self._enforce_length_limit(reply)
                
                # ===========================================================
                # SAFETY VALIDATION - Block unsafe content
                # ===========================================================
                is_safe, violations, _ = SafetyValidator.validate_output(reply)
                
                if is_safe:
                    # Track the question intent
                    intent = self._extract_intent_from_response(reply)
                    session.add_question(reply, intent)
                    
                    logger.info(f"✅ Agent response ({language}): {reply[:50]}...")
                    return reply
                else:
                    logger.warning(f"⚠️ Attempt {attempt + 1}: Unsafe content blocked.")
                    if attempt < max_attempts - 1:
                        continue
                    else:
                        return self._get_fallback_response_language(current_stage, language)
                
            except Exception as e:
                logger.error(f"Agent response error: {e}")
                return self._get_fallback_response_language(current_stage, language)
        
        return self._get_fallback_response_language(current_stage, language)
    
    async def _generate_post_detection_response(
        self,
        scammer_message: str,
        extraction_question: str,
        language: str,
        session,
        stage: ScamStage
    ) -> str:
        """
        Generate post-detection response with extraction question.
        
        Uses minimal LLM to add natural variation, but falls back to template.
        Response is always 1-2 sentences with the extraction question.
        """
        # Get language templates
        templates = self.language_templates.get(language, self.language_templates["hindi"])
        
        # Try LLM for natural variation
        if self.client:
            try:
                lang_instruction = "Hindi (Romanized)" if language == "hindi" else "English"
                prompt = f"""You are a confused victim. Generate a 1-2 sentence response in {lang_instruction}.

Their message: "{scammer_message[:100]}"

Your response MUST:
1. Show slight confusion
2. End with this question: "{extraction_question}"

Generate response (1-2 sentences only):"""

                response = self.client.chat.completions.create(
                    model=self.model,
                    messages=[{"role": "user", "content": prompt}],
                    temperature=0.5,
                    max_tokens=50
                )
                
                reply = response.choices[0].message.content.strip().strip('"\'')
                reply = self._enforce_length_limit(reply)
                
                # Validate safety
                is_safe, _, _ = SafetyValidator.validate_output(reply)
                if is_safe:
                    return reply
                    
            except Exception as e:
                logger.warning(f"Post-detection LLM failed: {e}")
        
        # Fallback: Use template + extraction question
        confusion = random.choice(templates["confusion"])
        return f"{confusion} {extraction_question}"
    
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
    
    def _extract_intent_from_response(self, response: str) -> str:
        """
        Extract the intent/question type from an agent response.
        Used for anti-loop tracking.
        """
        response_lower = response.lower()
        
        intent_patterns = {
            "identity": ["naam", "name", "who", "kaun", "kon"],
            "payment_method": ["upi", "transfer", "payment", "paise", "paisa", "bhej"],
            "contact": ["call", "phone", "number", "whatsapp"],
            "process": ["app", "link", "download", "step", "kaise"],
            "account": ["account", "bank", "ifsc"],
            "verification": ["verify", "confirm", "check"],
        }
        
        for intent, keywords in intent_patterns.items():
            if any(kw in response_lower for kw in keywords):
                return intent
        
        return "generic"
    
    def _get_fallback_response_language(self, stage: ScamStage, language: str) -> str:
        """
        Get fallback response in the locked language.
        """
        templates = self.language_templates.get(language, self.language_templates["hindi"])
        
        if stage == ScamStage.NORMAL:
            return random.choice(templates["confusion"])
        elif stage in [ScamStage.HOOK, ScamStage.TRUST]:
            options = templates["confusion"] + templates["stalling"]
            return random.choice(options)
        elif stage in [ScamStage.THREAT, ScamStage.ACTION, ScamStage.CONFIRMED]:
            options = templates["extraction"] + templates["stalling"]
            return random.choice(options)
        else:
            return random.choice(templates["confusion"])
    
    def _get_fallback_response(self, stage: ScamStage, persona: Dict) -> str:
        """
        Get fallback response when LLM fails.
        SAFETY: Never use compliance templates.
        """
        # Select template based on stage - NEVER use compliance
        if stage == ScamStage.NORMAL:
            templates = self.templates["confusion"]
        elif stage == ScamStage.HOOK:
            templates = self.templates["confusion"] + self.templates["stalling"]
        elif stage == ScamStage.TRUST:
            templates = self.templates["concern"] + self.templates["stalling"]
        elif stage == ScamStage.THREAT:
            templates = self.templates["deflection"] + self.templates["concern"]
        elif stage in [ScamStage.ACTION, ScamStage.CONFIRMED]:
            # CRITICAL: Use deflection + extraction, NOT compliance
            templates = self.templates["deflection"] + self.templates["extraction"]
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
