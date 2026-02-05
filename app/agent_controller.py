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
        """
        session_id = session_id or "default"
        
        # Get session state - THIS drives behavior, not scam_detected param
        session = risk_engine.get_or_create_session(session_id)
        current_stage = session.scam_stage
        
        # Detect scam type for specialized behavior
        scam_type = self._detect_scam_type(latest_message, conversation_history)
        
        # Get dynamic persona
        persona = self._get_dynamic_persona(session_id, scam_type)
        
        # Build conversation context (only from last 6 messages)
        history_text = ""
        if conversation_history:
            history_text = "\n".join([
                f"{'Them' if hasattr(msg, 'sender') and msg.sender == 'scammer' else 'Me'}: "
                f"{msg.text if hasattr(msg, 'text') else msg.get('text', '')}"
                for msg in conversation_history[-6:]
            ])
        
        # Select appropriate questions based on stage
        stage_questions = persona["stage_questions"]
        
        # ==================================================================
        # SAFE LLM PROMPT - with explicit ethical constraints
        # ==================================================================
        prompt = f"""You are an AI agent playing a CONFUSED, NON-TECHNICAL victim in a scam honeypot.

═══════════════════════════════════════════════════════════════════════════════
ABSOLUTE SAFETY RULES (NEVER VIOLATE):
═══════════════════════════════════════════════════════════════════════════════
1. NEVER provide ANY numbers: OTP, PIN, CVV, account numbers, card numbers
2. NEVER share bank account details, UPI IDs, or IFSC codes
3. NEVER claim to be police, CID, bank official, or any authority
4. NEVER say you have transferred money or sent payment
5. NEVER fabricate FIR numbers, case numbers, or reference IDs
6. ALWAYS deflect sensitive requests with realistic excuses

YOUR SAFE DEFLECTION STRATEGIES:
- "I need to ask my son/husband first"
- "My phone battery is low"
- "Can you repeat that? The network is poor"
- "Let me verify this with my bank first"
- "I don't have that information with me right now"
- "Someone is at the door, one minute"

═══════════════════════════════════════════════════════════════════════════════
YOUR CHARACTER:
═══════════════════════════════════════════════════════════════════════════════
- {persona['base']} - {persona['detail']}
- Current emotion: {persona['emotion']}
- Tone: {persona['tone']}
- Strategy: {persona['strategy']}

SCAM TYPE DETECTED: {scam_type}
CURRENT STAGE: {current_stage.value}

═══════════════════════════════════════════════════════════════════════════════
CONVERSATION:
═══════════════════════════════════════════════════════════════════════════════
{history_text if history_text else "(conversation just started)"}

THEIR LATEST MESSAGE: "{latest_message}"

═══════════════════════════════════════════════════════════════════════════════
YOUR GOAL:
═══════════════════════════════════════════════════════════════════════════════
Extract THEIR information by asking questions like:
{chr(10).join(f'- {q}' for q in stage_questions[:3])}

Information to extract from THEM: {', '.join(persona['extraction_focus']) if persona['extraction_focus'] else 'their identity, contact details, account they want you to send to'}

Generate a response that:
1. DEFLECTS any request for sensitive information
2. Asks THEM to provide more details (their account, their name, their reference)
3. Uses realistic excuses to avoid complying
4. Sounds like an actual confused Indian person
5. Is 1-3 sentences maximum

Output ONLY the message text:"""

        max_attempts = 3
        for attempt in range(max_attempts):
            try:
                if not self.client:
                    return self._get_fallback_response(current_stage, persona)
                
                response = self.client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {
                            "role": "system",
                            "content": (
                                "You are playing a confused victim. NEVER provide any numbers, "
                                "codes, PINs, OTPs, or account details. NEVER impersonate police "
                                "or bank officials. Always deflect and ask THEM for details."
                            )
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
                
                # ===========================================================
                # SAFETY VALIDATION - Block unsafe content
                # ===========================================================
                is_safe, violations, _ = SafetyValidator.validate_output(reply)
                
                if is_safe:
                    logger.info(f"✅ Agent response validated: {reply[:50]}...")
                    return reply
                else:
                    # Log violation and retry
                    logger.warning(
                        f"⚠️ Attempt {attempt + 1}: Unsafe content blocked. "
                        f"Violations: {violations}"
                    )
                    if attempt < max_attempts - 1:
                        continue
                    else:
                        # After max attempts, use safe deflection
                        logger.warning("⚠️ Max attempts reached. Using safe deflection.")
                        return SafetyValidator.get_safe_deflection(current_stage)
                
            except Exception as e:
                logger.error(f"Agent response error: {e}")
                return self._get_fallback_response(current_stage, persona)
        
        return self._get_fallback_response(current_stage, persona)
    
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
