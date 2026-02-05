"""
RISK SCORING ENGINE - Bounded cumulative risk calculation with hard/soft rules
REFACTORED for MATHEMATICAL SOUNDNESS and EXPLAINABILITY

KEY SAFETY & QUALITY RULES:
1. Risk score is BOUNDED: 0-100 (never unbounded)
2. Risk is CUMULATIVE but CLAMPED: never exceeds 100
3. Hard rules IMMEDIATELY set scamDetected = True
4. Every risk change is LOGGED with explanation
5. Stage transitions are EXPLICIT and TRACEABLE

RISK THRESHOLDS (Explainable):
- 0-24:   NORMAL - No suspicious activity
- 25-49:  SUSPICIOUS/HOOK - Initial red flags
- 50-69:  THREAT - Clear scam indicators
- 70-100: CONFIRMED - Definitive scam

SCORING MATH:
riskScore = min(riskScore + delta, 100)
This ensures bounded, predictable scoring.
"""

import re
import logging
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ScamStage(str, Enum):
    """Explicit scam progression stages: HOOK → TRUST → THREAT → ACTION"""
    NORMAL = "NORMAL"
    HOOK = "HOOK"
    TRUST = "TRUST"
    THREAT = "THREAT"
    ACTION = "ACTION"
    CONFIRMED = "CONFIRMED"


class EmotionalState(str, Enum):
    """Dynamic emotional states for agent persona"""
    NEUTRAL = "neutral"
    CONFUSED = "confused"
    CONCERNED = "concerned"
    ANXIOUS = "anxious"
    SCARED = "scared"
    PANICKED = "panicked"
    COMPLIANT = "compliant"


class SignalCategory(str, Enum):
    """Categories of risk signals"""
    URGENCY = "urgency"
    THREAT = "threat"
    AUTHORITY = "authority"
    FINANCIAL = "financial"
    PERSONAL_INFO = "personal_info"
    PHISHING = "phishing"
    BEHAVIORAL = "behavioral"
    OTP_REQUEST = "otp_request"
    PAYMENT_REQUEST = "payment_request"
    QR_CODE = "qr_code"
    REMOTE_ACCESS = "remote_access"
    ML_DETECTION = "ml_detection"
    LLM_DETECTION = "llm_detection"


@dataclass
class TriggeredSignal:
    """Individual signal triggered in a turn"""
    signal_type: str
    signal_name: str
    score: int
    is_hard_rule: bool
    source: str  # "rule", "ml", "llm"
    turn_number: int
    description: str = ""
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class LLMJudgement:
    """LLM reasoning output for a turn"""
    turn_number: int
    is_scam_likely: bool
    confidence: float
    scam_type: Optional[str]
    reasoning: str
    risk_boost: int
    stage_suggestion: Optional[ScamStage]
    red_flags: List[str]
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class PersonaState:
    """Dynamic persona state that drifts during conversation"""
    base_persona: str = "middle-class Indian citizen"
    current_emotion: EmotionalState = EmotionalState.NEUTRAL
    emotion_history: List[EmotionalState] = field(default_factory=list)
    trust_level: float = 0.5
    compliance_level: float = 0.3
    
    def drift_emotion(self, new_emotion: EmotionalState):
        self.emotion_history.append(self.current_emotion)
        self.current_emotion = new_emotion
    
    def increase_compliance(self, amount: float = 0.1):
        self.compliance_level = min(1.0, self.compliance_level + amount)


@dataclass
class HardRule:
    """Hard rule that immediately confirms scam"""
    name: str
    pattern: re.Pattern
    score: int
    category: SignalCategory
    description: str


@dataclass
class SoftRule:
    """Soft rule that contributes to cumulative score"""
    name: str
    keywords: List[str]
    score: int
    category: SignalCategory
    description: str


class SessionState:
    """
    Complete session state for stateful scam detection.
    
    KEY DESIGN:
    1. riskScore is CUMULATIVE - never resets
    2. scamStage tracks progression explicitly
    3. scamDetected set by hard rules OR threshold
    4. triggeredSignals tracked per turn
    5. LLM judgements stored for analysis
    6. Persona state drifts dynamically
    """
    
    def __init__(self, session_id: str):
        self.session_id = session_id
        
        # Core detection state
        self.risk_score: int = 0
        self.scam_stage: ScamStage = ScamStage.NORMAL
        self.scam_detected: bool = False
        self.hard_rule_triggered: bool = False
        
        # Turn tracking
        self.turn_count: int = 0
        
        # Signal history
        self.triggered_signals: List[TriggeredSignal] = []
        self.signals_by_turn: Dict[int, List[TriggeredSignal]] = {}
        
        # LLM judgement history
        self.llm_judgements: List[LLMJudgement] = []
        
        # Intelligence extraction
        self.upi_ids: List[str] = []
        self.bank_accounts: List[str] = []
        self.phone_numbers: List[str] = []
        self.phishing_links: List[str] = []
        self.suspicious_keywords: List[str] = []
        
        # Persona state
        self.persona_state: PersonaState = PersonaState()
        
        # Mission tracking
        self.mission_complete: bool = False
        self.callback_sent: bool = False
        
        # Stage history
        self.stage_history: List[tuple] = []
        self.created_at: datetime = datetime.now()
    
    def add_risk(self, score: int, reason: str = ""):
        """
        Add risk score - CUMULATIVE but BOUNDED to 100.
        
        MATHEMATICAL SOUNDNESS (Problem #4, #9):
        - Score is added cumulatively (never resets)
        - Final score is clamped: min(current + delta, 100)
        - Every change is logged with reason for explainability
        """
        old_score = self.risk_score
        # BOUNDED: Clamp to maximum 100
        self.risk_score = min(self.risk_score + score, 100)
        
        # Log the change for explainability
        if reason:
            logger.info(
                f"📊 Risk: {old_score} → {self.risk_score} (+{score}) | {reason}"
            )
        
        self._check_risk_thresholds()
    
    def _check_risk_thresholds(self):
        """
        Update scam stage based on risk thresholds.
        
        THRESHOLD MAPPING (Problem #9 - Explainable):
        - 0-24:   NORMAL  (no action)
        - 25-49:  HOOK    (initial suspicion)
        - 50-69:  THREAT  (confirmed tactics)
        - 70-100: CONFIRMED (definitive scam)
        """
        if self.risk_score >= 70:
            if self.scam_stage != ScamStage.CONFIRMED:
                self._transition_stage(ScamStage.CONFIRMED)
            self.scam_detected = True
        elif self.risk_score >= 50:
            if self.scam_stage not in [ScamStage.THREAT, ScamStage.ACTION, ScamStage.CONFIRMED]:
                self._transition_stage(ScamStage.THREAT)
        elif self.risk_score >= 25:
            if self.scam_stage == ScamStage.NORMAL:
                self._transition_stage(ScamStage.HOOK)
    
    def trigger_hard_rule(self, rule_name: str, score: int):
        """
        Hard rules IMMEDIATELY set scamDetected = True.
        
        HARD RULE DESIGN (Problem #11):
        - Immediate detection, no threshold needed
        - Logs the trigger for audit trail
        - Transitions to ACTION stage
        """
        self.hard_rule_triggered = True
        self.scam_detected = True
        
        logger.warning(f"🚨 HARD RULE TRIGGERED: {rule_name}")
        
        self.add_risk(score, f"HARD RULE: {rule_name}")
        if self.scam_stage not in [ScamStage.ACTION, ScamStage.CONFIRMED]:
            self._transition_stage(ScamStage.ACTION)
    
    def _transition_stage(self, new_stage: ScamStage):
        """
        Record stage transition with logging.
        
        EXPLAINABILITY: Every stage change is logged with timestamp.
        """
        old_stage = self.scam_stage
        self.stage_history.append((self.scam_stage, self.turn_count, datetime.now()))
        self.scam_stage = new_stage
        
        logger.info(f"📈 Stage: {old_stage.value} → {new_stage.value}")
        
        self._update_persona_for_stage()
    
    def _update_persona_for_stage(self):
        """Update persona emotion based on current scam stage"""
        stage_emotions = {
            ScamStage.NORMAL: EmotionalState.NEUTRAL,
            ScamStage.HOOK: EmotionalState.CONFUSED,
            ScamStage.TRUST: EmotionalState.CONCERNED,
            ScamStage.THREAT: EmotionalState.ANXIOUS,
            ScamStage.ACTION: EmotionalState.SCARED,
            ScamStage.CONFIRMED: EmotionalState.COMPLIANT,
        }
        new_emotion = stage_emotions.get(self.scam_stage, EmotionalState.NEUTRAL)
        self.persona_state.drift_emotion(new_emotion)
        if self.scam_stage in [ScamStage.THREAT, ScamStage.ACTION, ScamStage.CONFIRMED]:
            self.persona_state.increase_compliance(0.15)
    
    def add_signal(self, signal: TriggeredSignal):
        """Add a triggered signal and update risk"""
        self.triggered_signals.append(signal)
        if signal.turn_number not in self.signals_by_turn:
            self.signals_by_turn[signal.turn_number] = []
        self.signals_by_turn[signal.turn_number].append(signal)
        self.add_risk(signal.score, signal.description)
        if signal.is_hard_rule:
            self.trigger_hard_rule(signal.signal_name, 0)
    
    def add_llm_judgement(self, judgement: LLMJudgement):
        """Add LLM judgement - MUST influence decision"""
        self.llm_judgements.append(judgement)
        if judgement.risk_boost > 0:
            self.add_risk(judgement.risk_boost, f"LLM: {judgement.reasoning[:50]}")
        if judgement.stage_suggestion and judgement.confidence >= 0.7:
            stage_priority = [ScamStage.NORMAL, ScamStage.HOOK, ScamStage.TRUST,
                             ScamStage.THREAT, ScamStage.ACTION, ScamStage.CONFIRMED]
            current_priority = stage_priority.index(self.scam_stage)
            suggested_priority = stage_priority.index(judgement.stage_suggestion)
            if suggested_priority > current_priority:
                self._transition_stage(judgement.stage_suggestion)
        if judgement.is_scam_likely and judgement.confidence >= 0.85:
            self.scam_detected = True
    
    def update_stage_from_patterns(self, detected_patterns: List[str]):
        """Update scam stage based on conversation patterns"""
        pattern_stage_map = {
            "greeting": ScamStage.HOOK, "introduction": ScamStage.HOOK, "authority_claim": ScamStage.HOOK,
            "verification": ScamStage.TRUST, "procedure": ScamStage.TRUST, "credibility": ScamStage.TRUST,
            "urgency": ScamStage.THREAT, "consequence": ScamStage.THREAT, "fear": ScamStage.THREAT,
            "payment_request": ScamStage.ACTION, "otp_request": ScamStage.ACTION, "link_share": ScamStage.ACTION,
        }
        stage_priority = [ScamStage.NORMAL, ScamStage.HOOK, ScamStage.TRUST, 
                         ScamStage.THREAT, ScamStage.ACTION, ScamStage.CONFIRMED]
        current_priority = stage_priority.index(self.scam_stage)
        for pattern in detected_patterns:
            if pattern in pattern_stage_map:
                suggested = pattern_stage_map[pattern]
                if stage_priority.index(suggested) > current_priority:
                    self._transition_stage(suggested)
                    current_priority = stage_priority.index(suggested)
    
    def has_high_value_intel(self) -> bool:
        """Check if we have high-value intelligence"""
        return bool(self.upi_ids or self.bank_accounts or 
                   (len(self.phone_numbers) > 0 and len(self.phishing_links) > 0))
    
    def check_mission_complete(self) -> bool:
        """Check if mission is complete with explicit criteria"""
        if self.mission_complete:
            return True
        if not self.scam_detected:
            return False
        has_intel = self.has_high_value_intel()
        min_turns = self.turn_count >= 5
        action_signals = [s for s in self.triggered_signals 
                         if s.signal_type in ["financial", "otp_request", "payment_request"]]
        repeated_demands = len(action_signals) >= 3
        if has_intel and (min_turns or repeated_demands):
            self.mission_complete = True
            return True
        if self.turn_count >= 25:
            self.mission_complete = True
            return True
        return False
    
    def to_dict(self) -> Dict:
        """
        Convert state to dictionary for API responses.
        
        BOUNDED SCORE: risk_score is guaranteed 0-100
        """
        return {
            "session_id": self.session_id,
            "risk_score": self.risk_score,  # Guaranteed 0-100
            "risk_score_max": 100,  # For UI display purposes
            "scam_stage": self.scam_stage.value,
            "scam_detected": self.scam_detected,
            "hard_rule_triggered": self.hard_rule_triggered,
            "turn_count": self.turn_count,
            "signals_count": len(self.triggered_signals),
            "upi_ids": self.upi_ids,
            "bank_accounts": self.bank_accounts,
            "phone_numbers": self.phone_numbers,
            "persona_emotion": self.persona_state.current_emotion.value,
            "mission_complete": self.mission_complete,
        }


class CumulativeRiskEngine:
    """
    Production-grade cumulative risk scoring engine.
    
    KEY DESIGN:
    1. Risk NEVER resets - accumulates across all turns
    2. Hard rules IMMEDIATELY set scamDetected = True
    3. Clear thresholds: ≥25 SUSPICIOUS, ≥50 THREAT, ≥70 CONFIRMED
    """
    
    THRESHOLD_SUSPICIOUS = 25
    THRESHOLD_THREAT = 50
    THRESHOLD_CONFIRMED = 70
    
    def __init__(self):
        self.sessions: Dict[str, SessionState] = {}
        self._init_hard_rules()
        self._init_soft_rules()
        self._init_stage_patterns()
    
    def get_or_create_session(self, session_id: str) -> SessionState:
        """Get existing session or create new one"""
        if session_id not in self.sessions:
            self.sessions[session_id] = SessionState(session_id)
        return self.sessions[session_id]
    
    def get_session(self, session_id: str) -> Optional[SessionState]:
        """Get existing session, return None if not found"""
        return self.sessions.get(session_id)
    
    def _init_hard_rules(self):
        """HARD RULES - Immediately confirm scam"""
        self.hard_rules: List[HardRule] = [
            HardRule(
                name="otp_share_request",
                pattern=re.compile(
                    r'\b(?:share|send|tell|give|provide|forward|enter)[\s\w]{0,10}'
                    r'(?:otp|o\.t\.p|one[\s-]?time[\s-]?password|verification[\s-]?code|'
                    r'auth(?:entication)?[\s-]?code|security[\s-]?code|pin|cvv)\b',
                    re.IGNORECASE
                ),
                score=35,
                category=SignalCategory.OTP_REQUEST,
                description="Explicit request to share OTP/verification code"
            ),
            HardRule(
                name="otp_on_phone",
                pattern=re.compile(
                    r'\b(?:otp|code)[\s\w]{0,15}(?:received|came|sent|got|on your phone|message)\b',
                    re.IGNORECASE
                ),
                score=30,
                category=SignalCategory.OTP_REQUEST,
                description="Reference to OTP sent to victim's phone"
            ),
            HardRule(
                name="upi_pin_request",
                pattern=re.compile(
                    r'\b(?:enter|share|tell|give|type|input)[\s\w]{0,10}'
                    r'(?:upi[\s-]?pin|mpin|m\.pin)\b',
                    re.IGNORECASE
                ),
                score=40,
                category=SignalCategory.FINANCIAL,
                description="Request for UPI PIN"
            ),
            HardRule(
                name="qr_receive_money",
                pattern=re.compile(
                    r'\b(?:scan|accept)[\s\w]{0,15}(?:qr|code)[\s\w]{0,15}'
                    r'(?:receive|get|claim|credit)\b|\b(?:receive|get)[\s\w]{0,15}'
                    r'(?:money|amount|payment)[\s\w]{0,15}(?:scan|qr)\b',
                    re.IGNORECASE
                ),
                score=35,
                category=SignalCategory.QR_CODE,
                description="QR code scam - scan to receive money"
            ),
            HardRule(
                name="qr_approve",
                pattern=re.compile(
                    r'\b(?:approve|accept|confirm)[\s\w]{0,10}(?:payment|request|qr)\b',
                    re.IGNORECASE
                ),
                score=30,
                category=SignalCategory.QR_CODE,
                description="Request to approve payment"
            ),
            HardRule(
                name="remote_access_request",
                pattern=re.compile(
                    r'\b(?:install|download|open)[\s\w]{0,15}'
                    r'(?:anydesk|teamviewer|quick[\s-]?support|ammyy|ultraviewer|'
                    r'screen[\s-]?share|remote[\s-]?access|airdroid)\b',
                    re.IGNORECASE
                ),
                score=40,
                category=SignalCategory.REMOTE_ACCESS,
                description="Request to install remote access software"
            ),
            HardRule(
                name="remote_access_code",
                pattern=re.compile(
                    r'\b(?:anydesk|teamviewer)[\s\w]{0,10}(?:code|id|number)\b|'
                    r'\b(?:9|10)[\s-]?digit[\s-]?code\b',
                    re.IGNORECASE
                ),
                score=35,
                category=SignalCategory.REMOTE_ACCESS,
                description="Request for remote access code"
            ),
            HardRule(
                name="transfer_money_request",
                pattern=re.compile(
                    r'\b(?:transfer|send|pay|deposit)[\s\w]{0,15}'
                    r'(?:rs\.?|₹|rupees?|amount|money)[\s\w]{0,10}'
                    r'(?:\d{2,}|to[\s\w]+account|immediately|now|urgent)\b',
                    re.IGNORECASE
                ),
                score=30,
                category=SignalCategory.PAYMENT_REQUEST,
                description="Direct money transfer request"
            ),
            HardRule(
                name="fee_request",
                pattern=re.compile(
                    r'\b(?:processing|registration|service|insurance|verification|'
                    r'security|token|advance|handling)[\s-]?fee\b',
                    re.IGNORECASE
                ),
                score=28,
                category=SignalCategory.FINANCIAL,
                description="Request for processing/registration fee"
            ),
            HardRule(
                name="card_pin_request",
                pattern=re.compile(
                    r'\b(?:atm|debit|credit|card)[\s\w]{0,10}(?:pin|cvv|number)\b|'
                    r'\b(?:share|tell|give)[\s\w]{0,10}(?:pin|cvv)\b',
                    re.IGNORECASE
                ),
                score=40,
                category=SignalCategory.FINANCIAL,
                description="Request for card PIN/CVV"
            ),
            HardRule(
                name="phishing_url",
                pattern=re.compile(
                    r'http[s]?://(?:[\w-]+\.)*(?:tk|ml|ga|cf|gq|herokuapp\.com|'
                    r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})'
                    r'[/\w\-\._~:/?#\[\]@!$&\'()*+,;=%]*',
                    re.IGNORECASE
                ),
                score=35,
                category=SignalCategory.PHISHING,
                description="Suspicious/phishing URL detected"
            ),
        ]
    
    def _init_soft_rules(self):
        """SOFT RULES - Contribute to cumulative score"""
        self.soft_rules: List[SoftRule] = [
            SoftRule(
                name="high_urgency",
                keywords=["immediately", "right now", "urgent", "asap", "hurry",
                         "within 24 hours", "within 2 hours", "last warning", 
                         "final notice", "deadline today", "expires today",
                         "time sensitive", "don't delay", "act now"],
                score=12,
                category=SignalCategory.URGENCY,
                description="High urgency language"
            ),
            SoftRule(
                name="medium_urgency",
                keywords=["soon", "quickly", "fast", "deadline", "limited time"],
                score=8,
                category=SignalCategory.URGENCY,
                description="Medium urgency language"
            ),
            SoftRule(
                name="account_threat",
                keywords=["account blocked", "account suspended", "account terminated",
                         "account frozen", "account deactivated", "account compromised",
                         "account hacked", "unauthorized access", "suspicious activity"],
                score=18,
                category=SignalCategory.THREAT,
                description="Account threat/suspension"
            ),
            SoftRule(
                name="legal_threat",
                keywords=["legal action", "court case", "police complaint", "fir",
                         "arrest warrant", "jail", "imprisoned", "criminal case",
                         "cyber crime", "prosecution", "investigation"],
                score=22,
                category=SignalCategory.THREAT,
                description="Legal/criminal threat"
            ),
            SoftRule(
                name="financial_threat",
                keywords=["penalty", "fine", "charge", "loss", "fraud detected",
                         "money at risk", "savings at risk", "seized"],
                score=15,
                category=SignalCategory.THREAT,
                description="Financial threat"
            ),
            SoftRule(
                name="gov_authority",
                keywords=["rbi", "reserve bank", "income tax", "it department",
                         "customs", "government", "ministry", "trai", "sebi",
                         "enforcement directorate", "ed", "cbi"],
                score=20,
                category=SignalCategory.AUTHORITY,
                description="Government authority impersonation"
            ),
            SoftRule(
                name="police_authority",
                keywords=["police", "cyber cell", "cyber crime", "investigation officer",
                         "inspector", "commissioner"],
                score=22,
                category=SignalCategory.AUTHORITY,
                description="Police/law enforcement impersonation"
            ),
            SoftRule(
                name="bank_authority",
                keywords=["bank manager", "customer care", "security team",
                         "fraud department", "bank official", "authorized representative"],
                score=15,
                category=SignalCategory.AUTHORITY,
                description="Bank authority impersonation"
            ),
            SoftRule(
                name="money_mention",
                keywords=["refund", "cashback", "prize money", "lottery", "winner",
                         "claim reward", "bonus", "compensation"],
                score=12,
                category=SignalCategory.FINANCIAL,
                description="Money/reward mention"
            ),
            SoftRule(
                name="payment_terms",
                keywords=["bank details", "account number", "transfer", "payment",
                         "pay now", "emi", "loan", "credit", "insurance"],
                score=10,
                category=SignalCategory.FINANCIAL,
                description="Payment terminology"
            ),
            SoftRule(
                name="identity_request",
                keywords=["aadhaar", "aadhar", "pan card", "pan number",
                         "date of birth", "dob", "kyc", "verify identity"],
                score=15,
                category=SignalCategory.PERSONAL_INFO,
                description="Identity document request"
            ),
            SoftRule(
                name="credential_request",
                keywords=["password", "login details", "credentials",
                         "security question", "mother's maiden name"],
                score=18,
                category=SignalCategory.PERSONAL_INFO,
                description="Credential request"
            ),
            SoftRule(
                name="link_action",
                keywords=["click here", "click the link", "click this link",
                         "visit this link", "open link", "tap here"],
                score=14,
                category=SignalCategory.PHISHING,
                description="Link click request"
            ),
            SoftRule(
                name="app_install",
                keywords=["download app", "install app", "install application",
                         "download from", "get this app"],
                score=16,
                category=SignalCategory.PHISHING,
                description="App installation request"
            ),
            SoftRule(
                name="evasion",
                keywords=["can't tell you", "confidential", "security reasons",
                         "protocol", "procedure", "policy doesn't allow"],
                score=10,
                category=SignalCategory.BEHAVIORAL,
                description="Evasive behavior"
            ),
            SoftRule(
                name="pressure",
                keywords=["trust me", "believe me", "i promise", "guaranteed",
                         "100%", "no risk", "safe", "secure", "verified process"],
                score=8,
                category=SignalCategory.BEHAVIORAL,
                description="Trust pressure"
            ),
        ]
    
    def _init_stage_patterns(self):
        """Patterns that indicate scam stage progression"""
        self.stage_patterns = {
            "greeting": re.compile(r'\b(?:hello|hi|dear|sir|madam|good\s+(?:morning|afternoon|evening))\b', re.I),
            "introduction": re.compile(r'\b(?:i\s+am|this\s+is|calling\s+from|speaking\s+from|on\s+behalf)\b', re.I),
            "authority_claim": re.compile(r'\b(?:from\s+(?:bank|rbi|police|customs|government)|official|department)\b', re.I),
            "verification": re.compile(r'\b(?:verify|confirm|validate|check|update)\s+(?:your|account|details)\b', re.I),
            "procedure": re.compile(r'\b(?:procedure|process|step|follow|simple|easy)\b', re.I),
            "credibility": re.compile(r'\b(?:authorized|official|verified|genuine|legitimate)\b', re.I),
            "urgency": re.compile(r'\b(?:urgent|immediate|right\s+now|asap|quickly)\b', re.I),
            "consequence": re.compile(r'\b(?:blocked|suspended|frozen|terminated|legal|penalty|fine)\b', re.I),
            "fear": re.compile(r'\b(?:arrest|jail|court|police|complaint|case|fraud)\b', re.I),
            "deadline": re.compile(r'\b(?:within\s+\d+|today|deadline|expires|last\s+chance)\b', re.I),
            "payment_request": re.compile(r'\b(?:pay|transfer|send|deposit)\s+(?:money|amount|rs|₹)\b', re.I),
            "otp_request": re.compile(r'\b(?:share|send|tell|give)\s+(?:otp|code|pin)\b', re.I),
            "link_share": re.compile(r'\b(?:click|open|visit|download)\s+(?:link|app|here)\b', re.I),
            "info_request": re.compile(r'\b(?:provide|share|tell|give)\s+(?:details|number|information)\b', re.I),
        }
    
    def analyze_message(
        self, 
        message: str, 
        session_id: str,
        turn_number: int
    ) -> Tuple[List[TriggeredSignal], int, bool]:
        """
        Analyze a single message for risk signals.
        Returns: (signals, message_score, hard_rule_triggered)
        """
        signals: List[TriggeredSignal] = []
        message_score = 0
        hard_rule_triggered = False
        message_lower = message.lower()
        
        # Check HARD RULES first - IMMEDIATE DETECTION (Problem #11)
        for rule in self.hard_rules:
            if rule.pattern.search(message):
                hard_rule_triggered = True
                signal = TriggeredSignal(
                    signal_type=rule.category.value,
                    signal_name=rule.name,
                    score=rule.score,
                    is_hard_rule=True,
                    source="rule",
                    turn_number=turn_number,
                    description=rule.description
                )
                signals.append(signal)
                message_score += rule.score
        
        # Check SOFT RULES - CUMULATIVE (Problem #3)
        for rule in self.soft_rules:
            matches = [kw for kw in rule.keywords if kw.lower() in message_lower]
            if matches:
                scaled_score = min(rule.score * (1 + len(matches) * 0.2), rule.score * 2)
                signal = TriggeredSignal(
                    signal_type=rule.category.value,
                    signal_name=rule.name,
                    score=int(scaled_score),
                    is_hard_rule=False,
                    source="rule",
                    turn_number=turn_number,
                    description=f"{rule.description}: {', '.join(matches[:3])}"
                )
                signals.append(signal)
                message_score += int(scaled_score)
        
        return signals, message_score, hard_rule_triggered
    
    def detect_stage_patterns(self, message: str) -> List[str]:
        """Detect which stage patterns are present in message"""
        detected = []
        for pattern_name, pattern in self.stage_patterns.items():
            if pattern.search(message):
                detected.append(pattern_name)
        return detected
    
    def apply_signals_to_session(
        self, 
        session_id: str, 
        signals: List[TriggeredSignal],
        hard_rule_triggered: bool
    ) -> SessionState:
        """Apply detected signals to session state - CUMULATIVE"""
        session = self.get_or_create_session(session_id)
        for signal in signals:
            session.add_signal(signal)
        if hard_rule_triggered:
            session.scam_detected = True
            session.hard_rule_triggered = True
        return session
    
    def apply_ml_score(
        self, 
        session_id: str,
        ml_confidence: float,
        ml_is_scam: bool,
        features: List[str],
        turn_number: int
    ):
        """Apply ML prediction as signal (Problem #12 - influences, doesn't override)"""
        if not ml_is_scam or ml_confidence < 0.6:
            return
        
        if ml_confidence >= 0.9:
            score = 25
        elif ml_confidence >= 0.8:
            score = 18
        elif ml_confidence >= 0.7:
            score = 12
        else:
            score = 8
        
        signal = TriggeredSignal(
            signal_type=SignalCategory.ML_DETECTION.value,
            signal_name="ml_classifier",
            score=score,
            is_hard_rule=False,
            source="ml",
            turn_number=turn_number,
            description=f"ML confidence {ml_confidence:.2f}"
        )
        session = self.get_or_create_session(session_id)
        session.add_signal(signal)
    
    def apply_llm_judgement(
        self,
        session_id: str,
        judgement: LLMJudgement
    ):
        """Apply LLM reasoning judgement (Problem #4 - must influence)"""
        session = self.get_or_create_session(session_id)
        session.add_llm_judgement(judgement)
    
    def get_risk_assessment(self, session_id: str) -> Dict:
        """Get current risk assessment for session"""
        session = self.get_or_create_session(session_id)
        return {
            "risk_score": session.risk_score,
            "scam_stage": session.scam_stage.value,
            "scam_detected": session.scam_detected,
            "hard_rule_triggered": session.hard_rule_triggered,
            "turn_count": session.turn_count,
            "total_signals": len(session.triggered_signals),
        }
    
    def increment_turn(self, session_id: str):
        """Increment turn counter for session"""
        session = self.get_or_create_session(session_id)
        session.turn_count += 1


# Singleton instance
risk_engine = CumulativeRiskEngine()
