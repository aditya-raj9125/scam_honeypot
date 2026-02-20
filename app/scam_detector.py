"""
SCAM DETECTOR - LLM-FIRST detection pipeline
REWRITTEN for maximum accuracy

KEY DESIGN:
- LLM runs on EVERY turn as PRIMARY detector (no threshold gating)
- Comprehensive Indian scam type coverage
- Aggressive scoring - scams detected fast
- Rule-based signals as SECONDARY reinforcement
- ML classifier as TERTIARY confirmation
"""

import os
import json
import logging
from typing import Dict, List, Optional
from dotenv import load_dotenv
from groq import AsyncGroq

from .risk_engine import (
    risk_engine, ScamStage, LLMJudgement, 
    TriggeredSignal, SignalCategory
)
from .ml_detector import ml_detector

load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class LLMReasoningJudge:
    """
    LLM-based reasoning judge - PRIMARY detection mechanism.
    Runs on EVERY turn with full conversation context.
    """
    
    def __init__(self):
        self.groq_api_key = os.getenv("GROQ_API_KEY")
        self.client = AsyncGroq(api_key=self.groq_api_key) if self.groq_api_key else None
        self.model = os.getenv("GROQ_MODEL", "llama-3.1-8b-instant")
    
    async def judge(
        self,
        message: str,
        conversation_history: List[str],
        current_risk_score: int,
        current_stage: ScamStage,
        detected_signals: List[str],
        turn_number: int
    ) -> LLMJudgement:
        """
        LLM reasoning judge - runs on EVERY turn.
        This is the PRIMARY detection mechanism.
        """
        if not self.client:
            return self._fallback_judgement(turn_number, detected_signals, message)
        
        try:
            # Build full conversation context
            history_text = ""
            if conversation_history:
                history_text = "\n".join(
                    f"Message {i+1}: {msg}" 
                    for i, msg in enumerate(conversation_history[-8:])
                )
            
            signals_text = ", ".join(detected_signals[:8]) if detected_signals else "None yet"
            
            prompt = f"""You are an expert Indian fraud/scam analyst. Your job is to detect ALL types of scams with HIGH SENSITIVITY. It is MUCH worse to miss a scam than to have a false positive.

CONVERSATION HISTORY:
{history_text}

LATEST MESSAGE FROM SENDER: "{message}"

CURRENT STATE:
- Risk Score: {current_risk_score}/100
- Stage: {current_stage.value}
- Turn: {turn_number}
- Prior Signals: {signals_text}

COMMON INDIAN SCAM TYPES TO CHECK:
1. KYC/Bank Update Scam - "Your account will be blocked, update KYC"
2. OTP/PIN Fraud - Asking for OTP, UPI PIN, CVV, ATM PIN
3. UPI Scam - QR code scan, collect request, "pay to receive"
4. Police/CBI Impersonation - "Digital arrest", warrant, case filed
5. Customs/Courier Scam - Package stuck, pay customs duty
6. Loan/Credit Scam - Pre-approved loan, processing fee required
7. Job/Work-from-home Scam - Easy money, data entry, investment task
8. Lottery/Prize Scam - "You won", claim reward, pay tax
9. Refund/Cashback Scam - Excess payment, refund process
10. Tech Support Scam - Remote access (AnyDesk/TeamViewer)
11. Investment/Trading Scam - Guaranteed returns, crypto
12. Insurance Scam - Policy expiring, claim settlement
13. Electricity/Gas Bill Scam - "Bill overdue, connection cut"
14. Aadhaar/PAN Fraud - Identity document collection
15. Romance/Social Engineering - Building trust then asking money

DETECTION SIGNALS (check ALL):
- Is sender claiming to be from bank/police/government/company?
- Is there urgency or deadline pressure?
- Is there a threat (account block, arrest, legal action)?
- Is sender asking for money, OTP, PIN, personal info?
- Is sender sharing suspicious links or asking to install apps?
- Is the conversation pattern consistent with known scam scripts?
- Is sender avoiding questions or giving vague answers?
- Is there emotional manipulation (fear, greed, curiosity)?
- Even if message seems innocent, does it fit a HOOK pattern (initial contact for a scam)?

IMPORTANT RULES:
- Even FIRST messages like "Hello, I am calling from X bank" or "This is regarding your account" are HOOKS - mark as suspicious
- Messages asking to "verify", "update", "confirm" anything are HIGHLY suspicious
- Any message mentioning money, payment, transfer, fee is suspicious
- Authority claims (police, bank, government) are suspicious
- Be AGGRESSIVE in detection - it's better to flag legitimate messages than miss scams
- If the conversation shows ANY scam pattern across turns, confidence should be HIGH

Respond in this EXACT JSON format:
{{
    "is_scam_likely": true/false,
    "confidence": 0.0-1.0,
    "scam_type": "specific type or null",
    "reasoning": "one sentence explanation",
    "risk_boost": 0-40,
    "suggested_stage": "NORMAL|HOOK|TRUST|THREAT|ACTION|CONFIRMED|null",
    "red_flags": ["list", "of", "flags"]
}}

SCORING GUIDE:
- Any authority claim or identity mention → confidence ≥ 0.5, risk_boost ≥ 15
- Urgency + authority → confidence ≥ 0.7, risk_boost ≥ 25
- Request for OTP/PIN/money → confidence ≥ 0.9, risk_boost ≥ 35
- Threat + financial request → confidence ≥ 0.95, risk_boost ≥ 40
- Even subtle hooks → confidence ≥ 0.3, risk_boost ≥ 10"""

            response = await self.client.chat.completions.create(
                messages=[
                    {
                        "role": "system",
                        "content": "You are an aggressive Indian scam detection expert. Your priority is to NEVER MISS a scam. False positives are acceptable. Analyze every message assuming it COULD be a scam attempt. Output only valid JSON."
                    },
                    {"role": "user", "content": prompt}
                ],
                model=self.model,
                temperature=0.05,
                max_tokens=500
            )
            
            result_text = response.choices[0].message.content.strip()
            
            # Parse JSON response
            if "```" in result_text:
                result_text = result_text.split("```")[1]
                if result_text.startswith("json"):
                    result_text = result_text[4:]
                result_text = result_text.strip()
            
            result = json.loads(result_text)
            
            # Parse stage suggestion
            stage_suggestion = None
            if result.get("suggested_stage"):
                try:
                    stage_suggestion = ScamStage(result["suggested_stage"])
                except ValueError:
                    pass
            
            return LLMJudgement(
                turn_number=turn_number,
                is_scam_likely=result.get("is_scam_likely", False),
                confidence=result.get("confidence", 0.5),
                scam_type=result.get("scam_type"),
                reasoning=result.get("reasoning", ""),
                risk_boost=min(40, max(0, result.get("risk_boost", 0))),
                stage_suggestion=stage_suggestion,
                red_flags=result.get("red_flags", [])
            )
            
        except Exception as e:
            logger.error(f"LLM judge error: {e}")
            return self._fallback_judgement(turn_number, detected_signals, message)
    
    def _fallback_judgement(
        self, 
        turn_number: int, 
        detected_signals: List[str],
        message: str = ""
    ) -> LLMJudgement:
        """Enhanced fallback when LLM unavailable - aggressive heuristic"""
        msg_lower = message.lower() if message else ""
        
        # Aggressive keyword detection
        high_risk = ["otp", "pin", "payment", "transfer", "arrest", "block", 
                     "suspend", "verify", "kyc", "update", "urgent", "immediate",
                     "police", "bank", "account", "refund", "prize", "winner",
                     "loan", "aadhaar", "pan", "customs", "parcel", "warrant"]
        risk_count = sum(1 for hr in high_risk if hr in msg_lower)
        risk_count += sum(1 for s in detected_signals if any(hr in s.lower() for hr in high_risk))
        
        # Authority/identity patterns
        authority = ["i am from", "calling from", "this is", "speaking from",
                     "department", "officer", "manager", "executive", "representative"]
        auth_count = sum(1 for a in authority if a in msg_lower)
        
        total_risk = risk_count + auth_count * 2
        
        confidence = min(1.0, 0.3 + (total_risk * 0.12))
        risk_boost = min(40, total_risk * 8)
        
        return LLMJudgement(
            turn_number=turn_number,
            is_scam_likely=total_risk >= 1,
            confidence=confidence,
            scam_type=None,
            reasoning=f"Fallback: {total_risk} risk indicators detected",
            risk_boost=risk_boost,
            stage_suggestion=ScamStage.HOOK if total_risk >= 1 else None,
            red_flags=detected_signals[:5]
        )


class HybridScamDetector:
    """
    LLM-FIRST hybrid scam detection system.
    
    PIPELINE ORDER:
    1. Rule-based signal extraction (fast, parallel)
    2. LLM Reasoning Judge (PRIMARY - runs EVERY turn)
    3. ML Classifier (reinforcement)
    4. Decision Engine (combines all, aggressive)
    """
    
    def __init__(self):
        self.llm_judge = LLMReasoningJudge()
        self.ML_CONFIDENCE_THRESHOLD = 0.4  # Lowered from 0.6
    
    async def detect(
        self, 
        message_text: str, 
        conversation_history: list, 
        session_id: str = None
    ) -> Dict:
        """
        Main detection pipeline - LLM-first on EVERY turn.
        """
        session_id = session_id or "default"
        
        session = risk_engine.get_or_create_session(session_id)
        session.turn_count += 1
        turn_number = session.turn_count
        
        history_texts = self._extract_history_texts(conversation_history)
        
        # STEP 1: Rule-based signal extraction
        signals, message_score, hard_rule_triggered = risk_engine.analyze_message(
            message_text, session_id, turn_number
        )
        risk_engine.apply_signals_to_session(session_id, signals, hard_rule_triggered)
        
        # STEP 2: Stage pattern detection
        stage_patterns = risk_engine.detect_stage_patterns(message_text)
        session.update_stage_from_patterns(stage_patterns)
        
        # STEP 3: ML-based detection
        ml_result = await self._run_ml_detection(message_text, history_texts)
        if ml_result["is_scam"] and ml_result["confidence"] >= self.ML_CONFIDENCE_THRESHOLD:
            risk_engine.apply_ml_score(
                session_id,
                ml_result["confidence"],
                ml_result["is_scam"],
                ml_result.get("features_triggered", []),
                turn_number
            )
        
        # STEP 4: LLM Reasoning Judge - ALWAYS RUNS (PRIMARY DETECTOR)
        detected_signal_names = [s.signal_name for s in signals]
        llm_judgement = await self.llm_judge.judge(
            message=message_text,
            conversation_history=history_texts,
            current_risk_score=session.risk_score,
            current_stage=session.scam_stage,
            detected_signals=detected_signal_names,
            turn_number=turn_number
        )
        
        # Apply LLM judgement — PRIMARY influence
        risk_engine.apply_llm_judgement(session_id, llm_judgement)
        
        # STEP 5: Decision Engine
        result = self._make_decision(
            session=session,
            signals=signals,
            hard_rule_triggered=hard_rule_triggered,
            ml_result=ml_result,
            llm_judgement=llm_judgement
        )
        
        return result
    
    def _extract_history_texts(self, conversation_history: list) -> List[str]:
        """Extract text from conversation history"""
        history_texts = []
        if conversation_history:
            for msg in conversation_history:
                if hasattr(msg, 'text'):
                    history_texts.append(msg.text)
                elif isinstance(msg, dict):
                    history_texts.append(msg.get('text', ''))
        return history_texts
    
    async def _run_ml_detection(
        self, 
        message_text: str, 
        history_texts: List[str]
    ) -> Dict:
        """Run ML-based detection"""
        try:
            single_pred = ml_detector.predict(message_text, history_texts)
            
            if history_texts:
                conv_pred = ml_detector.predict_conversation(history_texts + [message_text])
                final_confidence = max(single_pred.confidence, conv_pred.confidence)
            else:
                final_confidence = single_pred.confidence
            
            return {
                "is_scam": final_confidence >= self.ML_CONFIDENCE_THRESHOLD,
                "confidence": final_confidence,
                "features_triggered": single_pred.features_triggered,
                "explanation": single_pred.explanation
            }
        except Exception as e:
            logger.error(f"ML detection error: {e}")
            return {"is_scam": False, "confidence": 0.0, "features_triggered": []}
    
    def _make_decision(
        self,
        session,
        signals: List[TriggeredSignal],
        hard_rule_triggered: bool,
        ml_result: Dict,
        llm_judgement: Optional[LLMJudgement]
    ) -> Dict:
        """
        AGGRESSIVE decision engine.
        
        scamDetected = true if:
        1. Any HARD RULE fires
        2. LLM confidence ≥ 0.6
        3. riskScore ≥ 45
        4. riskScore ≥ 30 AND (ML OR LLM agrees)
        5. Multiple soft rules triggered in same turn
        """
        reasons = []
        decision_reason = ""
        
        for signal in signals[:5]:
            reasons.append(f"Rule: {signal.description}")
        
        if ml_result.get("features_triggered"):
            for feat in ml_result["features_triggered"][:3]:
                reasons.append(f"Pattern: {feat}")
        
        if llm_judgement and llm_judgement.red_flags:
            for flag in llm_judgement.red_flags[:3]:
                reasons.append(f"Analysis: {flag}")
        
        scam_detected = session.scam_detected
        
        # Decision logic - AGGRESSIVE
        if hard_rule_triggered:
            decision_reason = "HARD RULE TRIGGERED - Immediate scam confirmation"
            scam_detected = True
        elif llm_judgement and llm_judgement.is_scam_likely and llm_judgement.confidence >= 0.6:
            decision_reason = f"LLM HIGH CONFIDENCE scam detection ({llm_judgement.confidence:.2f})"
            scam_detected = True
        elif session.risk_score >= 45:
            decision_reason = f"Risk threshold exceeded ({session.risk_score}/45)"
            scam_detected = True
        elif session.risk_score >= 30:
            ml_agrees = ml_result.get("is_scam", False)
            llm_agrees = llm_judgement.is_scam_likely if llm_judgement else False
            if ml_agrees or llm_agrees:
                decision_reason = f"Elevated risk ({session.risk_score}) with AI confirmation"
                scam_detected = True
            else:
                decision_reason = f"Elevated risk ({session.risk_score}), monitoring"
        elif len(signals) >= 3:
            decision_reason = f"Multiple signals detected ({len(signals)} signals)"
            scam_detected = True
        elif session.risk_score >= 15:
            decision_reason = f"Suspicious activity ({session.risk_score})"
        else:
            decision_reason = "Monitoring"
        
        # Update session
        if scam_detected:
            session.scam_detected = True
        
        if not reasons:
            reasons = [decision_reason]
        
        # Calculate confidence
        confidence = min(1.0, session.risk_score / 80)
        if llm_judgement:
            confidence = max(confidence, llm_judgement.confidence)
        
        return {
            "scamDetected": scam_detected,
            "confidence": round(confidence, 3),
            "risk_score": session.risk_score,
            "scam_stage": session.scam_stage.value,
            "hard_rule_triggered": hard_rule_triggered,
            "turn_count": session.turn_count,
            "reasons": reasons[:5],
            "decision_reason": decision_reason,
        }


class ScamDetector:
    """Backward-compatible wrapper for hybrid detector."""
    
    def __init__(self):
        self.hybrid_detector = HybridScamDetector()
    
    async def detect(
        self, 
        message_text: str, 
        conversation_history: list, 
        session_id: str = None
    ) -> dict:
        """Detect scam - backward compatible interface."""
        result = await self.hybrid_detector.detect(
            message_text=message_text,
            conversation_history=conversation_history,
            session_id=session_id
        )
        
        return {
            "scamDetected": result["scamDetected"],
            "confidence": result["confidence"],
            "reasons": result["reasons"],
            "risk_score": result.get("risk_score", 0),
            "scam_stage": result.get("scam_stage", "NORMAL"),
        }
