"""
SCAM DETECTOR - Hybrid detection pipeline with LLM reasoning judge
REFACTORED to fix Problems #4, #10, #12

KEY CHANGES:
- LLM is now a REASONING JUDGE, not keyword detector (Problem #4)
- Clear separation of detection responsibilities (Problem #10)
- ML influences risk score, doesn't override (Problem #12)
- Detection runs on EVERY turn with stateful accumulation
"""

import os
import json
from typing import Dict, List, Optional
from dotenv import load_dotenv
from groq import AsyncGroq

from .risk_engine import (
    risk_engine, ScamStage, LLMJudgement, 
    TriggeredSignal, SignalCategory
)
from .ml_detector import ml_detector

load_dotenv()


class LLMReasoningJudge:
    """
    LLM-based reasoning judge for scam detection.
    
    KEY DESIGN (Problem #4):
    - NOT a keyword detector
    - Answers reasoning questions about scammer behavior
    - Evaluates consistency, evasion, social engineering
    - Output ALWAYS influences risk score
    """
    
    def __init__(self):
        self.groq_api_key = os.getenv("GROQ_API_KEY")
        self.client = AsyncGroq(api_key=self.groq_api_key) if self.groq_api_key else None
        self.model = "llama-3.1-8b-instant"
    
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
        LLM reasoning judge - evaluates scam likelihood through reasoning.
        
        INVOKED WHEN (Problem #4):
        - riskScore ≥ 20
        - OR behavior mismatch detected
        - OR stage escalation suspected
        
        OUTPUT MUST influence decision - never ignored.
        """
        if not self.client:
            return self._fallback_judgement(turn_number, detected_signals)
        
        try:
            # Build conversation context
            history_text = ""
            if conversation_history:
                history_text = "\n".join(
                    f"Message {i+1}: {msg}" 
                    for i, msg in enumerate(conversation_history[-5:])
                )
            
            # Build detected signals context
            signals_text = ", ".join(detected_signals[:5]) if detected_signals else "None yet"
            
            prompt = f"""You are an expert fraud analyst evaluating a potential scam conversation.

CONVERSATION CONTEXT:
{history_text}

CURRENT MESSAGE: "{message}"

CURRENT ANALYSIS:
- Risk Score: {current_risk_score}/100
- Current Stage: {current_stage.value}
- Detected Signals: {signals_text}

ANSWER THESE REASONING QUESTIONS:

1. AUTHORITY CHECK: Is the sender's claimed authority (bank/government/police) behaving consistently with how that authority actually operates?
   - Real banks don't ask for OTP over chat
   - Real police don't threaten arrest over phone for payments
   - Real government doesn't demand immediate payment

2. EVASION CHECK: Is the sender avoiding direct questions or being procedurally vague?
   - Refusing to provide verifiable details
   - Rushing past clarification requests
   - Giving generic/scripted responses

3. COERCION CHECK: Is there social engineering or emotional manipulation?
   - Fear tactics (arrest, account loss, legal action)
   - Urgency pressure (deadline, limited time)
   - Authority abuse (I am officer, this is official)

4. ESCALATION CHECK: Is the conversation escalating toward financial/credential request?
   - Moving from information to action
   - Introducing payment or OTP request
   - Pushing toward immediate action

Based on your analysis, provide your judgement in this EXACT JSON format:
{{
    "is_scam_likely": true/false,
    "confidence": 0.0-1.0,
    "scam_type": "type or null",
    "reasoning": "one sentence explaining your judgement",
    "risk_boost": 0-30,
    "suggested_stage": "NORMAL|HOOK|TRUST|THREAT|ACTION|CONFIRMED|null",
    "red_flags": ["list", "of", "flags"]
}}

IMPORTANT:
- risk_boost should be 0 if no scam indicators, 10-15 for moderate, 20-30 for strong
- suggested_stage should advance the stage if escalation detected
- Be specific in reasoning about WHY this is or isn't a scam"""

            response = await self.client.chat.completions.create(
                messages=[
                    {
                        "role": "system",
                        "content": "You are a fraud detection expert. Analyze conversations for scam patterns through REASONING, not keyword matching. Output only valid JSON."
                    },
                    {"role": "user", "content": prompt}
                ],
                model=self.model,
                temperature=0.1,
                max_tokens=400
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
                risk_boost=min(30, max(0, result.get("risk_boost", 0))),
                stage_suggestion=stage_suggestion,
                red_flags=result.get("red_flags", [])
            )
            
        except Exception as e:
            print(f"LLM judge error: {e}")
            return self._fallback_judgement(turn_number, detected_signals)
    
    def _fallback_judgement(
        self, 
        turn_number: int, 
        detected_signals: List[str]
    ) -> LLMJudgement:
        """Fallback when LLM unavailable - use signal-based heuristic"""
        # Count high-risk signals
        high_risk = ["otp", "pin", "payment", "transfer", "arrest", "block"]
        risk_count = sum(1 for s in detected_signals if any(hr in s.lower() for hr in high_risk))
        
        return LLMJudgement(
            turn_number=turn_number,
            is_scam_likely=risk_count >= 2,
            confidence=0.5 + (risk_count * 0.1),
            scam_type=None,
            reasoning="Fallback judgement based on signal count",
            risk_boost=risk_count * 5,
            stage_suggestion=None,
            red_flags=detected_signals[:3]
        )


class HybridScamDetector:
    """
    Production-grade hybrid scam detection system.
    
    PIPELINE ORDER:
    1. Light Signal Extraction (risk_engine)
    2. Risk Score Update (cumulative)
    3. Scam Stage Update
    4. LLM Reasoning Judge (conditional)
    5. ML Classifier (influences score)
    6. Decision Engine (combines all)
    """
    
    def __init__(self):
        self.llm_judge = LLMReasoningJudge()
        
        # Thresholds for LLM invocation
        self.LLM_INVOKE_THRESHOLD = 20
        self.ML_CONFIDENCE_THRESHOLD = 0.6
    
    async def detect(
        self, 
        message_text: str, 
        conversation_history: list, 
        session_id: str = None
    ) -> Dict:
        """
        Main detection pipeline - runs on EVERY turn.
        
        Returns stateful detection result with:
        - scamDetected (bool)
        - confidence (float)
        - risk_score (cumulative int)
        - scam_stage (str)
        - reasons (list)
        """
        session_id = session_id or "default"
        
        # Get current session state
        session = risk_engine.get_or_create_session(session_id)
        session.turn_count += 1
        turn_number = session.turn_count
        
        # Extract message texts from history
        history_texts = self._extract_history_texts(conversation_history)
        
        # =====================================================================
        # STEP 1: Rule-based signal extraction (Problem #11 - hard rules)
        # =====================================================================
        signals, message_score, hard_rule_triggered = risk_engine.analyze_message(
            message_text, session_id, turn_number
        )
        
        # Apply signals to session (CUMULATIVE - Problem #3)
        risk_engine.apply_signals_to_session(session_id, signals, hard_rule_triggered)
        
        # =====================================================================
        # STEP 2: Detect stage patterns and update stage (Problem #8)
        # =====================================================================
        stage_patterns = risk_engine.detect_stage_patterns(message_text)
        session.update_stage_from_patterns(stage_patterns)
        
        # =====================================================================
        # STEP 3: ML-based detection (Problem #12 - influences, doesn't override)
        # =====================================================================
        ml_result = await self._run_ml_detection(message_text, history_texts)
        if ml_result["is_scam"] and ml_result["confidence"] >= self.ML_CONFIDENCE_THRESHOLD:
            risk_engine.apply_ml_score(
                session_id,
                ml_result["confidence"],
                ml_result["is_scam"],
                ml_result.get("features_triggered", []),
                turn_number
            )
        
        # =====================================================================
        # STEP 4: LLM Reasoning Judge (Problem #4)
        # Invoked when: riskScore ≥ 20 OR behavior mismatch OR stage escalation
        # =====================================================================
        llm_judgement = None
        should_invoke_llm = (
            session.risk_score >= self.LLM_INVOKE_THRESHOLD or
            len(stage_patterns) >= 2 or
            hard_rule_triggered
        )
        
        if should_invoke_llm:
            detected_signal_names = [s.signal_name for s in signals]
            llm_judgement = await self.llm_judge.judge(
                message=message_text,
                conversation_history=history_texts,
                current_risk_score=session.risk_score,
                current_stage=session.scam_stage,
                detected_signals=detected_signal_names,
                turn_number=turn_number
            )
            
            # Apply LLM judgement (MUST influence - Problem #4)
            risk_engine.apply_llm_judgement(session_id, llm_judgement)
        
        # =====================================================================
        # STEP 5: Decision Engine - Combine all signals
        # =====================================================================
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
            print(f"ML detection error: {e}")
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
        Final decision engine - combines all detection sources.
        
        DECISION LOGIC:
        scamDetected = true if:
        1. Any HARD RULE fires (Problem #11)
        OR
        2. riskScore ≥ 70 (threshold crossing)
        OR
        3. riskScore ≥ 50 AND (ML + LLM agree on scam)
        """
        reasons = []
        decision_reason = ""
        
        # Collect reasons from all sources
        for signal in signals[:5]:
            reasons.append(f"Rule: {signal.description}")
        
        if ml_result.get("features_triggered"):
            for feat in ml_result["features_triggered"][:3]:
                reasons.append(f"Pattern: {feat}")
        
        if llm_judgement and llm_judgement.red_flags:
            for flag in llm_judgement.red_flags[:3]:
                reasons.append(f"Analysis: {flag}")
        
        # Determine final scamDetected status
        # The session already tracks this via cumulative scoring
        scam_detected = session.scam_detected
        
        # Build decision reason
        if hard_rule_triggered:
            decision_reason = "HARD RULE TRIGGERED - Immediate scam confirmation"
            scam_detected = True
        elif session.risk_score >= 70:
            decision_reason = f"Risk threshold exceeded ({session.risk_score}/70)"
            scam_detected = True
        elif session.risk_score >= 50:
            ml_agrees = ml_result.get("is_scam", False)
            llm_agrees = llm_judgement.is_scam_likely if llm_judgement else False
            if ml_agrees and llm_agrees:
                decision_reason = "ML and LLM consensus at elevated risk"
                scam_detected = True
            elif ml_agrees or llm_agrees:
                decision_reason = f"Elevated risk ({session.risk_score}), partial AI agreement"
            else:
                decision_reason = f"Elevated risk ({session.risk_score}), monitoring"
        elif session.risk_score >= 25:
            decision_reason = f"Suspicious activity detected ({session.risk_score})"
        else:
            decision_reason = "Normal conversation, monitoring"
        
        if not reasons:
            reasons = [decision_reason]
        
        # Calculate confidence
        confidence = min(1.0, session.risk_score / 100)
        if llm_judgement:
            confidence = (confidence + llm_judgement.confidence) / 2
        
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
