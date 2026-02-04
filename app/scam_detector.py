"""
SCAM DETECTOR - Hybrid scam detection system
Combines rule-based, ML, and LLM approaches for maximum accuracy
"""

import os
import json
from typing import Dict, List, Optional
from dotenv import load_dotenv
from groq import AsyncGroq

from .scam_rules import scam_rules_engine, RuleMatch, RuleCategory
from .risk_engine import risk_engine, RiskLevel, RiskAssessment
from .state_machine import state_machine, ConversationState
from .ml_detector import ml_detector, llm_classifier, MLPrediction

load_dotenv()


class HybridScamDetector:
    """
    Production-grade hybrid scam detection system.
    Combines multiple detection strategies for maximum accuracy.
    """
    
    def __init__(self):
        self.groq_api_key = os.getenv("GROQ_API_KEY")
        self.client = AsyncGroq(api_key=self.groq_api_key) if self.groq_api_key else None
        self.model = "llama-3.1-8b-instant"
        
        # Detection thresholds
        self.RULE_SCORE_THRESHOLD = 40
        self.ML_CONFIDENCE_THRESHOLD = 0.6
        self.LLM_CONFIDENCE_THRESHOLD = 0.7
        self.COMBINED_THRESHOLD = 0.65
    
    async def detect(self, message_text: str, conversation_history: list, session_id: str = None) -> Dict:
        """
        Main detection method - runs hybrid detection pipeline.
        """
        session_id = session_id or "default"
        
        # Extract message texts from history
        history_texts = []
        if conversation_history:
            for msg in conversation_history:
                if hasattr(msg, 'text'):
                    history_texts.append(msg.text)
                elif isinstance(msg, dict):
                    history_texts.append(msg.get('text', ''))
        
        # Run all detection methods
        results = {
            "rule_based": await self._rule_based_detection(message_text, history_texts, session_id),
            "ml_based": await self._ml_based_detection(message_text, history_texts),
            "llm_based": await self._llm_based_detection(message_text, history_texts),
        }
        
        # Combine results
        combined = self._combine_detection_results(results, session_id)
        
        # Update state machine
        current_state, did_transition = state_machine.transition(
            session_id=session_id,
            risk_score=risk_engine.get_assessment(session_id).total_score,
            scam_confirmed=combined["scamDetected"],
            hard_rule_triggered=results["rule_based"].get("hard_rule_triggered", False),
        )
        
        combined["current_state"] = current_state.name
        combined["detection_sources"] = {
            "rule_based": results["rule_based"],
            "ml_based": results["ml_based"],
            "llm_based": results["llm_based"],
        }
        
        return combined
    
    async def _rule_based_detection(
        self, 
        message_text: str, 
        history_texts: List[str],
        session_id: str
    ) -> Dict:
        """Run rule-based detection and update risk engine"""
        
        matches, message_score = scam_rules_engine.analyze_message(message_text)
        all_matches, total_score, categories = scam_rules_engine.analyze_conversation(
            history_texts + [message_text]
        )
        
        hard_rule_triggered = scam_rules_engine.has_hard_rule_match(matches)
        
        for match in matches:
            risk_engine.add_signal(
                session_id=session_id,
                signal_type=match.category.value,
                source="rule",
                raw_score=match.score,
                confidence=1.0 if match.is_hard_rule else 0.8,
                description=f"Rule match: {match.matched_text}"
            )
        
        summary = scam_rules_engine.get_scam_summary(all_matches)
        
        return {
            "score": total_score,
            "message_score": message_score,
            "matches_count": len(matches),
            "categories_detected": [c.value for c in categories],
            "hard_rule_triggered": hard_rule_triggered,
            "top_indicators": summary["top_indicators"],
            "is_scam": total_score >= self.RULE_SCORE_THRESHOLD or hard_rule_triggered,
            "confidence": min(1.0, total_score / 100) if total_score > 0 else 0.0
        }
    
    async def _ml_based_detection(
        self,
        message_text: str,
        history_texts: List[str]
    ) -> Dict:
        """Run ML-based detection"""
        
        single_pred = ml_detector.predict(message_text, history_texts)
        
        if history_texts:
            conv_pred = ml_detector.predict_conversation(history_texts + [message_text])
        else:
            conv_pred = single_pred
        
        final_confidence = max(single_pred.confidence, conv_pred.confidence)
        
        return {
            "is_scam": final_confidence >= self.ML_CONFIDENCE_THRESHOLD,
            "confidence": final_confidence,
            "message_confidence": single_pred.confidence,
            "conversation_confidence": conv_pred.confidence if history_texts else None,
            "features_triggered": single_pred.features_triggered,
            "explanation": single_pred.explanation
        }
    
    async def _llm_based_detection(
        self,
        message_text: str,
        history_texts: List[str]
    ) -> Dict:
        """Run LLM-based intent classification"""
        
        if not self.client:
            return {"is_scam": False, "confidence": 0.0, "error": "No Groq API key"}
        
        try:
            context = ""
            if history_texts:
                context = "Previous messages:\n" + "\n".join(
                    f"- {msg}" for msg in history_texts[-5:]
                ) + "\n\n"
            
            prompt = f"""You are an expert fraud detection system. Analyze this message for scam indicators.

{context}Current message: "{message_text}"

Consider: urgency/fear tactics, requests for OTP/PIN/passwords, authority impersonation, financial pressure, phishing.

Return ONLY valid JSON:
{{"scamDetected": true/false, "confidence": 0.0-1.0, "scam_type": "type or null", "reasons": ["reason1", "reason2"]}}"""

            response = await self.client.chat.completions.create(
                messages=[
                    {"role": "system", "content": "You are a fraud detection expert. Output only valid JSON."},
                    {"role": "user", "content": prompt}
                ],
                model=self.model,
                temperature=0.1,
                max_tokens=200
            )
            
            result_text = response.choices[0].message.content.strip()
            if "```" in result_text:
                result_text = result_text.split("```")[1]
                if result_text.startswith("json"):
                    result_text = result_text[4:]
                result_text = result_text.strip()
            
            result = json.loads(result_text)
            return {
                "is_scam": result.get("scamDetected", False),
                "confidence": result.get("confidence", 0.5),
                "scam_type": result.get("scam_type"),
                "reasons": result.get("reasons", [])
            }
            
        except Exception as e:
            print(f"LLM detection error: {e}")
            return {"is_scam": False, "confidence": 0.0, "error": str(e)}
    
    def _combine_detection_results(self, results: Dict, session_id: str) -> Dict:
        """Combine results from all detection methods using weighted voting."""
        
        rule_result = results["rule_based"]
        ml_result = results["ml_based"]
        llm_result = results["llm_based"]
        
        weights = {"rule": 0.40, "ml": 0.25, "llm": 0.35}
        
        weighted_confidence = 0.0
        votes_for_scam = 0
        total_weight = 0
        
        if rule_result.get("is_scam"):
            votes_for_scam += weights["rule"]
            weighted_confidence += rule_result.get("confidence", 0.5) * weights["rule"]
        total_weight += weights["rule"]
        
        if ml_result.get("is_scam"):
            votes_for_scam += weights["ml"]
            weighted_confidence += ml_result.get("confidence", 0.5) * weights["ml"]
        total_weight += weights["ml"]
        
        if llm_result.get("is_scam") and "error" not in llm_result:
            votes_for_scam += weights["llm"]
            weighted_confidence += llm_result.get("confidence", 0.5) * weights["llm"]
            total_weight += weights["llm"]
        elif "error" not in llm_result:
            total_weight += weights["llm"]
        
        if total_weight > 0:
            weighted_confidence = weighted_confidence / total_weight
        
        # Decision logic
        if rule_result.get("hard_rule_triggered"):
            is_scam = True
            final_confidence = max(0.9, weighted_confidence)
            decision_reason = "Hard rule triggered"
        elif rule_result.get("is_scam") and (ml_result.get("is_scam") or llm_result.get("is_scam")):
            is_scam = True
            final_confidence = weighted_confidence
            decision_reason = "Rule-based confirmed by ML/LLM"
        elif ml_result.get("is_scam") and llm_result.get("is_scam"):
            is_scam = True
            final_confidence = weighted_confidence
            decision_reason = "ML and LLM consensus"
        elif max(rule_result.get("confidence", 0), ml_result.get("confidence", 0), llm_result.get("confidence", 0)) >= 0.85:
            is_scam = True
            final_confidence = max(rule_result.get("confidence", 0), ml_result.get("confidence", 0), llm_result.get("confidence", 0))
            decision_reason = "High confidence single source"
        elif votes_for_scam >= self.COMBINED_THRESHOLD:
            is_scam = True
            final_confidence = weighted_confidence
            decision_reason = "Combined threshold exceeded"
        else:
            is_scam = False
            final_confidence = 1.0 - weighted_confidence
            decision_reason = "Insufficient evidence"
        
        risk_assessment = risk_engine.get_assessment(session_id)
        
        reasons = []
        if rule_result.get("top_indicators"):
            reasons.extend([f"Rule: {ind['text']}" for ind in rule_result["top_indicators"][:3]])
        if ml_result.get("features_triggered"):
            reasons.extend([f"Pattern: {feat}" for feat in ml_result["features_triggered"][:2]])
        if llm_result.get("reasons"):
            reasons.extend([f"AI: {r}" for r in llm_result["reasons"][:2]])
        
        if not reasons and is_scam:
            reasons = [decision_reason]
        
        return {
            "scamDetected": is_scam,
            "confidence": round(final_confidence, 3),
            "risk_level": risk_assessment.risk_level.value,
            "risk_score": round(risk_assessment.total_score, 1),
            "reasons": reasons[:5],
            "decision_reason": decision_reason,
        }


class ScamDetector:
    """Backward-compatible wrapper for hybrid detector."""
    
    def __init__(self):
        self.hybrid_detector = HybridScamDetector()
    
    async def detect(self, message_text: str, conversation_history: list, session_id: str = None) -> dict:
        """Detect scam - backward compatible interface."""
        result = await self.hybrid_detector.detect(
            message_text=message_text,
            conversation_history=conversation_history,
            session_id=session_id
        )
        
        return {
            "scamDetected": result["scamDetected"],
            "confidence": result["confidence"],
            "reasons": result["reasons"]
        }
