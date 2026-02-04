"""
ML DETECTOR - Machine Learning based scam detection
Combines lightweight ML with LLM for conversation-level analysis
"""

import re
import os
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
from collections import Counter
import math

@dataclass
class MLPrediction:
    """ML model prediction result"""
    is_scam: bool
    confidence: float
    features_triggered: List[str]
    explanation: str

class FeatureExtractor:
    """Extract features from text for ML classification"""
    
    def __init__(self):
        self._init_feature_weights()
    
    def _init_feature_weights(self):
        """Initialize feature importance weights based on domain knowledge"""
        
        # High-signal n-grams for scam detection
        self.scam_ngrams = {
            # Urgency patterns
            "act now": 3.0,
            "immediately": 2.5,
            "urgent": 2.5,
            "right now": 2.0,
            "don't delay": 2.5,
            "limited time": 2.0,
            "expires today": 2.5,
            "last chance": 2.5,
            "final warning": 3.0,
            
            # Threat patterns
            "account blocked": 3.5,
            "account suspended": 3.5,
            "legal action": 3.0,
            "police complaint": 3.5,
            "arrest warrant": 4.0,
            "court case": 3.0,
            "will be blocked": 3.0,
            "will be suspended": 3.0,
            
            # Financial request patterns
            "share otp": 4.0,
            "send otp": 4.0,
            "otp number": 3.5,
            "verification code": 2.5,
            "bank details": 3.0,
            "account number": 2.5,
            "transfer money": 3.0,
            "upi id": 3.0,
            "upi pin": 4.0,
            "atm pin": 4.0,
            "cvv number": 4.0,
            
            # Authority impersonation
            "rbi": 3.0,
            "reserve bank": 3.0,
            "income tax": 3.0,
            "cyber cell": 3.5,
            "police": 2.5,
            "government official": 3.0,
            "bank manager": 2.5,
            "customer care": 2.0,
            
            # Phishing patterns
            "click here": 2.0,
            "click the link": 2.5,
            "download app": 2.5,
            "install app": 2.5,
            "anydesk": 4.0,
            "teamviewer": 4.0,
            "screen share": 3.5,
            
            # Reward/lottery patterns
            "won lottery": 3.5,
            "prize money": 3.0,
            "claim reward": 3.0,
            "cashback": 2.0,
            "refund": 2.0,
        }
        
        # Patterns that indicate legitimate messages
        self.safe_ngrams = {
            "thank you for": -1.0,
            "have a nice day": -1.5,
            "how can i help": -1.5,
            "please let me know": -1.0,
            "feel free to": -1.0,
            "happy to help": -1.5,
        }
    
    def extract_features(self, text: str, conversation_history: List[str] = None) -> Dict[str, float]:
        """Extract features from text for classification"""
        features = {}
        text_lower = text.lower()
        
        # 1. N-gram features
        ngram_score = 0.0
        triggered_ngrams = []
        
        for ngram, weight in self.scam_ngrams.items():
            if ngram in text_lower:
                ngram_score += weight
                triggered_ngrams.append(ngram)
        
        for ngram, weight in self.safe_ngrams.items():
            if ngram in text_lower:
                ngram_score += weight  # weight is negative
        
        features["ngram_score"] = ngram_score
        features["ngram_count"] = len(triggered_ngrams)
        
        # 2. Lexical features
        features["length"] = len(text)
        features["word_count"] = len(text.split())
        features["avg_word_length"] = sum(len(w) for w in text.split()) / max(len(text.split()), 1)
        
        # 3. Punctuation features
        features["exclamation_count"] = text.count("!")
        features["question_count"] = text.count("?")
        features["caps_ratio"] = sum(1 for c in text if c.isupper()) / max(len(text), 1)
        
        # 4. Number features
        numbers = re.findall(r'\d+', text)
        features["number_count"] = len(numbers)
        features["long_number_count"] = sum(1 for n in numbers if len(n) >= 6)  # Potential account/phone numbers
        
        # 5. URL/link features
        urls = re.findall(r'https?://\S+', text)
        features["url_count"] = len(urls)
        features["has_suspicious_url"] = 1.0 if any(
            not any(safe in url for safe in ["google", "facebook", "amazon", "flipkart", "paytm", "sbi", "hdfc"])
            for url in urls
        ) else 0.0
        
        # 6. Entity features
        features["has_upi_pattern"] = 1.0 if re.search(r'[a-zA-Z0-9._-]+@[a-zA-Z]{2,}', text) else 0.0
        features["has_phone_pattern"] = 1.0 if re.search(r'(?:\+91[\-\s]?)?[6-9]\d{9}', text) else 0.0
        features["has_aadhaar_pattern"] = 1.0 if re.search(r'\b\d{4}\s?\d{4}\s?\d{4}\b', text) else 0.0
        
        # 7. Sentiment/intent features (simple heuristics)
        urgency_words = ["urgent", "immediate", "now", "today", "quick", "fast", "hurry", "asap"]
        threat_words = ["block", "suspend", "arrest", "legal", "police", "jail", "fine", "penalty"]
        request_words = ["share", "send", "give", "provide", "transfer", "pay", "verify"]
        
        features["urgency_score"] = sum(1 for w in urgency_words if w in text_lower) * 0.5
        features["threat_score"] = sum(1 for w in threat_words if w in text_lower) * 0.7
        features["request_score"] = sum(1 for w in request_words if w in text_lower) * 0.5
        
        # 8. Conversation-level features (if history provided)
        if conversation_history:
            all_text = " ".join(conversation_history) + " " + text
            features["conversation_length"] = len(conversation_history)
            
            # Check for escalation pattern
            history_scores = []
            for msg in conversation_history:
                msg_score = sum(
                    weight for ngram, weight in self.scam_ngrams.items() 
                    if ngram in msg.lower()
                )
                history_scores.append(msg_score)
            
            if len(history_scores) >= 2:
                # Check if scores are increasing (escalation)
                increasing = sum(
                    1 for i in range(1, len(history_scores)) 
                    if history_scores[i] > history_scores[i-1]
                )
                features["escalation_ratio"] = increasing / (len(history_scores) - 1)
            else:
                features["escalation_ratio"] = 0.0
            
            # Repetition detection
            all_msgs = conversation_history + [text]
            word_counts = Counter(" ".join(all_msgs).lower().split())
            repeated_scam_words = sum(
                count for word, count in word_counts.items()
                if any(ngram in word for ngram in ["urgent", "block", "suspend", "otp", "verify"])
                and count > 1
            )
            features["scam_word_repetition"] = repeated_scam_words
        
        return features, triggered_ngrams
    
    def get_feature_vector(self, features: Dict[str, float]) -> List[float]:
        """Convert feature dict to vector for ML model"""
        feature_order = [
            "ngram_score", "ngram_count", "length", "word_count", "avg_word_length",
            "exclamation_count", "question_count", "caps_ratio", "number_count",
            "long_number_count", "url_count", "has_suspicious_url", "has_upi_pattern",
            "has_phone_pattern", "has_aadhaar_pattern", "urgency_score", "threat_score",
            "request_score"
        ]
        return [features.get(f, 0.0) for f in feature_order]


class LightweightMLDetector:
    """
    Lightweight ML-based scam detector.
    Uses a simple weighted scoring model that doesn't require training data.
    Can be replaced with trained model (LogisticRegression, RandomForest, etc.)
    """
    
    def __init__(self):
        self.feature_extractor = FeatureExtractor()
        self._init_weights()
    
    def _init_weights(self):
        """Initialize feature weights (learned or expert-defined)"""
        # These weights are based on domain expertise
        # Can be replaced with learned weights from trained model
        self.weights = {
            "ngram_score": 0.25,
            "ngram_count": 0.15,
            "threat_score": 0.20,
            "urgency_score": 0.15,
            "request_score": 0.10,
            "has_suspicious_url": 0.05,
            "has_upi_pattern": 0.03,
            "has_phone_pattern": 0.02,
            "has_aadhaar_pattern": 0.03,
            "caps_ratio": 0.02,
        }
        
        self.bias = -0.3  # Baseline threshold
        self.scam_threshold = 0.5
    
    def predict(self, text: str, conversation_history: List[str] = None) -> MLPrediction:
        """
        Predict if message/conversation is a scam.
        Returns prediction with confidence and explanation.
        """
        features, triggered_ngrams = self.feature_extractor.extract_features(
            text, conversation_history
        )
        
        # Calculate weighted score
        score = self.bias
        for feature, weight in self.weights.items():
            if feature in features:
                score += features[feature] * weight
        
        # Apply sigmoid for probability
        probability = 1 / (1 + math.exp(-score * 2))
        
        # Determine prediction
        is_scam = probability >= self.scam_threshold
        
        # Generate explanation
        top_features = sorted(
            [(f, features.get(f, 0) * self.weights.get(f, 0)) 
             for f in self.weights.keys()],
            key=lambda x: x[1],
            reverse=True
        )[:5]
        
        explanation_parts = []
        if triggered_ngrams:
            explanation_parts.append(f"Triggered patterns: {', '.join(triggered_ngrams[:5])}")
        for feat, contrib in top_features:
            if contrib > 0.05:
                explanation_parts.append(f"{feat}: +{contrib:.2f}")
        
        explanation = "; ".join(explanation_parts) if explanation_parts else "No significant indicators"
        
        return MLPrediction(
            is_scam=is_scam,
            confidence=probability,
            features_triggered=triggered_ngrams,
            explanation=explanation
        )
    
    def predict_conversation(self, messages: List[str]) -> MLPrediction:
        """Predict scam for entire conversation"""
        if not messages:
            return MLPrediction(
                is_scam=False,
                confidence=0.0,
                features_triggered=[],
                explanation="No messages to analyze"
            )
        
        # Analyze each message and aggregate
        all_predictions = []
        all_features = []
        
        for i, msg in enumerate(messages):
            history = messages[:i] if i > 0 else None
            pred = self.predict(msg, history)
            all_predictions.append(pred)
            all_features.extend(pred.features_triggered)
        
        # Aggregate predictions
        # Use max confidence and combine features
        max_confidence = max(p.confidence for p in all_predictions)
        avg_confidence = sum(p.confidence for p in all_predictions) / len(all_predictions)
        
        # Weight towards max but consider average
        final_confidence = 0.7 * max_confidence + 0.3 * avg_confidence
        
        # Bonus for consistent scam indicators
        scam_predictions = sum(1 for p in all_predictions if p.is_scam)
        if scam_predictions >= len(all_predictions) * 0.5:
            final_confidence = min(1.0, final_confidence * 1.1)
        
        unique_features = list(set(all_features))
        
        return MLPrediction(
            is_scam=final_confidence >= self.scam_threshold,
            confidence=final_confidence,
            features_triggered=unique_features,
            explanation=f"Analyzed {len(messages)} messages, {scam_predictions} flagged as scam"
        )


class LLMIntentClassifier:
    """
    LLM-based intent classification for contextual understanding.
    Uses Groq API for inference.
    """
    
    def __init__(self):
        self.groq_api_key = os.getenv("GROQ_API_KEY")
    
    async def classify_intent(self, text: str, conversation_history: List[str] = None) -> Dict:
        """
        Classify the intent of a message using LLM.
        Returns structured intent classification.
        """
        if not self.groq_api_key:
            return {"intent": "unknown", "confidence": 0.0, "error": "No API key"}
        
        try:
            from groq import AsyncGroq
            client = AsyncGroq(api_key=self.groq_api_key)
            
            # Build context
            context = ""
            if conversation_history:
                context = "Previous messages:\n" + "\n".join(
                    f"- {msg}" for msg in conversation_history[-5:]
                ) + "\n\n"
            
            prompt = f"""Analyze this message for scam indicators.

{context}Current message: "{text}"

Classify the intent and provide a scam probability score.
Respond in this exact JSON format only:
{{"intent": "scam|legitimate|unclear", "scam_probability": 0.0-1.0, "scam_type": "type if scam else null", "key_indicators": ["list", "of", "indicators"], "reasoning": "brief explanation"}}"""
            
            response = await client.chat.completions.create(
                model="llama-3.1-8b-instant",
                messages=[
                    {
                        "role": "system",
                        "content": "You are a scam detection expert. Analyze messages for fraud indicators. Return only valid JSON."
                    },
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1,
                max_tokens=300
            )
            
            result_text = response.choices[0].message.content.strip()
            
            # Parse JSON response
            import json
            # Clean up response if needed
            if result_text.startswith("```"):
                result_text = result_text.split("```")[1]
                if result_text.startswith("json"):
                    result_text = result_text[4:]
            
            result = json.loads(result_text)
            return {
                "intent": result.get("intent", "unclear"),
                "confidence": result.get("scam_probability", 0.5),
                "scam_type": result.get("scam_type"),
                "indicators": result.get("key_indicators", []),
                "reasoning": result.get("reasoning", "")
            }
            
        except Exception as e:
            return {
                "intent": "error",
                "confidence": 0.0,
                "error": str(e)
            }


# Singleton instances
ml_detector = LightweightMLDetector()
llm_classifier = LLMIntentClassifier()
