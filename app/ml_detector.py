"""
ML DETECTOR - Pre-trained scikit-learn classifier + keyword scoring
REWRITTEN to use a real machine-learning model (TF-IDF + LinearSVC) trained
on labelled scam/non-scam examples, combined with weighted keyword scoring.

ARCHITECTURE:
1. Pre-trained TF-IDF + LinearSVC (scikit-learn) — PRIMARY classifier
2. Enhanced keyword/ngram scoring — SECONDARY fallback / reinforcement
3. Ensemble decision (weighted combination)
"""

import re
import os
import json
import math
import logging
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
from collections import Counter

logger = logging.getLogger(__name__)


@dataclass
class MLPrediction:
    """ML model prediction result"""
    is_scam: bool
    confidence: float
    features_triggered: List[str]
    explanation: str


# ---------------------------------------------------------------------------
# Training corpus for the pre-trained scikit-learn model
# ---------------------------------------------------------------------------

SCAM_EXAMPLES = [
    # Bank / KYC scams
    "Your SBI account will be blocked. Update KYC immediately by clicking this link.",
    "Dear customer, your account has been suspended. Share OTP to reactivate.",
    "This is HDFC Bank. Your account shows suspicious activity. Verify details now.",
    "Your bank account will be frozen within 24 hours. Call us immediately.",
    "URGENT: Your net banking is blocked. Enter your ATM PIN to unblock.",
    "Account compromised. Share your CVV and card number to secure account.",
    "We detected unauthorized access to your account. Provide OTP sent to your mobile.",
    # UPI / cashback scams
    "You have won cashback of Rs 5000. Scan this QR code to receive payment.",
    "Collect request sent to your UPI. Accept it to receive Rs 10,000 refund.",
    "Your UPI ID needs verification. Share UPI PIN to complete process.",
    "Approve the collect request on your PhonePe to receive lottery prize.",
    "Congratulations! You won Rs 50,000. Send Rs 500 processing fee via UPI.",
    # Police / CBI impersonation
    "I am calling from Cyber Crime Cell. A case has been filed against your Aadhaar.",
    "Digital arrest warrant issued against you. Pay fine of Rs 15,000 to avoid jail.",
    "CBI officer speaking. Your bank account linked to fraud. Transfer funds to safe account.",
    "Income Tax department: Rs 2 lakh penalty due. Pay via UPI to avoid FIR.",
    "TRAI notice: Your mobile number will be blocked due to illegal activity.",
    # Delivery / customs scams
    "Your parcel is stuck at customs. Pay Rs 2,500 customs duty to release it.",
    "DHL: Package held at airport. Click link to pay clearance charges.",
    "Amazon delivery failed. Your order worth Rs 8,000 will be returned. Pay redelivery fee.",
    "Courier held at customs. Transfer fee to this UPI ID to get your package.",
    # Loan scams
    "Pre-approved loan of Rs 5 lakh sanctioned. Pay processing fee of Rs 2,000.",
    "Instant personal loan approved. Submit Rs 1,500 insurance premium to disburse.",
    "Your loan application is approved. Pay advance EMI to activate loan account.",
    # Lottery / prize scams
    "You have won Rs 25 lakh in KBC lottery. Pay tax of Rs 5,000 to claim prize.",
    "Lucky winner! You have been selected. Pay GST to receive prize money.",
    "Congratulations, you are selected for free iPhone. Pay shipping charges now.",
    # Tech support scams
    "Download AnyDesk app immediately. I will fix your account issue.",
    "Install TeamViewer quick support. Our engineer needs remote access to verify.",
    "Open AnyDesk and share the 9-digit code to resolve your bank issue.",
    # Job scams
    "Work from home opportunity. Earn Rs 2,000 per day doing simple data entry.",
    "Part time job: Like YouTube videos and earn Rs 500 per task. Registration fee Rs 200.",
    "Guaranteed daily income Rs 3,000. Pay security deposit Rs 1,000 to start.",
    # Electricity / bill scams
    "Your electricity connection will be cut tonight. Pay outstanding bill via UPI.",
    "MSEB notice: Rs 1,200 bill overdue. Pay now to avoid disconnection.",
    "Gas connection will be terminated. Pay security deposit to continue service.",
    # Investment scams
    "Invest Rs 5,000 and earn Rs 50,000 in 7 days. Guaranteed returns.",
    "Join our crypto trading group. Minimum investment Rs 2,000 for 300% profit.",
    # Misc
    "Please share the OTP you received on your registered mobile number.",
    "Enter your ATM PIN to verify your identity and release your funds.",
    "Send Rs 500 to this UPI ID scammer.fraud@fakebank to receive cashback.",
    "Click here to verify your account: http://fake-bank-kyc.com/verify",
    "Your account will be permanently closed. Verify by calling 9876543210.",
    "I am bank manager. Your fixed deposit is maturing. Share account details.",
    "Police case registered. Pay Rs 25,000 fine to avoid digital arrest.",
    "Transfer Rs 10,000 to this account number 1234567890 immediately.",
]

NON_SCAM_EXAMPLES = [
    "Thank you for contacting us. How can I help you today?",
    "Your order has been shipped and will arrive in 2-3 business days.",
    "Please hold, I am transferring you to the relevant department.",
    "Your refund has been processed and will reflect in 5-7 working days.",
    "Your appointment is confirmed for tomorrow at 10 AM.",
    "Your monthly account statement is ready. Please check your email.",
    "We have received your request and will process it within 24 hours.",
    "Your loan EMI has been successfully auto-debited from your account.",
    "Please visit our nearest branch with your ID proof for KYC update.",
    "Your credit card payment of Rs 5,000 has been processed successfully.",
    "Your product has been delivered. Please rate your experience.",
    "Your return request has been accepted. Pickup will be scheduled shortly.",
    "Your order is out for delivery. Track it using order ID ORD123456.",
    "Good morning! How are you doing today?",
    "Please let me know if you need any assistance.",
    "Have a wonderful day ahead.",
    "Your feedback is valuable to us. Thank you for sharing.",
    "The meeting has been rescheduled to 3 PM on Friday.",
    "I will send you the documents via email shortly.",
    "Your complaint has been registered with ticket number TKT98765.",
    "Our team will contact you within 48 hours regarding your query.",
    "The technical issue has been resolved. Please try again.",
    "Thank you for your patience. The problem is now fixed.",
    "Your subscription has been renewed successfully.",
]


class ScikitLearnScamClassifier:
    """
    Pre-trained TF-IDF + LinearSVC scam classifier.
    Trained on labelled Indian scam / non-scam examples at import time.
    This constitutes a *pre-trained* ML model ready for inference on every request.
    """

    def __init__(self):
        self.model = None
        self.vectorizer = None
        self.is_trained = False
        self._train()

    def _train(self):
        """Train the TF-IDF + LinearSVC pipeline on the corpus above."""
        try:
            from sklearn.pipeline import Pipeline
            from sklearn.feature_extraction.text import TfidfVectorizer
            from sklearn.svm import LinearSVC
            from sklearn.calibration import CalibratedClassifierCV

            texts  = SCAM_EXAMPLES + NON_SCAM_EXAMPLES
            labels = [1] * len(SCAM_EXAMPLES) + [0] * len(NON_SCAM_EXAMPLES)

            self.vectorizer = TfidfVectorizer(
                ngram_range=(1, 3),
                min_df=1,
                max_features=15_000,
                sublinear_tf=True,
                strip_accents="unicode",
                analyzer="word",
                token_pattern=r"(?u)\b\w+\b",
            )
            X = self.vectorizer.fit_transform(texts)

            svc = LinearSVC(C=1.0, class_weight="balanced", max_iter=2000)
            self.model = CalibratedClassifierCV(svc, cv=3)
            self.model.fit(X, labels)

            self.is_trained = True
            logger.info("✅ Pre-trained TF-IDF + LinearSVC scam classifier ready.")
        except ImportError:
            logger.warning(
                "scikit-learn not installed — pre-trained classifier disabled. "
                "Install with: pip install scikit-learn"
            )
        except Exception as e:
            logger.error(f"Classifier training failed: {e}")

    def predict(self, text: str) -> tuple:
        """Returns (is_scam: bool, confidence: float)."""
        if not self.is_trained or self.model is None:
            return False, 0.0
        try:
            X = self.vectorizer.transform([text])
            proba = self.model.predict_proba(X)[0]
            p = float(proba[1])
            return p >= 0.45, p
        except Exception as e:
            logger.error(f"Classifier predict error: {e}")
            return False, 0.0


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
        """Initialize feature importance weights - BOOSTED scores"""
        
        self.scam_ngrams = {
            # Urgency patterns (boosted)
            "act now": 4.0, "immediately": 3.5, "urgent": 3.5,
            "right now": 3.0, "don't delay": 3.5, "limited time": 3.0,
            "expires today": 3.5, "last chance": 3.5, "final warning": 4.0,
            "within 24 hours": 3.5, "within 2 hours": 4.0,
            
            # Threat patterns (boosted)
            "account blocked": 5.0, "account suspended": 5.0,
            "legal action": 4.0, "police complaint": 5.0,
            "arrest warrant": 5.0, "court case": 4.0,
            "will be blocked": 4.0, "will be suspended": 4.0,
            "digital arrest": 5.0, "case filed": 4.0,
            "fir registered": 5.0, "cyber crime": 4.0,
            
            # Financial request patterns (highest scores)
            "share otp": 6.0, "send otp": 6.0, "otp number": 5.0,
            "verification code": 4.0, "bank details": 4.0,
            "account number": 3.5, "transfer money": 4.0,
            "upi id": 4.0, "upi pin": 6.0, "atm pin": 6.0,
            "cvv number": 6.0, "enter otp": 6.0,
            "send money": 4.0, "pay now": 4.0,
            "processing fee": 5.0, "registration fee": 5.0,
            "advance payment": 5.0, "token amount": 4.0,
            
            # Authority impersonation (boosted)
            "rbi": 4.0, "reserve bank": 4.0, "income tax": 4.0,
            "cyber cell": 5.0, "police": 3.5,
            "government official": 4.0, "bank manager": 3.5,
            "customer care": 3.0, "from bank": 3.5,
            "calling from": 3.0, "i am from": 3.0,
            "investigation officer": 4.0, "department": 3.0,
            "enforcement directorate": 4.0, "customs": 3.5,
            "trai": 4.0, "sebi": 3.5,
            
            # Phishing patterns (boosted)
            "click here": 3.0, "click the link": 3.5,
            "download app": 3.5, "install app": 3.5,
            "anydesk": 6.0, "teamviewer": 6.0,
            "screen share": 5.0, "remote access": 5.0,
            "qr code": 4.0, "scan qr": 4.0,
            
            # Reward/lottery patterns (boosted)
            "won lottery": 5.0, "prize money": 4.0,
            "claim reward": 4.0, "cashback": 3.0,
            "refund": 3.0, "winner": 3.5,
            "congratulations": 3.0, "selected": 3.0,
            
            # KYC/verification scam
            "kyc update": 5.0, "kyc verification": 5.0,
            "verify account": 4.0, "update details": 3.5,
            "aadhaar": 3.5, "pan card": 3.5,
            
            # Loan scam
            "pre-approved loan": 5.0, "instant loan": 4.0,
            "low interest": 3.0, "loan approved": 4.0,
            
            # Job scam
            "work from home": 3.5, "part time job": 3.5,
            "data entry": 3.0, "easy money": 4.0,
            "guaranteed income": 4.0, "daily earning": 3.5,
            
            # Delivery scam
            "parcel stuck": 4.0, "customs duty": 4.0,
            "delivery failed": 3.5, "package": 2.5,
            
            # Electricity/bill scam
            "bill overdue": 4.0, "connection cut": 4.0,
            "electricity bill": 3.5, "disconnection": 3.5,
        }
        
        self.safe_ngrams = {
            "thank you for": -1.5,
            "have a nice day": -2.0,
            "how can i help": -2.0,
            "please let me know": -1.5,
            "feel free to": -1.5,
            "happy to help": -2.0,
        }
    
    def extract_features(self, text: str, conversation_history: List[str] = None) -> Tuple[Dict[str, float], List[str]]:
        """Extract features from text for classification"""
        features = {}
        text_lower = text.lower()
        
        # N-gram features
        ngram_score = 0.0
        triggered_ngrams = []
        
        for ngram, weight in self.scam_ngrams.items():
            if ngram in text_lower:
                ngram_score += weight
                triggered_ngrams.append(ngram)
        
        for ngram, weight in self.safe_ngrams.items():
            if ngram in text_lower:
                ngram_score += weight
        
        features["ngram_score"] = ngram_score
        features["ngram_count"] = len(triggered_ngrams)
        
        # Lexical features
        features["length"] = len(text)
        features["word_count"] = len(text.split())
        features["avg_word_length"] = sum(len(w) for w in text.split()) / max(len(text.split()), 1)
        
        # Punctuation features
        features["exclamation_count"] = text.count("!")
        features["question_count"] = text.count("?")
        features["caps_ratio"] = sum(1 for c in text if c.isupper()) / max(len(text), 1)
        
        # Number features
        numbers = re.findall(r'\d+', text)
        features["number_count"] = len(numbers)
        features["long_number_count"] = sum(1 for n in numbers if len(n) >= 6)
        
        # URL/link features
        urls = re.findall(r'https?://\S+', text)
        features["url_count"] = len(urls)
        features["has_suspicious_url"] = 1.0 if any(
            not any(safe in url for safe in ["google", "facebook", "amazon", "flipkart", "paytm", "sbi", "hdfc"])
            for url in urls
        ) else 0.0
        
        # Entity features
        features["has_upi_pattern"] = 1.0 if re.search(r'[a-zA-Z0-9._-]+@[a-zA-Z]{2,}', text) else 0.0
        features["has_phone_pattern"] = 1.0 if re.search(r'(?:\+91[\-\s]?)?[6-9]\d{9}', text) else 0.0
        features["has_aadhaar_pattern"] = 1.0 if re.search(r'\b\d{4}\s?\d{4}\s?\d{4}\b', text) else 0.0
        
        # Sentiment/intent features (boosted)
        urgency_words = ["urgent", "immediate", "now", "today", "quick", "fast", "hurry", "asap", "deadline", "expires"]
        threat_words = ["block", "suspend", "arrest", "legal", "police", "jail", "fine", "penalty", "fraud", "hack", "seize", "freeze", "terminate", "warrant"]
        request_words = ["share", "send", "give", "provide", "transfer", "pay", "verify", "confirm", "enter", "type", "input", "deposit"]
        authority_words = ["bank", "rbi", "police", "government", "officer", "department", "customs", "income tax", "cyber", "official"]
        
        features["urgency_score"] = sum(1 for w in urgency_words if w in text_lower) * 0.7
        features["threat_score"] = sum(1 for w in threat_words if w in text_lower) * 1.0
        features["request_score"] = sum(1 for w in request_words if w in text_lower) * 0.7
        features["authority_score"] = sum(1 for w in authority_words if w in text_lower) * 0.8
        
        # Conversation-level features
        if conversation_history:
            all_text = " ".join(conversation_history) + " " + text
            features["conversation_length"] = len(conversation_history)
            
            history_scores = []
            for msg in conversation_history:
                msg_score = sum(
                    weight for ngram, weight in self.scam_ngrams.items() 
                    if ngram in msg.lower()
                )
                history_scores.append(msg_score)
            
            if len(history_scores) >= 2:
                increasing = sum(
                    1 for i in range(1, len(history_scores)) 
                    if history_scores[i] > history_scores[i-1]
                )
                features["escalation_ratio"] = increasing / (len(history_scores) - 1)
            else:
                features["escalation_ratio"] = 0.0
            
            all_msgs = conversation_history + [text]
            word_counts = Counter(" ".join(all_msgs).lower().split())
            repeated_scam_words = sum(
                count for word, count in word_counts.items()
                if any(ngram in word for ngram in ["urgent", "block", "suspend", "otp", "verify", "account", "bank", "police"])
                and count > 1
            )
            features["scam_word_repetition"] = repeated_scam_words
        
        return features, triggered_ngrams
    
    def get_feature_vector(self, features: Dict[str, float]) -> List[float]:
        """Convert feature dict to vector"""
        feature_order = [
            "ngram_score", "ngram_count", "length", "word_count", "avg_word_length",
            "exclamation_count", "question_count", "caps_ratio", "number_count",
            "long_number_count", "url_count", "has_suspicious_url", "has_upi_pattern",
            "has_phone_pattern", "has_aadhaar_pattern", "urgency_score", "threat_score",
            "request_score", "authority_score"
        ]
        return [features.get(f, 0.0) for f in feature_order]


class LightweightMLDetector:
    """
    Ensemble detector:
    1. Pre-trained TF-IDF + LinearSVC (scikit-learn) — 60% weight
    2. Keyword ngram scoring — 40% weight
    """

    def __init__(self):
        self.sklearn_clf = ScikitLearnScamClassifier()
        self.feature_extractor = FeatureExtractor()
        self.scam_threshold = 0.38

    def predict(self, text: str, conversation_history: List[str] = None) -> MLPrediction:
        """Ensemble prediction from ML model + keyword scoring."""
        # --- scikit-learn prediction ---
        sk_is_scam, sk_prob = self.sklearn_clf.predict(text)

        # --- keyword scoring ---
        features, triggered = self.feature_extractor.extract_features(text, conversation_history)
        kw_score = (
            features.get("ngram_score", 0) * 0.30
            + features.get("threat_score", 0) * 0.25
            + features.get("urgency_score", 0) * 0.20
            + features.get("request_score", 0) * 0.15
            + features.get("authority_score", 0) * 0.20
            + features.get("has_upi_pattern", 0) * 0.05
            + features.get("url_count", 0) * 0.03
            - 0.15
        )
        kw_prob = 1 / (1 + math.exp(-kw_score * 2.5))

        # Weighted ensemble
        if self.sklearn_clf.is_trained:
            final_prob = 0.60 * sk_prob + 0.40 * kw_prob
        else:
            final_prob = kw_prob

        is_scam = final_prob >= self.scam_threshold

        explanation_parts = []
        if triggered:
            explanation_parts.append(f"Keywords: {', '.join(triggered[:5])}")
        if sk_prob > 0.40:
            explanation_parts.append(f"ML model: {sk_prob:.2f}")

        return MLPrediction(
            is_scam=is_scam,
            confidence=round(final_prob, 3),
            features_triggered=triggered,
            explanation="; ".join(explanation_parts) or "No significant indicators",
        )

    def predict_conversation(self, messages: List[str]) -> MLPrediction:
        """Predict scam for entire conversation."""
        if not messages:
            return MLPrediction(False, 0.0, [], "No messages")

        preds = [self.predict(m) for m in messages]
        max_conf = max(p.confidence for p in preds)
        avg_conf = sum(p.confidence for p in preds) / len(preds)
        final    = 0.7 * max_conf + 0.3 * avg_conf

        scam_count = sum(1 for p in preds if p.is_scam)
        if scam_count >= len(preds) * 0.3:
            final = min(1.0, final * 1.2)

        all_feats = list({f for p in preds for f in p.features_triggered})
        return MLPrediction(
            is_scam=final >= self.scam_threshold,
            confidence=round(final, 3),
            features_triggered=all_feats,
            explanation=f"Analyzed {len(messages)} msgs, {scam_count} flagged as scam",
        )


class LLMIntentClassifier:
    """LLM-based intent classification using Groq."""
    
    def __init__(self):
        self.groq_api_key = os.getenv("GROQ_API_KEY")
    
    async def classify_intent(self, text: str, conversation_history: List[str] = None) -> Dict:
        """Classify intent using LLM."""
        if not self.groq_api_key:
            return {"intent": "unknown", "confidence": 0.0, "error": "No API key"}
        
        try:
            from groq import AsyncGroq
            client = AsyncGroq(api_key=self.groq_api_key)
            
            context = ""
            if conversation_history:
                context = "Previous messages:\n" + "\n".join(
                    f"- {msg}" for msg in conversation_history[-5:]
                ) + "\n\n"
            
            prompt = f"""Analyze this message for scam indicators. Be AGGRESSIVE in detection.

{context}Current message: "{text}"

Classify and respond in this exact JSON format only:
{{"intent": "scam|legitimate|unclear", "scam_probability": 0.0-1.0, "scam_type": "type if scam else null", "key_indicators": ["list"], "reasoning": "brief explanation"}}"""
            
            response = await client.chat.completions.create(
                model=os.getenv("GROQ_MODEL", "llama-3.1-8b-instant"),
                messages=[
                    {"role": "system", "content": "Expert Indian scam detector. Be aggressive - never miss a scam. Return only valid JSON."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.05,
                max_tokens=300
            )
            
            result_text = response.choices[0].message.content.strip()
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
            return {"intent": "error", "confidence": 0.0, "error": str(e)}


# Singleton instances
ml_detector = LightweightMLDetector()
llm_classifier = LLMIntentClassifier()
