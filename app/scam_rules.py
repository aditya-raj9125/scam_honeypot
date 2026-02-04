"""
SCAM RULES ENGINE - Rule-based deterministic scam detection
Production-grade pattern matching for Indian scam patterns
"""

import re
from typing import List, Dict, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum

class RuleCategory(Enum):
    URGENCY = "urgency"
    AUTHORITY = "authority"
    THREAT = "threat"
    FINANCIAL = "financial"
    PERSONAL_INFO = "personal_info"
    PHISHING = "phishing"
    BEHAVIORAL = "behavioral"

@dataclass
class RuleMatch:
    rule_id: str
    category: RuleCategory
    matched_text: str
    score: float
    is_hard_rule: bool = False  # Hard rules immediately confirm scam

class ScamRulesEngine:
    """
    Deterministic rule-based scam detection engine.
    Uses keyword patterns, regex, and behavioral rules.
    """
    
    def __init__(self):
        self._init_keyword_rules()
        self._init_regex_patterns()
        self._init_behavioral_rules()
    
    def _init_keyword_rules(self):
        """Initialize keyword-based detection rules with scores"""
        
        # URGENCY INDICATORS (Score: 5-15)
        self.urgency_keywords = {
            # High urgency (score: 15)
            "immediate action required": 15,
            "act now": 12,
            "urgent": 10,
            "immediately": 10,
            "right now": 10,
            "within 24 hours": 12,
            "within 2 hours": 15,
            "last warning": 15,
            "final notice": 15,
            "deadline": 8,
            "expires today": 12,
            "limited time": 8,
            "don't delay": 10,
            "time sensitive": 10,
            "hurry": 8,
            "asap": 8,
            "quick": 5,
            "fast": 5,
        }
        
        # THREAT INDICATORS (Score: 10-25)
        self.threat_keywords = {
            # High threat (score: 20-25) - HARD RULES
            "account will be blocked": 25,
            "account blocked": 20,
            "account suspended": 20,
            "account terminated": 20,
            "legal action": 20,
            "police complaint": 25,
            "arrest warrant": 25,
            "court case": 20,
            "jail": 25,
            "imprisoned": 25,
            "penalty": 15,
            "fine": 12,
            "blacklisted": 18,
            "deactivated": 15,
            "frozen": 15,
            "seized": 20,
            "compromised": 15,
            "hacked": 15,
            "unauthorized access": 15,
            "suspicious activity": 12,
            "fraud detected": 15,
        }
        
        # AUTHORITY IMPERSONATION (Score: 15-30) - HARD RULES
        self.authority_keywords = {
            "rbi": 25,
            "reserve bank": 25,
            "income tax": 25,
            "it department": 20,
            "customs": 20,
            "cyber cell": 25,
            "cyber crime": 25,
            "police": 20,
            "cbi": 25,
            "ed": 20,  # Enforcement Directorate
            "sebi": 20,
            "government": 15,
            "official": 12,
            "authorized": 10,
            "verified": 10,
            "certified": 10,
            "bank manager": 18,
            "customer care": 15,
            "support team": 12,
            "security team": 15,
            "fraud department": 18,
        }
        
        # FINANCIAL REQUEST INDICATORS (Score: 15-30) - HARD RULES
        self.financial_keywords = {
            "share otp": 30,
            "send otp": 30,
            "give otp": 30,
            "otp number": 25,
            "verification code": 20,
            "pin number": 25,
            "atm pin": 30,
            "cvv": 30,
            "card number": 25,
            "account number": 20,
            "bank details": 20,
            "transfer money": 25,
            "send money": 25,
            "pay now": 20,
            "payment required": 18,
            "processing fee": 20,
            "refund": 15,
            "cashback": 12,
            "prize money": 20,
            "lottery": 25,
            "winner": 15,
            "claim reward": 18,
        }
        
        # PERSONAL INFO REQUESTS (Score: 10-25)
        self.personal_info_keywords = {
            "upi id": 25,
            "upi pin": 30,
            "aadhaar": 25,
            "aadhar": 25,
            "pan card": 20,
            "pan number": 20,
            "date of birth": 15,
            "dob": 12,
            "mother's maiden name": 20,
            "security question": 18,
            "password": 25,
            "login details": 25,
            "credentials": 20,
            "kyc": 18,
            "verify identity": 15,
            "identity verification": 15,
        }
        
        # PHISHING INDICATORS (Score: 15-25)
        self.phishing_keywords = {
            "click here": 15,
            "click the link": 18,
            "visit this link": 15,
            "download app": 18,
            "install app": 20,
            "remote access": 25,
            "anydesk": 30,
            "teamviewer": 30,
            "screen share": 25,
            "form fill": 15,
            "update details": 15,
            "verify account": 15,
        }
    
    def _init_regex_patterns(self):
        """Initialize regex patterns for structured data detection"""
        
        self.regex_patterns = {
            # UPI ID pattern (score: 20)
            "upi_id": (
                re.compile(r'[a-zA-Z0-9._-]+@[a-zA-Z]{2,}', re.IGNORECASE),
                20, RuleCategory.FINANCIAL
            ),
            
            # Phone numbers (score: 10)
            "phone_number": (
                re.compile(r'(?:\+91[\-\s]?)?[6-9]\d{9}'),
                10, RuleCategory.PERSONAL_INFO
            ),
            
            # Bank account numbers (score: 15)
            "bank_account": (
                re.compile(r'\d{9,18}'),
                8, RuleCategory.FINANCIAL
            ),
            
            # IFSC codes (score: 15)
            "ifsc_code": (
                re.compile(r'[A-Z]{4}0[A-Z0-9]{6}', re.IGNORECASE),
                15, RuleCategory.FINANCIAL
            ),
            
            # OTP patterns (score: 25)
            "otp_request": (
                re.compile(r'\b(otp|one\s*time\s*password|verification\s*code)\b', re.IGNORECASE),
                25, RuleCategory.FINANCIAL
            ),
            
            # Suspicious URLs (score: 20)
            "suspicious_url": (
                re.compile(r'https?://(?!(?:www\.)?(?:google|facebook|amazon|flipkart|paytm|phonepe|gpay|sbi|hdfc|icici|axis)\.)[^\s]+', re.IGNORECASE),
                20, RuleCategory.PHISHING
            ),
            
            # Money amounts (score: 10)
            "money_amount": (
                re.compile(r'(?:rs\.?|₹|inr)\s*[\d,]+(?:\.\d{2})?|\d+\s*(?:rupees?|rs)', re.IGNORECASE),
                10, RuleCategory.FINANCIAL
            ),
            
            # Aadhaar numbers (score: 25)
            "aadhaar": (
                re.compile(r'\b\d{4}\s?\d{4}\s?\d{4}\b'),
                25, RuleCategory.PERSONAL_INFO
            ),
            
            # PAN numbers (score: 20)
            "pan_number": (
                re.compile(r'\b[A-Z]{5}\d{4}[A-Z]\b', re.IGNORECASE),
                20, RuleCategory.PERSONAL_INFO
            ),
            
            # CVV (score: 30)
            "cvv_request": (
                re.compile(r'\b(cvv|cvc|security\s*code)\b', re.IGNORECASE),
                30, RuleCategory.FINANCIAL
            ),
        }
    
    def _init_behavioral_rules(self):
        """Initialize behavioral pattern detection rules"""
        
        self.behavioral_patterns = {
            # Message starts with urgency
            "starts_with_urgent": (
                re.compile(r'^(?:urgent|important|alert|warning|attention)', re.IGNORECASE),
                15
            ),
            # All caps (shouting)
            "excessive_caps": (
                re.compile(r'[A-Z]{10,}'),
                10
            ),
            # Multiple exclamation marks
            "excessive_exclamation": (
                re.compile(r'!{2,}'),
                8
            ),
            # Pressure phrases
            "pressure_phrase": (
                re.compile(r'(don\'?t\s+(ignore|delay|wait)|must\s+act|failure\s+to\s+comply)', re.IGNORECASE),
                15
            ),
        }
    
    def analyze_message(self, text: str) -> Tuple[List[RuleMatch], float]:
        """
        Analyze a single message for scam indicators.
        Returns list of matches and total score.
        """
        matches = []
        text_lower = text.lower()
        
        # Check keyword rules
        for category, keywords in [
            (RuleCategory.URGENCY, self.urgency_keywords),
            (RuleCategory.THREAT, self.threat_keywords),
            (RuleCategory.AUTHORITY, self.authority_keywords),
            (RuleCategory.FINANCIAL, self.financial_keywords),
            (RuleCategory.PERSONAL_INFO, self.personal_info_keywords),
            (RuleCategory.PHISHING, self.phishing_keywords),
        ]:
            for keyword, score in keywords.items():
                if keyword in text_lower:
                    is_hard = score >= 25  # High score = hard rule
                    matches.append(RuleMatch(
                        rule_id=f"kw_{category.value}_{keyword[:20]}",
                        category=category,
                        matched_text=keyword,
                        score=score,
                        is_hard_rule=is_hard
                    ))
        
        # Check regex patterns
        for pattern_name, (pattern, score, category) in self.regex_patterns.items():
            found = pattern.findall(text)
            if found:
                is_hard = score >= 25
                matches.append(RuleMatch(
                    rule_id=f"regex_{pattern_name}",
                    category=category,
                    matched_text=str(found[:3]),  # Limit matched text
                    score=score,
                    is_hard_rule=is_hard
                ))
        
        # Check behavioral patterns
        for pattern_name, (pattern, score) in self.behavioral_patterns.items():
            if pattern.search(text):
                matches.append(RuleMatch(
                    rule_id=f"behavior_{pattern_name}",
                    category=RuleCategory.BEHAVIORAL,
                    matched_text=pattern_name,
                    score=score,
                    is_hard_rule=False
                ))
        
        total_score = sum(m.score for m in matches)
        return matches, total_score
    
    def analyze_conversation(self, messages: List[str]) -> Tuple[List[RuleMatch], float, Set[RuleCategory]]:
        """
        Analyze entire conversation for cumulative scam indicators.
        Returns all matches, total score, and unique categories detected.
        """
        all_matches = []
        categories_detected = set()
        
        for msg in messages:
            matches, _ = self.analyze_message(msg)
            all_matches.extend(matches)
            for m in matches:
                categories_detected.add(m.category)
        
        # Apply conversation-level bonuses
        total_score = sum(m.score for m in all_matches)
        
        # Bonus for multiple categories (indicates sophisticated scam)
        if len(categories_detected) >= 3:
            total_score *= 1.2
        if len(categories_detected) >= 5:
            total_score *= 1.3
        
        # Bonus for repeated patterns (persistence)
        rule_counts = {}
        for m in all_matches:
            rule_counts[m.rule_id] = rule_counts.get(m.rule_id, 0) + 1
        
        repeated_rules = sum(1 for count in rule_counts.values() if count > 1)
        if repeated_rules >= 2:
            total_score *= 1.15
        
        return all_matches, total_score, categories_detected
    
    def has_hard_rule_match(self, matches: List[RuleMatch]) -> bool:
        """Check if any hard rule was triggered"""
        return any(m.is_hard_rule for m in matches)
    
    def get_scam_summary(self, matches: List[RuleMatch]) -> Dict:
        """Generate a summary of detected scam indicators"""
        summary = {
            "total_matches": len(matches),
            "hard_rules_triggered": sum(1 for m in matches if m.is_hard_rule),
            "categories": {},
            "top_indicators": []
        }
        
        # Group by category
        for m in matches:
            cat = m.category.value
            if cat not in summary["categories"]:
                summary["categories"][cat] = {"count": 0, "score": 0}
            summary["categories"][cat]["count"] += 1
            summary["categories"][cat]["score"] += m.score
        
        # Top indicators by score
        sorted_matches = sorted(matches, key=lambda x: x.score, reverse=True)
        summary["top_indicators"] = [
            {"rule": m.rule_id, "score": m.score, "text": m.matched_text}
            for m in sorted_matches[:5]
        ]
        
        return summary


# Singleton instance
scam_rules_engine = ScamRulesEngine()
