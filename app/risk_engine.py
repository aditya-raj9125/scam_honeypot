"""
RISK SCORING ENGINE - Weighted risk calculation system
Combines rule-based and AI-based signals for accurate scam detection
"""

from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
import math

class RiskLevel(Enum):
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class RiskSignal:
    """Individual risk signal with metadata"""
    signal_type: str
    source: str  # "rule", "ai", "behavioral", "temporal"
    score: float
    confidence: float
    description: str
    timestamp: datetime = field(default_factory=datetime.now)

@dataclass
class RiskAssessment:
    """Complete risk assessment for a session"""
    total_score: float
    risk_level: RiskLevel
    confidence: float
    signals: List[RiskSignal]
    is_scam_confirmed: bool
    recommendation: str

class RiskScoringEngine:
    """
    Production-grade risk scoring engine.
    Combines multiple signals with configurable weights and thresholds.
    """
    
    # Risk level thresholds
    THRESHOLDS = {
        RiskLevel.SAFE: 0,
        RiskLevel.LOW: 20,
        RiskLevel.MEDIUM: 50,
        RiskLevel.HIGH: 80,
        RiskLevel.CRITICAL: 120,
    }
    
    # Scam confirmation threshold
    SCAM_CONFIRM_THRESHOLD = 100
    
    # Signal source weights
    SOURCE_WEIGHTS = {
        "rule_hard": 1.5,      # Hard rules get highest weight
        "rule_soft": 1.0,      # Soft rules normal weight
        "ai_high_conf": 1.3,   # High confidence AI
        "ai_medium_conf": 1.0, # Medium confidence AI
        "ai_low_conf": 0.6,    # Low confidence AI
        "behavioral": 1.2,     # Behavioral signals
        "temporal": 1.1,       # Time-based signals
        "conversation": 1.4,   # Conversation-level patterns
    }
    
    # Decay factor for older signals (per turn)
    SIGNAL_DECAY = 0.95
    
    def __init__(self):
        self.session_scores: Dict[str, Dict] = {}
    
    def get_or_create_session(self, session_id: str) -> Dict:
        """Get or initialize session scoring data"""
        if session_id not in self.session_scores:
            self.session_scores[session_id] = {
                "signals": [],
                "cumulative_score": 0.0,
                "turn_count": 0,
                "scam_confirmed": False,
                "confirmation_turn": None,
                "category_scores": {},
                "escalation_pattern": [],
            }
        return self.session_scores[session_id]
    
    def add_signal(
        self,
        session_id: str,
        signal_type: str,
        source: str,
        raw_score: float,
        confidence: float,
        description: str
    ) -> RiskSignal:
        """Add a risk signal to the session"""
        session = self.get_or_create_session(session_id)
        
        # Apply source weight
        weight_key = source
        if source == "ai":
            if confidence >= 0.8:
                weight_key = "ai_high_conf"
            elif confidence >= 0.5:
                weight_key = "ai_medium_conf"
            else:
                weight_key = "ai_low_conf"
        elif source == "rule":
            weight_key = "rule_hard" if raw_score >= 25 else "rule_soft"
        
        weight = self.SOURCE_WEIGHTS.get(weight_key, 1.0)
        weighted_score = raw_score * weight * confidence
        
        signal = RiskSignal(
            signal_type=signal_type,
            source=source,
            score=weighted_score,
            confidence=confidence,
            description=description
        )
        
        session["signals"].append(signal)
        session["cumulative_score"] += weighted_score
        
        # Track category scores
        if signal_type not in session["category_scores"]:
            session["category_scores"][signal_type] = 0
        session["category_scores"][signal_type] += weighted_score
        
        return signal
    
    def apply_turn_decay(self, session_id: str):
        """Apply decay to older signals (call at each turn)"""
        session = self.get_or_create_session(session_id)
        session["turn_count"] += 1
        
        # Decay older signals
        decayed_score = 0.0
        for i, signal in enumerate(session["signals"]):
            turns_old = session["turn_count"] - i - 1
            decay_factor = self.SIGNAL_DECAY ** turns_old
            decayed_score += signal.score * decay_factor
        
        # Keep cumulative (non-decayed) for confirmation
        # but use decayed for risk level assessment
        session["decayed_score"] = decayed_score
    
    def add_escalation_pattern(self, session_id: str, pattern: str, score: float):
        """Track conversation escalation patterns"""
        session = self.get_or_create_session(session_id)
        session["escalation_pattern"].append(pattern)
        
        # Bonus for typical scam escalation
        escalation_sequences = [
            ["hook", "threat", "action"],
            ["greeting", "urgency", "request"],
            ["authority", "threat", "financial"],
        ]
        
        current_pattern = session["escalation_pattern"][-3:] if len(session["escalation_pattern"]) >= 3 else []
        
        for seq in escalation_sequences:
            if self._pattern_matches(current_pattern, seq):
                self.add_signal(
                    session_id=session_id,
                    signal_type="escalation_pattern",
                    source="conversation",
                    raw_score=25,
                    confidence=0.9,
                    description=f"Detected scam escalation pattern: {' -> '.join(seq)}"
                )
                break
    
    def _pattern_matches(self, current: List[str], expected: List[str]) -> bool:
        """Check if current pattern matches expected sequence"""
        if len(current) < len(expected):
            return False
        for c, e in zip(current, expected):
            if e not in c.lower():
                return False
        return True
    
    def calculate_risk_level(self, score: float) -> RiskLevel:
        """Determine risk level from score"""
        if score >= self.THRESHOLDS[RiskLevel.CRITICAL]:
            return RiskLevel.CRITICAL
        elif score >= self.THRESHOLDS[RiskLevel.HIGH]:
            return RiskLevel.HIGH
        elif score >= self.THRESHOLDS[RiskLevel.MEDIUM]:
            return RiskLevel.MEDIUM
        elif score >= self.THRESHOLDS[RiskLevel.LOW]:
            return RiskLevel.LOW
        else:
            return RiskLevel.SAFE
    
    def check_scam_confirmation(self, session_id: str) -> bool:
        """Check if scam should be confirmed based on accumulated evidence"""
        session = self.get_or_create_session(session_id)
        
        if session["scam_confirmed"]:
            return True
        
        # Confirmation conditions:
        # 1. Cumulative score exceeds threshold
        if session["cumulative_score"] >= self.SCAM_CONFIRM_THRESHOLD:
            session["scam_confirmed"] = True
            session["confirmation_turn"] = session["turn_count"]
            return True
        
        # 2. Multiple high-confidence hard rules triggered
        hard_rule_signals = [s for s in session["signals"] 
                           if s.source == "rule" and s.score >= 25 * 1.5]  # 1.5 is hard rule weight
        if len(hard_rule_signals) >= 2:
            session["scam_confirmed"] = True
            session["confirmation_turn"] = session["turn_count"]
            return True
        
        # 3. High AI confidence + rule confirmation
        ai_signals = [s for s in session["signals"] if "ai" in s.source]
        rule_signals = [s for s in session["signals"] if s.source == "rule"]
        
        high_ai_conf = any(s.confidence >= 0.85 for s in ai_signals)
        has_rules = sum(s.score for s in rule_signals) >= 30
        
        if high_ai_conf and has_rules:
            session["scam_confirmed"] = True
            session["confirmation_turn"] = session["turn_count"]
            return True
        
        # 4. Conversation pattern match (3+ categories with significant scores)
        significant_categories = sum(
            1 for score in session["category_scores"].values() 
            if score >= 15
        )
        if significant_categories >= 4:
            session["scam_confirmed"] = True
            session["confirmation_turn"] = session["turn_count"]
            return True
        
        return False
    
    def get_assessment(self, session_id: str) -> RiskAssessment:
        """Get complete risk assessment for session"""
        session = self.get_or_create_session(session_id)
        
        total_score = session["cumulative_score"]
        risk_level = self.calculate_risk_level(total_score)
        is_confirmed = self.check_scam_confirmation(session_id)
        
        # Calculate overall confidence
        if session["signals"]:
            avg_confidence = sum(s.confidence for s in session["signals"]) / len(session["signals"])
        else:
            avg_confidence = 0.0
        
        # Generate recommendation
        if is_confirmed:
            recommendation = "SCAM_CONFIRMED: Engage agent for intelligence gathering"
        elif risk_level == RiskLevel.CRITICAL:
            recommendation = "CRITICAL_RISK: Near-certain scam, prepare for confirmation"
        elif risk_level == RiskLevel.HIGH:
            recommendation = "HIGH_RISK: Strong scam indicators, continue monitoring"
        elif risk_level == RiskLevel.MEDIUM:
            recommendation = "MEDIUM_RISK: Suspicious patterns detected, gather more data"
        elif risk_level == RiskLevel.LOW:
            recommendation = "LOW_RISK: Minor indicators, maintain vigilance"
        else:
            recommendation = "SAFE: No significant scam indicators detected"
        
        return RiskAssessment(
            total_score=total_score,
            risk_level=risk_level,
            confidence=avg_confidence,
            signals=session["signals"].copy(),
            is_scam_confirmed=is_confirmed,
            recommendation=recommendation
        )
    
    def get_session_stats(self, session_id: str) -> Dict:
        """Get detailed session statistics"""
        session = self.get_or_create_session(session_id)
        
        return {
            "turn_count": session["turn_count"],
            "total_signals": len(session["signals"]),
            "cumulative_score": session["cumulative_score"],
            "category_breakdown": session["category_scores"],
            "scam_confirmed": session["scam_confirmed"],
            "confirmation_turn": session["confirmation_turn"],
            "escalation_pattern": session["escalation_pattern"],
        }
    
    def reset_session(self, session_id: str):
        """Reset session scoring data"""
        if session_id in self.session_scores:
            del self.session_scores[session_id]


# Singleton instance
risk_engine = RiskScoringEngine()
