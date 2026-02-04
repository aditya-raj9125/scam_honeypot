"""
STATE MACHINE - Finite State Machine for conversation management
Controls conversation flow and agent behavior based on scam detection state
"""

from enum import Enum, auto
from typing import Dict, Optional, List, Callable
from dataclasses import dataclass, field
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

class ConversationState(Enum):
    """
    Conversation states in the scam detection lifecycle.
    
    State Flow:
    INIT -> MONITORING -> SUSPICIOUS -> SCAM_CONFIRMED -> AGENT_ACTIVE -> INTELLIGENCE_GATHERING -> TERMINATED
                |            |              |
                v            v              v
           SAFE_EXIT    SAFE_EXIT      TERMINATED
    """
    INIT = auto()                    # Initial state, first message
    MONITORING = auto()              # Normal conversation monitoring
    SUSPICIOUS = auto()              # Elevated risk detected
    SCAM_CONFIRMED = auto()          # Scam definitively detected
    AGENT_ACTIVE = auto()            # AI agent actively engaging
    INTELLIGENCE_GATHERING = auto()  # Extracting scammer information
    TERMINATED = auto()              # Conversation ended
    SAFE_EXIT = auto()               # Determined to be safe, exit gracefully

@dataclass
class StateTransition:
    """Represents a state transition with conditions"""
    from_state: ConversationState
    to_state: ConversationState
    condition: str
    priority: int = 0  # Higher priority transitions checked first

@dataclass
class SessionState:
    """Complete state information for a session"""
    session_id: str
    current_state: ConversationState
    previous_state: Optional[ConversationState] = None
    state_history: List[tuple] = field(default_factory=list)  # (state, timestamp)
    turn_count: int = 0
    state_data: Dict = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    
    # State-specific counters
    suspicious_turns: int = 0
    safe_turns: int = 0
    intelligence_items_collected: int = 0
    max_turns: int = 50  # Safety limit

class ConversationStateMachine:
    """
    Finite State Machine for managing conversation states.
    Handles state transitions based on risk assessment and conversation context.
    """
    
    def __init__(self):
        self.sessions: Dict[str, SessionState] = {}
        self._init_transitions()
    
    def _init_transitions(self):
        """Define valid state transitions with conditions"""
        self.transitions = [
            # From INIT
            StateTransition(
                ConversationState.INIT,
                ConversationState.SCAM_CONFIRMED,
                "hard_rule_triggered",
                priority=10
            ),
            StateTransition(
                ConversationState.INIT,
                ConversationState.SUSPICIOUS,
                "risk_score >= 50",
                priority=5
            ),
            StateTransition(
                ConversationState.INIT,
                ConversationState.MONITORING,
                "default",
                priority=0
            ),
            
            # From MONITORING
            StateTransition(
                ConversationState.MONITORING,
                ConversationState.SCAM_CONFIRMED,
                "scam_confirmed",
                priority=10
            ),
            StateTransition(
                ConversationState.MONITORING,
                ConversationState.SUSPICIOUS,
                "risk_score >= 50",
                priority=5
            ),
            StateTransition(
                ConversationState.MONITORING,
                ConversationState.SAFE_EXIT,
                "safe_turns >= 5 and risk_score < 20",
                priority=3
            ),
            
            # From SUSPICIOUS
            StateTransition(
                ConversationState.SUSPICIOUS,
                ConversationState.SCAM_CONFIRMED,
                "scam_confirmed",
                priority=10
            ),
            StateTransition(
                ConversationState.SUSPICIOUS,
                ConversationState.MONITORING,
                "risk_score < 30 and suspicious_turns >= 3",
                priority=5
            ),
            StateTransition(
                ConversationState.SUSPICIOUS,
                ConversationState.SCAM_CONFIRMED,
                "suspicious_turns >= 3 and risk_score >= 80",
                priority=8
            ),
            
            # From SCAM_CONFIRMED
            StateTransition(
                ConversationState.SCAM_CONFIRMED,
                ConversationState.AGENT_ACTIVE,
                "default",
                priority=0
            ),
            
            # From AGENT_ACTIVE
            StateTransition(
                ConversationState.AGENT_ACTIVE,
                ConversationState.INTELLIGENCE_GATHERING,
                "engagement_established",
                priority=5
            ),
            StateTransition(
                ConversationState.AGENT_ACTIVE,
                ConversationState.TERMINATED,
                "max_turns_reached",
                priority=10
            ),
            
            # From INTELLIGENCE_GATHERING
            StateTransition(
                ConversationState.INTELLIGENCE_GATHERING,
                ConversationState.TERMINATED,
                "intelligence_complete or max_turns_reached",
                priority=5
            ),
        ]
        
        # Sort by priority (descending)
        self.transitions.sort(key=lambda t: t.priority, reverse=True)
    
    def get_or_create_session(self, session_id: str) -> SessionState:
        """Get existing session or create new one"""
        if session_id not in self.sessions:
            self.sessions[session_id] = SessionState(
                session_id=session_id,
                current_state=ConversationState.INIT
            )
            logger.info(f"Created new session state: {session_id}")
        return self.sessions[session_id]
    
    def get_current_state(self, session_id: str) -> ConversationState:
        """Get current state for session"""
        session = self.get_or_create_session(session_id)
        return session.current_state
    
    def transition(
        self,
        session_id: str,
        risk_score: float,
        scam_confirmed: bool,
        hard_rule_triggered: bool = False,
        engagement_established: bool = False,
        intelligence_complete: bool = False
    ) -> tuple[ConversationState, bool]:
        """
        Attempt state transition based on current conditions.
        Returns (new_state, did_transition)
        """
        session = self.get_or_create_session(session_id)
        session.turn_count += 1
        session.updated_at = datetime.now()
        
        # Update counters
        if risk_score >= 50:
            session.suspicious_turns += 1
            session.safe_turns = 0
        elif risk_score < 20:
            session.safe_turns += 1
        else:
            session.safe_turns = 0
        
        # Check max turns
        max_turns_reached = session.turn_count >= session.max_turns
        
        # Build condition context
        context = {
            "risk_score": risk_score,
            "scam_confirmed": scam_confirmed,
            "hard_rule_triggered": hard_rule_triggered,
            "engagement_established": engagement_established,
            "intelligence_complete": intelligence_complete,
            "max_turns_reached": max_turns_reached,
            "suspicious_turns": session.suspicious_turns,
            "safe_turns": session.safe_turns,
        }
        
        # Find matching transition
        current_state = session.current_state
        new_state = current_state
        
        for transition in self.transitions:
            if transition.from_state != current_state:
                continue
            
            if self._evaluate_condition(transition.condition, context):
                new_state = transition.to_state
                break
        
        # Apply transition if state changed
        did_transition = new_state != current_state
        if did_transition:
            session.previous_state = current_state
            session.current_state = new_state
            session.state_history.append((new_state, datetime.now()))
            logger.info(f"Session {session_id}: {current_state.name} -> {new_state.name}")
        
        return new_state, did_transition
    
    def _evaluate_condition(self, condition: str, context: Dict) -> bool:
        """Evaluate a transition condition string"""
        if condition == "default":
            return True
        
        try:
            # Safe evaluation of simple conditions
            # Replace variable names with values
            expr = condition
            for key, value in context.items():
                if isinstance(value, bool):
                    expr = expr.replace(key, str(value))
                elif isinstance(value, (int, float)):
                    expr = expr.replace(key, str(value))
            
            # Evaluate the expression
            return eval(expr)
        except Exception as e:
            logger.warning(f"Failed to evaluate condition '{condition}': {e}")
            return False
    
    def force_state(self, session_id: str, new_state: ConversationState):
        """Force a state transition (for testing or override)"""
        session = self.get_or_create_session(session_id)
        session.previous_state = session.current_state
        session.current_state = new_state
        session.state_history.append((new_state, datetime.now()))
        logger.info(f"Session {session_id}: Forced to {new_state.name}")
    
    def is_agent_mode(self, session_id: str) -> bool:
        """Check if agent should be actively engaging"""
        state = self.get_current_state(session_id)
        return state in [
            ConversationState.SCAM_CONFIRMED,
            ConversationState.AGENT_ACTIVE,
            ConversationState.INTELLIGENCE_GATHERING
        ]
    
    def is_terminated(self, session_id: str) -> bool:
        """Check if conversation is terminated"""
        state = self.get_current_state(session_id)
        return state in [
            ConversationState.TERMINATED,
            ConversationState.SAFE_EXIT
        ]
    
    def get_state_info(self, session_id: str) -> Dict:
        """Get detailed state information for a session"""
        session = self.get_or_create_session(session_id)
        return {
            "current_state": session.current_state.name,
            "previous_state": session.previous_state.name if session.previous_state else None,
            "turn_count": session.turn_count,
            "suspicious_turns": session.suspicious_turns,
            "safe_turns": session.safe_turns,
            "state_history": [
                {"state": s.name, "timestamp": t.isoformat()}
                for s, t in session.state_history
            ],
            "is_agent_mode": self.is_agent_mode(session_id),
            "is_terminated": self.is_terminated(session_id),
        }
    
    def get_behavior_profile(self, session_id: str) -> Dict:
        """Get behavior profile based on current state"""
        state = self.get_current_state(session_id)
        
        profiles = {
            ConversationState.INIT: {
                "persona": "curious_user",
                "engagement_level": "low",
                "information_sharing": "minimal",
                "question_asking": "basic",
            },
            ConversationState.MONITORING: {
                "persona": "cautious_user",
                "engagement_level": "medium",
                "information_sharing": "minimal",
                "question_asking": "clarifying",
            },
            ConversationState.SUSPICIOUS: {
                "persona": "confused_user",
                "engagement_level": "medium",
                "information_sharing": "minimal",
                "question_asking": "probing",
            },
            ConversationState.SCAM_CONFIRMED: {
                "persona": "naive_victim",
                "engagement_level": "high",
                "information_sharing": "gradual",
                "question_asking": "detailed",
            },
            ConversationState.AGENT_ACTIVE: {
                "persona": "cooperative_victim",
                "engagement_level": "high",
                "information_sharing": "strategic",
                "question_asking": "intelligence_gathering",
            },
            ConversationState.INTELLIGENCE_GATHERING: {
                "persona": "trusting_victim",
                "engagement_level": "maximum",
                "information_sharing": "fake_data",
                "question_asking": "extraction_focused",
            },
        }
        
        return profiles.get(state, profiles[ConversationState.INIT])
    
    def cleanup_session(self, session_id: str):
        """Remove session data"""
        if session_id in self.sessions:
            del self.sessions[session_id]


# Singleton instance
state_machine = ConversationStateMachine()


"""
STATE TRANSITION DIAGRAM (Text-based):

                    ┌─────────────────────────────────────────────────────────────┐
                    │                                                             │
                    │  ┌──────┐     low risk      ┌────────────┐    safe >= 5    │
                    │  │ INIT ├────────────────────► MONITORING ├───────────────►│ SAFE_EXIT
                    │  └──┬───┘                   └─────┬──────┘                 │
                    │     │                             │                         │
                    │     │ risk >= 50                  │ risk >= 50              │
                    │     │                             │                         │
                    │     ▼                             ▼                         │
                    │  ┌──────────┐  scam_confirmed  ┌───────────────┐            │
                    │  │SUSPICIOUS├─────────────────►│SCAM_CONFIRMED │            │
                    │  └──────────┘                  └───────┬───────┘            │
                    │                                        │                    │
                    │                                        │ auto               │
                    │                                        ▼                    │
                    │                                ┌──────────────┐             │
                    │                                │ AGENT_ACTIVE │             │
                    │                                └───────┬──────┘             │
                    │                                        │                    │
                    │                                        │ engaged            │
                    │                                        ▼                    │
                    │                          ┌─────────────────────────┐        │
                    │                          │INTELLIGENCE_GATHERING  │        │
                    │                          └───────────┬─────────────┘        │
                    │                                      │                      │
                    │                                      │ complete/max_turns   │
                    │                                      ▼                      │
                    │                               ┌────────────┐                │
                    └──────────────────────────────►│ TERMINATED │◄───────────────┘
                           max_turns               └────────────┘
"""
