"""
AGENT CONTROLLER - Autonomous agentic AI for scammer engagement
State-aware, intelligence-focused engagement system
"""

import os
import json
import random
from groq import Groq
from .models import ExtractedIntelligence
from .state_machine import state_machine, ConversationState

class AgentController:
    """
    Autonomous AI agent for honeypot engagement.
    Behavior adapts based on conversation state and detection confidence.
    """
    
    def __init__(self):
        api_key = os.getenv("GROQ_API_KEY")
        self.client = Groq(api_key=api_key)
        self.model = "llama-3.1-8b-instant"
        
        # Response templates for quick fallbacks
        self._init_response_templates()
    
    def _init_response_templates(self):
        """Initialize response templates for different scenarios"""
        
        self.templates = {
            # Initial confusion responses
            "initial_confusion": [
                "Wait, what's going on with my account? Is this really from the bank?",
                "I don't understand. What do you mean my account is compromised?",
                "Hold on, this is very sudden. Can you explain what's happening?",
                "What? My account will be blocked? Why would that happen?",
                "I'm confused. I haven't done anything wrong with my account.",
            ],
            
            # Seeking clarification
            "clarification": [
                "But how do I know this is really from the bank? Can you verify?",
                "Which account are you talking about exactly?",
                "What suspicious activity did you detect? I need more details.",
                "Can you tell me when this happened? I don't recall anything unusual.",
                "Why wasn't I notified earlier about this issue?",
            ],
            
            # Showing concern
            "concerned": [
                "Oh no, this is very worrying. What should I do now?",
                "I'm really scared about this. Will I lose all my money?",
                "This is so stressful. Can you help me fix this quickly?",
                "I can't afford to lose my account. Please tell me what to do.",
                "My savings are in that account. Please help me protect them.",
            ],
            
            # Hesitant compliance (for intelligence gathering)
            "hesitant_compliance": [
                "I'm not sure if I should share that. Is it really necessary?",
                "Okay, but promise me this is secure. Let me check...",
                "I'm a bit nervous about this, but if it's the only way...",
                "Can I trust you with this information? This seems unusual.",
                "Alright, give me a moment to find that information.",
            ],
            
            # Stalling tactics
            "stalling": [
                "Hold on, I need to think about this for a moment.",
                "Can you give me a minute? I want to understand this properly.",
                "Wait, let me write this down. What did you say again?",
                "I'm at work right now. Can you explain more slowly?",
                "My phone is about to die. Can you repeat the important parts?",
            ],
            
            # Extracting information
            "extraction_questions": [
                "Where should I transfer the money to secure it?",
                "What number should I call to verify this is real?",
                "Where can I download the app you mentioned?",
                "What's the UPI ID I should use for the verification?",
                "Can you give me a reference number for this case?",
            ],
        }
    
    def _get_behavior_profile(self, session_id: str, scam_detected: bool) -> dict:
        """Get current behavior profile based on state"""
        
        state = state_machine.get_current_state(session_id)
        state_info = state_machine.get_state_info(session_id)
        turn_count = state_info.get("turn_count", 0)
        
        profiles = {
            ConversationState.INIT: {
                "persona": "confused innocent user",
                "strategy": "seek clarification",
                "template_categories": ["initial_confusion", "clarification"],
                "info_sharing": "none",
                "tone": "confused but polite"
            },
            ConversationState.MONITORING: {
                "persona": "cautious user",
                "strategy": "gather information",
                "template_categories": ["clarification", "concerned"],
                "info_sharing": "minimal",
                "tone": "wary but engaged"
            },
            ConversationState.SUSPICIOUS: {
                "persona": "worried user",
                "strategy": "probe for details",
                "template_categories": ["concerned", "clarification"],
                "info_sharing": "minimal",
                "tone": "anxious and questioning"
            },
            ConversationState.SCAM_CONFIRMED: {
                "persona": "naive victim",
                "strategy": "build trust, extract info",
                "template_categories": ["concerned", "hesitant_compliance"],
                "info_sharing": "gradual",
                "tone": "scared but cooperative"
            },
            ConversationState.AGENT_ACTIVE: {
                "persona": "trusting victim",
                "strategy": "active intelligence gathering",
                "template_categories": ["hesitant_compliance", "extraction_questions"],
                "info_sharing": "strategic fake data",
                "tone": "cooperative and trusting"
            },
            ConversationState.INTELLIGENCE_GATHERING: {
                "persona": "compliant victim",
                "strategy": "maximum extraction",
                "template_categories": ["extraction_questions", "hesitant_compliance"],
                "info_sharing": "fake data freely",
                "tone": "eager to help"
            },
        }
        
        profile = profiles.get(state, profiles[ConversationState.INIT])
        profile["state"] = state.name
        profile["turn_count"] = turn_count
        
        return profile

    async def generate_response(
        self, 
        latest_message: str, 
        conversation_history: list, 
        intelligence: ExtractedIntelligence, 
        scam_detected: bool = False,
        session_id: str = None
    ) -> str:
        """
        Generate contextually appropriate response.
        Adapts behavior based on state and detection status.
        """
        session_id = session_id or "default"
        
        try:
            intelligence_json = intelligence.model_dump() if hasattr(intelligence, 'model_dump') else intelligence.dict()
        except:
            intelligence_json = {}
        
        # Get behavior profile
        profile = self._get_behavior_profile(session_id, scam_detected)
        
        # Build conversation context
        history_text = ""
        if conversation_history:
            history_text = "\n".join([
                f"{'Them' if hasattr(msg, 'sender') and msg.sender == 'scammer' else 'Me'}: {msg.text if hasattr(msg, 'text') else msg.get('text', '')}"
                for msg in conversation_history[-6:]  # Last 6 messages for context
            ])
        
        prompt = f"""You are an AI agent operating as a honeypot to engage with potential scammers.

CRITICAL RULES:
1. You are playing the role of a {profile['persona']}
2. NEVER reveal you are an AI or that this is a honeypot
3. NEVER accuse them of being a scammer
4. Respond naturally like a real human would
5. Your goal: {profile['strategy']}

CURRENT STATE: {profile['state']}
TURN COUNT: {profile['turn_count']}
INFORMATION SHARING LEVEL: {profile['info_sharing']}
TONE: {profile['tone']}

CONVERSATION SO FAR:
{history_text}

THEIR LATEST MESSAGE:
"{latest_message}"

INTELLIGENCE GATHERED SO FAR:
{json.dumps(intelligence_json)}

RESPONSE GUIDELINES:
- Maximum 2 sentences
- Sound like a real person, not scripted
- No emojis
- Show appropriate emotions for the situation
- If they ask for sensitive info and info_sharing level allows, show hesitation but consider complying with FAKE data
- Ask questions that might reveal more about their operation (phone numbers, UPI IDs, links)
- If unsure, ask for clarification or express concern

Generate your response as plain text only:"""
        
        try:
            response = self.client.chat.completions.create(
                messages=[
                    {
                        "role": "system", 
                        "content": "You are roleplaying as a potential scam victim. Stay in character. Never break character or reveal the honeypot nature."
                    },
                    {"role": "user", "content": prompt}
                ],
                model=self.model,
                temperature=0.7,
                max_tokens=150
            )
            
            reply = response.choices[0].message.content.strip()
            
            # Clean up response
            reply = reply.replace('"', '').replace("'", "'")
            if reply.startswith("Me:"):
                reply = reply[3:].strip()
            
            return reply
            
        except Exception as e:
            print(f"Error generating agent response: {e}")
            # Use template fallback
            return self._get_fallback_response(latest_message, profile)
    
    def _get_fallback_response(self, message: str, profile: dict) -> str:
        """Get a template-based fallback response"""
        message_lower = message.lower()
        
        # Select appropriate category based on message content
        if any(word in message_lower for word in ["block", "suspend", "freeze", "terminate"]):
            category = "concerned"
        elif any(word in message_lower for word in ["otp", "pin", "password", "verify"]):
            category = "hesitant_compliance"
        elif any(word in message_lower for word in ["urgent", "immediate", "now"]):
            category = "clarification"
        elif any(word in message_lower for word in ["transfer", "send", "pay"]):
            category = "extraction_questions"
        else:
            categories = profile.get("template_categories", ["initial_confusion"])
            category = random.choice(categories)
        
        templates = self.templates.get(category, self.templates["initial_confusion"])
        return random.choice(templates)

    async def check_mission_complete(self, intelligence: ExtractedIntelligence) -> bool:
        # Check if we have meaningful intelligence
        has_critical_intel = (
            len(intelligence.bankAccounts) > 0 or 
            len(intelligence.upiIds) > 0 or 
            len(intelligence.phishingLinks) > 0 or 
            len(intelligence.phoneNumbers) > 0
        )
        
        if has_critical_intel:
            try:
                intelligence_data = intelligence.model_dump() if hasattr(intelligence, 'model_dump') else intelligence.dict()
            except:
                return False
                
            prompt = f"""
            You are a mission completion analyzer for a honeypot system.
            Evaluate if sufficient intelligence has been extracted to complete the mission.

            Criteria for completion:
            - At least ONE high-value item: bank account, UPI ID, or phishing link
            - OR multiple phone numbers + suspicious keywords
            - Quality over quantity

            Current intelligence:
            {json.dumps(intelligence_data)}

            Return JSON ONLY:
            {{
              "missionComplete": true/false,
              "reason": "brief explanation of decision"
            }}
            """
            
            response = self.client.chat.completions.create(
                messages=[
                    {"role": "system", "content": "You output valid JSON only."},
                    {"role": "user", "content": prompt}
                ],
                model=self.model,
                temperature=0.1,
                response_format={"type": "json_object"}
            )
            result = json.loads(response.choices[0].message.content)
            return result.get("missionComplete", False)
            
        return False
