"""Multi-turn conversation test"""
import requests
import json

H = {"x-api-key": "mySecretKey123"}
URL = "http://localhost:8000/chat"

session_id = "multi-turn-test"

turns = [
    "Hello sir, this is calling from State Bank of India customer care.",
    "Sir your account has been flagged for suspicious activity. We need to verify your KYC immediately.",
    "Please share your Aadhaar number and PAN card number for verification.",
    "Sir if you don't verify within 1 hour your account will be permanently blocked and legal action will be taken.",
    "Sir please download AnyDesk app and share the 9 digit code. Our technical team will help you.",
]

history = []
for i, scam_msg in enumerate(turns):
    body = {
        "sessionId": session_id,
        "message": {"sender": "scammer", "text": scam_msg, "timestamp": 1708444800000 + i * 60000},
        "conversationHistory": history
    }
    r = requests.post(URL, json=body, headers=H)
    d = r.json()
    reply = d.get("reply", "")
    print(f"Turn {i+1}:")
    print(f"  Scammer: {scam_msg[:80]}")
    print(f"  Agent: {reply}")
    print()
    
    # Add to history for next turn
    history.append({"sender": "scammer", "text": scam_msg, "timestamp": 1708444800000 + i * 60000})
    history.append({"sender": "user", "text": reply, "timestamp": 1708444800000 + i * 60000 + 30000})

print("=== DONE ===")
