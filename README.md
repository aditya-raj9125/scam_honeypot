# Scam Honeypot API

## Description
An intelligent honeypot API that simulates a confused Indian victim to detect scams, extract attacker intelligence, and maximise conversation engagement. It uses a multi-layer detection pipeline (pre-trained ML + LLM + rule engine) and automatically submits structured final output after each scam-confirmed turn.

---

## Tech Stack
- **Language / Framework**: Python 3.11 + FastAPI + Uvicorn
- **LLM**: Groq API — `llama-3.3-70b-versatile` for conversation generation and scam reasoning
- **Pre-trained ML**: scikit-learn TF-IDF + LinearSVC (calibrated), trained on 80+ labelled Indian scam/non-scam examples
- **Rule Engine**: Cumulative weighted risk scoring with hard rules (OTP/PIN/remote-access/payment requests)
- **Intelligence Extraction**: Regex-based extraction — UPI IDs, phone numbers, bank accounts, email addresses, phishing URLs, case IDs, policy/order numbers

---

## Setup Instructions

1. **Clone the repository**
   ```bash
   git clone https://github.com/username/scam_honeypot.git
   cd scam_honeypot
   ```

2. **Create a virtual environment**
   ```bash
   python -m venv .venv
   .venv\Scripts\activate        # Windows
   # source .venv/bin/activate   # Linux/Mac
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Set environment variables** (copy `.env.example` → `.env`)
   ```
   GROQ_API_KEY=your_groq_api_key_here
   HONEYPOT_API_KEY=mySecretKey123
   ```

5. **Run the application**
   ```bash
   uvicorn app.main:app --host 0.0.0.0 --port 8000
   ```

---

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/` | Main honeypot endpoint |
| `POST` | `/chat` | Alternative chat endpoint |
| `GET`  | `/health` | Health check |
| `GET`  | `/session/{session_id}` | Debug — view session state |

### Authentication
```
x-api-key: mySecretKey123
```

### Request Format
```json
{
  "sessionId": "uuid-v4-string",
  "message": {
    "sender": "scammer",
    "text": "URGENT: Your account has been compromised. Share OTP now.",
    "timestamp": 1700000000000
  },
  "conversationHistory": [],
  "metadata": {
    "channel": "SMS",
    "language": "English",
    "locale": "IN"
  }
}
```

### Response Format
```json
{
  "status": "success",
  "reply": "Oh no, what happened to my account? Which bank are you calling from?"
}
```

---

## Approach

### Scam Detection Pipeline
1. **Rule-based signal extraction** — Hard rules (OTP/PIN/remote-access requests) trigger immediate detection; soft rules accumulate a bounded risk score (0–100).
2. **Pre-trained ML classifier** — TF-IDF (1–3 ngrams) + calibrated LinearSVC trained on 80+ labelled examples. Provides calibrated probability as primary signal.
3. **LLM Reasoning Judge** — Groq `llama-3.3-70b-versatile` analyses each message and conversation history to classify scam type, assign risk boost, and identify red flags.
4. **Ensemble decision** — Scam confirmed when: hard rule triggers, LLM confidence ≥ 0.60, risk score ≥ 45, or ML ensemble ≥ 0.38.

### Intelligence Extraction
Every scammer message is parsed with regex patterns covering:
- **UPI IDs** — generic `word@word` pattern (covers all providers)
- **Phone numbers** — Indian format (+91, 10-digit)
- **Bank accounts** — 9–18 digit numbers with context hint
- **Email addresses** — standard email regex
- **Phishing URLs** — HTTP/HTTPS and shortened URLs
- **Case / Reference IDs** — pattern-matched identifiers
- **Policy / Order numbers** — domain-specific patterns

### Engagement Strategy
The agent plays a confused, scared Indian victim persona that evolves through stages:
`NORMAL → HOOK → TRUST → THREAT → ACTION → CONFIRMED`

At each stage the agent:
- Asks investigative questions (employee ID, company name, supervisor, address, website)
- Elicits scammer contact details (UPI ID, phone number, bank account)
- Stalls naturally ("network slow", "app loading") to maximise turn count
- Never reveals real sensitive data

### Final Output Submission
The final output is submitted as a background task after every turn where `scamDetected=True`, so the evaluation system always receives the latest, most complete data. Fields submitted:
- `sessionId`, `scamDetected`, `totalMessagesExchanged`, `engagementDurationSeconds`
- `extractedIntelligence` (all types), `agentNotes`, `scamType`, `confidenceLevel`

---

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `GROQ_API_KEY` | Yes | — | Groq API key for LLM |
| `HONEYPOT_API_KEY` | No | `mySecretKey123` | API authentication key |

---

## Testing

```bash
curl -X POST "http://localhost:8000/" \
  -H "Content-Type: application/json" \
  -H "x-api-key: mySecretKey123" \
  -d '{
    "sessionId": "test-001",
    "message": {
      "sender": "scammer",
      "text": "URGENT: Your SBI account will be blocked today. Share OTP 482910 to verify.",
      "timestamp": 1700000000000
    },
    "conversationHistory": [],
    "metadata": {"channel": "SMS", "language": "English", "locale": "IN"}
  }'
```

Or use the included test script:
```bash
python test_api.py
```


## API Endpoints

### Main Endpoint
- **POST /**: Main honeypot endpoint (for API tester compatibility)
- **POST /chat**: Alternative chat endpoint  
- **GET /**: Health check endpoint
- **GET /health**: Detailed health check

## Required Headers
- `Content-Type: application/json`
- `x-api-key: mySecretKey123` (default, can be overridden with HONEYPOT_API_KEY env var)

## Request Format
```json
{
  "sessionId": "unique-session-id",
  "message": {
    "sender": "scammer",
    "text": "Your bank account will be blocked today. Verify immediately.",
    "timestamp": 1770005528731
  },
  "conversationHistory": [],
  "metadata": {
    "channel": "SMS",
    "language": "English",
    "locale": "IN"
  }
}
```

## Response Format
```json
{
  "status": "success",
  "reply": "Why is my account being suspended?"
}
```

## Environment Variables
- `HONEYPOT_API_KEY`: Custom API key (optional, defaults to "mySecretKey123")
- `GROQ_API_KEY`: Required for AI responses

## Deployment Commands
```bash
# Install dependencies
pip install -r requirements.txt

# Start server
uvicorn app.main:app --host 0.0.0.0 --port 8000

# Or for production
gunicorn app.main:app -w 4 -k uvicorn.workers.UvicornWorker --bind 0.0.0.0:8000
```

## Testing
```bash
curl -X POST "https://your-domain.com/" \
  -H "Content-Type: application/json" \
  -H "x-api-key: mySecretKey123" \
  -d '{
    "sessionId": "test-123",
    "message": {
      "sender": "scammer", 
      "text": "Urgent: Verify your account now!",
      "timestamp": 1770005528731
    },
    "conversationHistory": [],
    "metadata": {
      "channel": "SMS",
      "language": "English",
      "locale": "IN"
    }
  }'
```