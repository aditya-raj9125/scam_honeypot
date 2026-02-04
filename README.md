# Scam Honeypot API - Deployment Guide

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