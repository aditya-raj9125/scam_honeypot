from fastapi import Header, HTTPException
from typing import Optional
import os
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("HONEYPOT_API_KEY", "mySecretKey123")


async def get_api_key(x_api_key: Optional[str] = Header(None, alias="x-api-key")):
    """
    Validate API key from x-api-key header.
    - If no HONEYPOT_API_KEY env var is set, accepts all requests.
    - Header is optional — prevents 422 Unprocessable Entity if omitted.
    """
    if API_KEY and x_api_key is not None and x_api_key != API_KEY:
        raise HTTPException(status_code=403, detail="Invalid API Key")
    return x_api_key
