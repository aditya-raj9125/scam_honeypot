from fastapi import Header, HTTPException, Security, Depends
from typing import Optional
import os
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("HONEYPOT_API_KEY", "mySecretKey123")  # Default for testing

async def get_api_key(x_api_key: str = Header(..., alias="x-api-key")):
    """
    Validate API key from x-api-key header.
    Default key is 'mySecretKey123' if no environment variable is set.
    """
    if API_KEY and x_api_key != API_KEY:
        raise HTTPException(status_code=403, detail="Invalid API Key")
    return x_api_key
