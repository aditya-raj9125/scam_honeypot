import asyncio
import logging
import httpx
from .models import FinalResultPayload

logger = logging.getLogger(__name__)

# Exact callback endpoint as per specification
CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"

# ======================================================================
# ISSUE 6 FIX: RELIABLE, NON-BLOCKING CALLBACK WITH RETRY
# ----------------------------------------------------------------------
# The original send_final_result was awaited inline, which meant a slow
# or failing GUVI endpoint could block or timeout the API response.
#
# DESIGN:
# 1. send_final_result_with_retry() is called via asyncio.create_task()
#    so it runs in the background — the API response returns immediately.
# 2. Up to 3 retries with exponential backoff (2s, 4s, 8s).
# 3. On final failure, session.callback_sent is reset so a future turn
#    can re-trigger the callback attempt.
# 4. The original send_final_result() is preserved for direct use.
# ======================================================================


async def send_final_result(payload: FinalResultPayload) -> bool:
    """
    Single-shot callback to GUVI evaluation endpoint.
    Returns True on success (HTTP 200), False otherwise.
    """
    async with httpx.AsyncClient() as client:
        try:
            data = payload.model_dump() if hasattr(payload, 'model_dump') else payload.dict()
            
            response = await client.post(
                CALLBACK_URL,
                json=data,
                headers={"Content-Type": "application/json"},
                timeout=10.0
            )
            
            logger.info(f"Callback response: status={response.status_code}")
            return response.status_code == 200
            
        except Exception as e:
            logger.error(f"Callback failed: {e}")
            return False


async def send_final_result_with_retry(
    payload: FinalResultPayload,
    session=None,
    max_retries: int = 3,
    base_delay: float = 2.0
) -> bool:
    """
    Background-safe callback with exponential backoff.

    Called via asyncio.create_task() so it NEVER blocks the API response.
    On final failure, resets session.callback_sent to allow future retry.
    """
    for attempt in range(1, max_retries + 1):
        success = await send_final_result(payload)
        if success:
            logger.info(f"✅ Callback succeeded on attempt {attempt}")
            return True
        
        if attempt < max_retries:
            delay = base_delay * (2 ** (attempt - 1))  # 2s, 4s, 8s
            logger.warning(f"⚠️ Callback attempt {attempt} failed, retrying in {delay}s...")
            await asyncio.sleep(delay)
    
    # All retries exhausted — allow future re-trigger
    logger.error(f"❌ Callback failed after {max_retries} attempts")
    if session is not None:
        session.callback_sent = False  # Reset so next turn can retry
    return False
