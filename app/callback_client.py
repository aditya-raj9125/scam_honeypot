import httpx
from .models import FinalResultPayload

# Exact callback endpoint as per specification
CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"

async def send_final_result(payload: FinalResultPayload):
    """
    Send final extracted intelligence to GUVI evaluation endpoint.
    This is mandatory for evaluation as per the specification.
    """
    async with httpx.AsyncClient() as client:
        try:
            # Convert pydantic model to dict for JSON serialization
            # Use model_dump() for Pydantic v2 compatibility
            data = payload.model_dump() if hasattr(payload, 'model_dump') else payload.dict()
            
            response = await client.post(
                CALLBACK_URL, 
                json=data, 
                headers={"Content-Type": "application/json"},
                timeout=10.0
            )
            
            print(f"Final result callback sent. Status: {response.status_code}")
            print(f"Response: {response.text}")
            
            return response.status_code == 200
            
        except Exception as e:
            print(f"Failed to send final result callback: {e}")
            return False
