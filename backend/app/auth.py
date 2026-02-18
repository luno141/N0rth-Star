from fastapi import Header, HTTPException

API_KEY = "dev"

def require_api_key(x_api_key: str = Header(None)):
    if x_api_key is None:
        raise HTTPException(status_code=401, detail="Missing API key")

    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")

    return True
