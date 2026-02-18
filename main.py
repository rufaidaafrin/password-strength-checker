from fastapi import FastAPI, Request
from pydantic import BaseModel
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from fastapi.responses import JSONResponse
from password_checker import score_password
from fastapi.middleware.cors import CORSMiddleware

limiter = Limiter(key_func=get_remote_address)
app = FastAPI(title="Password Strength Checker API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # allow frontend to call API
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.state.limiter = limiter

class PasswordRequest(BaseModel):
    password: str

@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(
        status_code=429,
        content={"error": "Too many requests. Please slow down."},
    )

@app.post("/check-password")
@limiter.limit("15/minute")
async def check_password(payload: PasswordRequest, request: Request):
    password = payload.password
    return score_password(password)
