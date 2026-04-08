from fastapi import APIRouter, Depends
from src.api.dependencies import get_settings
from src.api.config import Settings
from src.api.schemas.auth import LoginRequest, TokenResponse
from src.api.middleware.auth import verify_password, create_access_token
from src.shared.exceptions import UnauthorizedError

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])

# Hardcoded admin for Week 1. Replaced by DB-backed users in Phase 4.
SEED_USERS = {
    "admin": "$2b$12$LJ3m4ys3Lk0TnEMO.LHmG.YBWzCnJCqoGGFoJLOVTeCgrJmOMC6C",  # "changeme"
}

@router.post("/login", response_model=TokenResponse)
async def login(payload: LoginRequest, settings: Settings = Depends(get_settings)):
    hashed = SEED_USERS.get(payload.username)
    if not hashed or not verify_password(payload.password, hashed):
        raise UnauthorizedError(detail="Invalid username or password")
    token = create_access_token(data={"sub": payload.username}, settings=settings)
    return TokenResponse(access_token=token)
