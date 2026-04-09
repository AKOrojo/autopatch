"""Authentication — JWT login with database-backed users."""
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.config import Settings
from src.api.dependencies import get_db, get_settings
from src.api.middleware.auth import verify_password, create_access_token
from src.api.middleware.audit import write_audit_log
from src.api.models.user import User

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


class LoginRequest(BaseModel):
    email: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user_id: str
    role: str


async def _authenticate_user(session: AsyncSession, email: str, password: str) -> User | None:
    result = await session.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()
    if not user or not user.is_active:
        return None
    if not verify_password(password, user.password_hash):
        return None
    return user


@router.post("/login", response_model=TokenResponse)
async def login(request: LoginRequest, settings: Settings = Depends(get_settings), session: AsyncSession = Depends(get_db)):
    user = await _authenticate_user(session, request.email, request.password)
    if not user:
        await write_audit_log(session, "failed_login", {"email": request.email})
        await session.commit()
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_access_token({"sub": str(user.id), "role": user.role}, settings)
    user.last_login_at = datetime.now(timezone.utc)
    await write_audit_log(session, "login", {"email": user.email}, user_id=str(user.id))
    await session.commit()
    return TokenResponse(access_token=token, user_id=str(user.id), role=user.role)
