from fastapi import Depends, Header, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.config import Settings
from src.api.middleware.auth import verify_token, verify_api_key
from src.api.models.user import User
from src.shared.database import get_session
from src.shared.exceptions import UnauthorizedError

_settings: Settings | None = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings


async def get_db(session: AsyncSession = Depends(get_session)) -> AsyncSession:
    return session


def get_current_user(request: Request, settings: Settings = Depends(get_settings)) -> dict:
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise UnauthorizedError(detail="Missing or invalid Authorization header")
    token = auth_header.split(" ", 1)[1]
    return verify_token(token, settings)


def get_api_key_user(
    x_api_key: str = Header(None, alias="X-API-Key"),
    settings: Settings = Depends(get_settings),
) -> bool:
    if not x_api_key or not verify_api_key(x_api_key, settings):
        raise UnauthorizedError(detail="Invalid API key")
    return True


def get_authenticated(request: Request, settings: Settings = Depends(get_settings)) -> dict | bool:
    api_key = request.headers.get("X-API-Key")
    if api_key and verify_api_key(api_key, settings):
        return {"auth_type": "api_key"}
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ", 1)[1]
        payload = verify_token(token, settings)
        payload["auth_type"] = "jwt"
        return payload
    raise UnauthorizedError(detail="No valid authentication provided")


def _check_role(user: User, allowed_roles: list[str]) -> None:
    if not user.is_active:
        raise HTTPException(status_code=403, detail="User account is deactivated")
    if user.role not in allowed_roles:
        raise HTTPException(status_code=403, detail=f"Role '{user.role}' not authorized")


async def get_current_db_user(
    request: Request,
    settings: Settings = Depends(get_settings),
    session: AsyncSession = Depends(get_db),
) -> User:
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise UnauthorizedError(detail="Missing or invalid Authorization header")
    token = auth_header.split(" ", 1)[1]
    payload = verify_token(token, settings)
    user_id = payload.get("sub")
    result = await session.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise UnauthorizedError(detail="User not found")
    if not user.is_active:
        raise UnauthorizedError(detail="User account is deactivated")
    return user


def require_roles(*roles: str):
    allowed = list(roles)
    async def dependency(user: User = Depends(get_current_db_user)) -> User:
        _check_role(user, allowed)
        return user
    return dependency


require_admin = require_roles("admin")
require_operator = require_roles("admin", "operator")
require_any_role = require_roles("admin", "operator", "viewer")
