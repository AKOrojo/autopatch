from fastapi import Depends, Header, Request
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.config import Settings
from src.api.middleware.auth import verify_token, verify_api_key
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
