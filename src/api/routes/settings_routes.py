"""Global settings API -- admin only. Persists global_mode to Redis."""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from src.api.config import Settings
from src.api.dependencies import get_db, get_settings, require_admin
from src.api.middleware.audit import write_audit_log
from src.api.models.user import User
from src.shared.redis_client import redis_client

router = APIRouter(prefix="/api/v1/settings", tags=["settings"])

REDIS_SETTINGS_KEY = "autopatch:global_settings"


class SettingsResponse(BaseModel):
    global_mode: str
    gmp_host: str
    gmp_port: int
    llm_model: str
    smtp_host: str
    smtp_from_email: str


class SettingsUpdateRequest(BaseModel):
    global_mode: str | None = None


async def _get_global_mode(settings: Settings) -> str:
    """Read global_mode from Redis, falling back to config default."""
    if redis_client:
        val = await redis_client.hget(REDIS_SETTINGS_KEY, "global_mode")
        if val:
            return val
    return settings.global_mode


@router.get("")
async def get_app_settings(admin: User = Depends(require_admin), settings: Settings = Depends(get_settings)):
    global_mode = await _get_global_mode(settings)
    return SettingsResponse(global_mode=global_mode, gmp_host=settings.gmp_host,
        gmp_port=settings.gmp_port, llm_model=settings.llm_model,
        smtp_host=settings.smtp_host, smtp_from_email=settings.smtp_from_email)


@router.put("")
async def update_settings(body: SettingsUpdateRequest, admin: User = Depends(require_admin),
    settings: Settings = Depends(get_settings), session: AsyncSession = Depends(get_db)):
    current_mode = await _get_global_mode(settings)
    pre_state = {"global_mode": current_mode}
    if body.global_mode is not None:
        if body.global_mode not in ("auto", "manual"):
            raise HTTPException(status_code=400, detail="Invalid mode")
        if redis_client:
            await redis_client.hset(REDIS_SETTINGS_KEY, "global_mode", body.global_mode)
        settings.global_mode = body.global_mode
    post_state = {"global_mode": body.global_mode or current_mode}
    await write_audit_log(session, "settings_changed", {"changed_fields": ["global_mode"]},
        user_id=str(admin.id), pre_state=pre_state, post_state=post_state)
    await session.commit()
    return {"global_mode": post_state["global_mode"]}
