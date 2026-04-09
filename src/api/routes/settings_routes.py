"""Global settings API -- admin only."""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from src.api.config import Settings
from src.api.dependencies import get_db, get_settings, require_admin
from src.api.middleware.audit import write_audit_log
from src.api.models.user import User

router = APIRouter(prefix="/api/v1/settings", tags=["settings"])


class SettingsResponse(BaseModel):
    global_mode: str
    gmp_host: str
    gmp_port: int
    llm_model: str
    smtp_host: str
    smtp_from_email: str


class SettingsUpdateRequest(BaseModel):
    global_mode: str | None = None


@router.get("")
async def get_app_settings(admin: User = Depends(require_admin), settings: Settings = Depends(get_settings)):
    return SettingsResponse(global_mode=settings.global_mode, gmp_host=settings.gmp_host,
        gmp_port=settings.gmp_port, llm_model=settings.llm_model,
        smtp_host=settings.smtp_host, smtp_from_email=settings.smtp_from_email)


@router.put("")
async def update_settings(body: SettingsUpdateRequest, admin: User = Depends(require_admin),
    settings: Settings = Depends(get_settings), session: AsyncSession = Depends(get_db)):
    pre_state = {"global_mode": settings.global_mode}
    if body.global_mode is not None:
        if body.global_mode not in ("auto", "manual"):
            raise HTTPException(status_code=400, detail="Invalid mode")
        settings.global_mode = body.global_mode
    post_state = {"global_mode": settings.global_mode}
    await write_audit_log(session, "settings_changed", {"changed_fields": ["global_mode"]},
        user_id=str(admin.id), pre_state=pre_state, post_state=post_state)
    await session.commit()
    return {"global_mode": settings.global_mode}
