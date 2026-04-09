"""User management API — admin only."""
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.dependencies import get_db, require_admin
from src.api.middleware.auth import hash_password
from src.api.middleware.audit import write_audit_log
from src.api.models.user import User

router = APIRouter(prefix="/api/v1/users", tags=["users"])


class CreateUserRequest(BaseModel):
    email: str
    name: str
    password: str
    role: str = "viewer"


class UpdateUserRequest(BaseModel):
    name: str | None = None
    role: str | None = None
    is_active: bool | None = None


def _user_to_response(u: User) -> dict:
    return {
        "id": str(u.id),
        "email": u.email,
        "name": u.name,
        "role": u.role,
        "is_active": u.is_active,
        "last_login_at": u.last_login_at.isoformat() if u.last_login_at else None,
        "created_at": u.created_at.isoformat() if u.created_at else None,
    }


async def _list_users(session: AsyncSession) -> list[dict]:
    result = await session.execute(select(User).order_by(User.created_at.desc()))
    return [_user_to_response(u) for u in result.scalars().all()]


@router.get("")
async def list_users(admin: User = Depends(require_admin), session: AsyncSession = Depends(get_db)):
    return await _list_users(session)


@router.post("", status_code=201)
async def create_user(request: CreateUserRequest, admin: User = Depends(require_admin), session: AsyncSession = Depends(get_db)):
    if request.role not in ("admin", "operator", "viewer"):
        raise HTTPException(status_code=400, detail="Invalid role")
    existing = await session.execute(select(User).where(User.email == request.email))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Email already exists")
    user = User(email=request.email, name=request.name, password_hash=hash_password(request.password), role=request.role)
    session.add(user)
    await session.flush()
    await write_audit_log(session, "user_created", {"email": request.email, "role": request.role}, user_id=str(admin.id))
    await session.commit()
    return _user_to_response(user)


@router.get("/{user_id}")
async def get_user(user_id: str, admin: User = Depends(require_admin), session: AsyncSession = Depends(get_db)):
    result = await session.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return _user_to_response(user)


@router.put("/{user_id}")
async def update_user(user_id: str, request: UpdateUserRequest, admin: User = Depends(require_admin), session: AsyncSession = Depends(get_db)):
    result = await session.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    pre_state = {"role": user.role, "is_active": user.is_active}
    if request.name is not None:
        user.name = request.name
    if request.role is not None:
        if request.role not in ("admin", "operator", "viewer"):
            raise HTTPException(status_code=400, detail="Invalid role")
        user.role = request.role
    if request.is_active is not None:
        user.is_active = request.is_active
    post_state = {"role": user.role, "is_active": user.is_active}
    await write_audit_log(session, "user_updated", {"user_id": user_id}, user_id=str(admin.id), pre_state=pre_state, post_state=post_state)
    await session.commit()
    return _user_to_response(user)


@router.delete("/{user_id}", status_code=204)
async def deactivate_user(user_id: str, admin: User = Depends(require_admin), session: AsyncSession = Depends(get_db)):
    result = await session.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user.is_active = False
    await write_audit_log(session, "user_deactivated", {"user_id": user_id, "email": user.email}, user_id=str(admin.id))
    await session.commit()
