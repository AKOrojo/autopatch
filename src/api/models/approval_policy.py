import uuid
from datetime import datetime, timezone

from sqlalchemy import String, Float, Boolean, DateTime
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from src.shared.database import Base


class ApprovalPolicy(Base):
    __tablename__ = "approval_policies"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset_tier: Mapped[str] = mapped_column(String(20), unique=True, nullable=False)
    max_auto_approve_cvss: Mapped[float] = mapped_column(Float, default=7.0)
    auto_approve_config_only: Mapped[bool] = mapped_column(Boolean, default=True)
    require_approval_for_service_restart: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
