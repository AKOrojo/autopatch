import uuid
from datetime import datetime, timezone

from sqlalchemy import String, DateTime, Index
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from src.shared.database import Base


class RemediationEvent(Base):
    __tablename__ = "remediation_events"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    remediation_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    level: Mapped[str] = mapped_column(String(10), nullable=False)
    node_name: Mapped[str] = mapped_column(String(50), nullable=False)
    event_type: Mapped[str] = mapped_column(String(20), nullable=False)
    payload: Mapped[dict] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        Index("idx_remediation_events_rid", "remediation_id"),
        Index("idx_remediation_events_level", "level"),
    )
