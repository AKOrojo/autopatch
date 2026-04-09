from datetime import datetime, timezone

from sqlalchemy import BigInteger, String, Text, DateTime, ForeignKey, Index
from sqlalchemy.dialects.postgresql import UUID, INET, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from src.shared.database import Base


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    event_type: Mapped[str] = mapped_column(String(50), nullable=False)
    remediation_id: Mapped[str | None] = mapped_column(UUID(as_uuid=True))
    vulnerability_id: Mapped[str | None] = mapped_column(UUID(as_uuid=True), ForeignKey("vulnerabilities.id"))
    scan_id: Mapped[str | None] = mapped_column(UUID(as_uuid=True))
    asset_id: Mapped[str | None] = mapped_column(UUID(as_uuid=True), ForeignKey("assets.id"))
    agent_id: Mapped[str | None] = mapped_column(String(100))
    model_id: Mapped[str | None] = mapped_column(String(100))
    action_detail: Mapped[dict] = mapped_column(JSONB, nullable=False)
    reasoning_chain: Mapped[str | None] = mapped_column(Text)
    pre_state: Mapped[dict | None] = mapped_column(JSONB)
    post_state: Mapped[dict | None] = mapped_column(JSONB)
    user_id: Mapped[str | None] = mapped_column(String(200))
    ip_address: Mapped[str | None] = mapped_column(INET)
    checksum: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        Index("idx_audit_event", "event_type"),
        Index("idx_audit_remediation", "remediation_id"),
        Index("idx_audit_time", "created_at"),
    )
