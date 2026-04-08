from datetime import date, datetime, timezone

from sqlalchemy import String, Numeric, Boolean, Text, Date, DateTime
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from src.shared.database import Base


class CVEEnrichment(Base):
    __tablename__ = "cve_enrichment"

    cve_id: Mapped[str] = mapped_column(String(20), primary_key=True)
    description: Mapped[str | None] = mapped_column(Text)
    cvss_v3_score: Mapped[float | None] = mapped_column(Numeric(3, 1))
    cvss_v3_vector: Mapped[str | None] = mapped_column(String(100))
    epss_score: Mapped[float | None] = mapped_column(Numeric(5, 4))
    epss_percentile: Mapped[float | None] = mapped_column(Numeric(5, 4))
    epss_updated_at: Mapped[date | None] = mapped_column(Date)
    is_kev: Mapped[bool] = mapped_column(Boolean, default=False)
    kev_due_date: Mapped[date | None] = mapped_column(Date)
    references: Mapped[list] = mapped_column(JSONB, default=list)
    affected_configs: Mapped[list] = mapped_column(JSONB, default=list)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
