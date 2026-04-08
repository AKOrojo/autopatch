import uuid
from datetime import datetime
from pydantic import BaseModel


class ScanCreate(BaseModel):
    asset_id: uuid.UUID
    scanner_type: str
    config: dict | None = None


class ScanResponse(BaseModel):
    model_config = {"from_attributes": True}
    id: uuid.UUID
    asset_id: uuid.UUID
    scanner_type: str
    status: str
    scanner_task_id: str | None
    config: dict | None
    started_at: datetime | None
    completed_at: datetime | None
    raw_report_path: str | None
    vuln_count: int
    created_at: datetime
