import uuid
from datetime import datetime
from pydantic import BaseModel


class ScanReportCreate(BaseModel):
    asset_id: uuid.UUID
    scanner_types: list[str]


class ScanReportResponse(BaseModel):
    model_config = {"from_attributes": True}
    id: uuid.UUID
    asset_id: uuid.UUID
    status: str
    scanner_types: str
    total_vulns: int
    created_at: datetime
    completed_at: datetime | None


class ScanReportDetail(ScanReportResponse):
    scans: list[dict]
    vulnerabilities: list[dict]
