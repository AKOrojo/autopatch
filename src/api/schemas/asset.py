import uuid
from datetime import datetime
from pydantic import BaseModel


class AssetCreate(BaseModel):
    hostname: str
    ip_address: str
    os_family: str | None = None
    os_version: str | None = None
    kernel_version: str | None = None
    environment: str = "production"
    criticality: str = "medium"
    tags: dict = {}


class AssetResponse(BaseModel):
    model_config = {"from_attributes": True}
    id: uuid.UUID
    hostname: str
    ip_address: str
    os_family: str | None
    os_version: str | None
    kernel_version: str | None
    environment: str
    criticality: str
    tags: dict
    last_scan_at: datetime | None
    created_at: datetime
    updated_at: datetime
