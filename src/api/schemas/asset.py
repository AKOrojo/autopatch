import uuid
from datetime import datetime
from ipaddress import IPv4Address, IPv6Address
from typing import Union

from pydantic import BaseModel, field_serializer

IPAddress = Union[IPv4Address, IPv6Address, str]


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
    ip_address: IPAddress

    @field_serializer("ip_address")
    def serialize_ip(self, v):
        return str(v)
    os_family: str | None
    os_version: str | None
    kernel_version: str | None
    environment: str
    criticality: str
    tags: dict
    last_scan_at: datetime | None
    created_at: datetime
    updated_at: datetime
