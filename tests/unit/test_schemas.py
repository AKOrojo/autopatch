import uuid
from datetime import datetime, timezone

from src.api.schemas.asset import AssetCreate, AssetResponse
from src.api.schemas.scan import ScanCreate
from src.api.schemas.vulnerability import VulnerabilityUpdate
from src.api.schemas.auth import LoginRequest, TokenResponse


def test_asset_create_schema():
    a = AssetCreate(
        hostname="web-01",
        ip_address="10.0.1.5",
        os_family="ubuntu",
        os_version="22.04",
        environment="production",
        criticality="high",
    )
    assert a.hostname == "web-01"
    assert a.ip_address == "10.0.1.5"


def test_asset_create_defaults():
    a = AssetCreate(hostname="web-01", ip_address="10.0.1.5")
    assert a.environment == "production"
    assert a.criticality == "medium"
    assert a.tags == {}


def test_asset_response_schema():
    now = datetime.now(timezone.utc)
    a = AssetResponse(
        id=uuid.uuid4(), hostname="web-01", ip_address="10.0.1.5",
        os_family="ubuntu", os_version="22.04", kernel_version=None,
        environment="production", criticality="high", tags={},
        ssh_port=22, scan_config={},
        last_scan_at=None, created_at=now, updated_at=now,
    )
    assert a.hostname == "web-01"


def test_scan_create_schema():
    s = ScanCreate(asset_id=uuid.uuid4(), scanner_type="openvas")
    assert s.scanner_type == "openvas"


def test_vulnerability_update_schema():
    v = VulnerabilityUpdate(status="accepted_risk")
    assert v.status == "accepted_risk"


def test_login_request_schema():
    lr = LoginRequest(username="admin", password="secret")
    assert lr.username == "admin"


def test_token_response_schema():
    tr = TokenResponse(access_token="abc.def.ghi", token_type="bearer")
    assert tr.token_type == "bearer"
