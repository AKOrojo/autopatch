# tests/unit/test_models.py
import uuid

from src.api.models.asset import Asset
from src.api.models.scan import Scan
from src.api.models.vulnerability import Vulnerability
from src.api.models.audit_log import AuditLog
from src.api.models.cve_enrichment import CVEEnrichment


def test_asset_model_fields():
    a = Asset(
        hostname="web-01",
        ip_address="10.0.1.5",
        os_family="ubuntu",
        os_version="22.04",
        environment="production",
        criticality="high",
    )
    assert a.hostname == "web-01"
    assert a.ip_address == "10.0.1.5"
    assert a.os_family == "ubuntu"
    assert a.criticality == "high"


def test_scan_model_fields():
    asset_id = uuid.uuid4()
    s = Scan(
        asset_id=asset_id,
        scanner_type="openvas",
        status="pending",
    )
    assert s.scanner_type == "openvas"
    assert s.status == "pending"


def test_vulnerability_model_fields():
    v = Vulnerability(
        asset_id=uuid.uuid4(),
        scan_id=uuid.uuid4(),
        title="OpenSSH < 9.0 RCE",
        severity="critical",
        cvss_score=9.8,
        cve_id="CVE-2024-1234",
        is_kev=True,
        status="open",
    )
    assert v.title == "OpenSSH < 9.0 RCE"
    assert v.severity == "critical"
    assert v.is_kev is True


def test_audit_log_model_fields():
    a = AuditLog(
        event_type="scan_started",
        action_detail={"scanner": "nuclei", "target": "10.0.1.5"},
    )
    assert a.event_type == "scan_started"
    assert a.action_detail["scanner"] == "nuclei"


def test_cve_enrichment_model_fields():
    c = CVEEnrichment(
        cve_id="CVE-2024-1234",
        description="Buffer overflow in OpenSSH",
        cvss_v3_score=9.8,
        is_kev=True,
    )
    assert c.cve_id == "CVE-2024-1234"
    assert c.is_kev is True
