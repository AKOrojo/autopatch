import uuid
from datetime import datetime, timezone

import pytest


def test_user_model_columns():
    from src.api.models.user import User

    u = User(
        id=uuid.uuid4(),
        email="admin@example.com",
        password_hash="hashed",
        name="Admin",
        role="admin",
        is_active=True,
    )
    assert u.email == "admin@example.com"
    assert u.role == "admin"
    assert u.is_active is True


def test_approval_request_model_columns():
    from src.api.models.approval_request import ApprovalRequest

    ar = ApprovalRequest(
        id=uuid.uuid4(),
        remediation_id=uuid.uuid4(),
        asset_id=uuid.uuid4(),
        risk_score=8.5,
        asset_tier="prod",
        auto_approved=False,
        status="pending",
    )
    assert ar.status == "pending"
    assert ar.auto_approved is False
    assert ar.asset_tier == "prod"


def test_approval_policy_model_columns():
    from src.api.models.approval_policy import ApprovalPolicy

    ap = ApprovalPolicy(
        id=uuid.uuid4(),
        asset_tier="dev",
        max_auto_approve_cvss=7.0,
        auto_approve_config_only=True,
        require_approval_for_service_restart=False,
    )
    assert ap.max_auto_approve_cvss == 7.0
    assert ap.auto_approve_config_only is True


def test_remediation_event_model_columns():
    from src.api.models.remediation_event import RemediationEvent

    re = RemediationEvent(
        id=uuid.uuid4(),
        remediation_id=uuid.uuid4(),
        level="node",
        node_name="executor",
        event_type="started",
        payload={"status": "running"},
    )
    assert re.level == "node"
    assert re.node_name == "executor"


def test_notification_channel_model_columns():
    from src.api.models.notification_channel import NotificationChannel

    nc = NotificationChannel(
        id=uuid.uuid4(),
        type="email",
        config={"addresses": ["ops@example.com"]},
        events=["approval_required", "remediation_completed"],
        enabled=True,
        created_by=uuid.uuid4(),
    )
    assert nc.type == "email"
    assert nc.enabled is True
