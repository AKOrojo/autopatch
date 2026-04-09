import uuid
import pytest
from fastapi import HTTPException


@pytest.fixture
def admin_user():
    from src.api.models.user import User
    return User(id=uuid.uuid4(), email="admin@test.com", password_hash="x", name="Admin", role="admin", is_active=True)


@pytest.fixture
def viewer_user():
    from src.api.models.user import User
    return User(id=uuid.uuid4(), email="viewer@test.com", password_hash="x", name="Viewer", role="viewer", is_active=True)


def test_require_role_admin_passes(admin_user):
    from src.api.dependencies import _check_role
    _check_role(admin_user, ["admin"])


def test_require_role_viewer_blocked(viewer_user):
    from src.api.dependencies import _check_role
    with pytest.raises(HTTPException) as exc_info:
        _check_role(viewer_user, ["admin", "operator"])
    assert exc_info.value.status_code == 403


def test_require_role_operator_allowed():
    from src.api.models.user import User
    from src.api.dependencies import _check_role
    u = User(id=uuid.uuid4(), email="op@test.com", password_hash="x", name="Op", role="operator", is_active=True)
    _check_role(u, ["admin", "operator"])


def test_inactive_user_blocked(admin_user):
    from src.api.dependencies import _check_role
    admin_user.is_active = False
    with pytest.raises(HTTPException) as exc_info:
        _check_role(admin_user, ["admin"])
    assert exc_info.value.status_code == 403
