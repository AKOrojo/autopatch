import uuid
from unittest.mock import AsyncMock, MagicMock, patch
import pytest


@pytest.mark.asyncio
@patch("src.api.routes.auth.verify_password", return_value=True)
async def test_login_returns_user(mock_verify):
    from src.api.routes.auth import _authenticate_user
    from src.api.models.user import User

    user = User(id=uuid.UUID("00000000-0000-0000-0000-000000000001"), email="test@example.com", password_hash="hashed", name="Test", role="admin", is_active=True)
    session = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = user
    session.execute.return_value = mock_result

    result = await _authenticate_user(session, "test@example.com", "secret123")
    assert result is not None
    assert result.id == user.id
    mock_verify.assert_called_once_with("secret123", "hashed")


@pytest.mark.asyncio
@patch("src.api.routes.auth.verify_password", return_value=False)
async def test_login_wrong_password_returns_none(mock_verify):
    from src.api.routes.auth import _authenticate_user
    from src.api.models.user import User

    user = User(id=uuid.UUID("00000000-0000-0000-0000-000000000001"), email="test@example.com", password_hash="hashed", name="Test", role="admin", is_active=True)
    session = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = user
    session.execute.return_value = mock_result

    result = await _authenticate_user(session, "test@example.com", "wrong")
    assert result is None
