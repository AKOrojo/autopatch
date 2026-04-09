"""Unit tests for the Vault service."""

import time
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from unittest.mock import patch as mock_patch

from src.api.services.vault_service import VaultClient, SignedCertificate


@pytest.fixture
def vault():
    return VaultClient(
        addr="http://vault-test:8200",
        role_id="test-role-id",
        secret_id="test-secret-id",
    )


class TestSignedCertificate:
    def test_write_to_tempfile(self, tmp_path):
        cert = SignedCertificate(
            signed_key="ssh-rsa-cert-v01@openssh.com AAAA...",
            serial_number="12345",
            lease_duration=300,
        )
        path = cert.write_to_tempfile()
        assert path.exists()
        assert path.read_text() == "ssh-rsa-cert-v01@openssh.com AAAA..."
        path.unlink()


class TestVaultClient:
    @pytest.mark.asyncio
    async def test_authenticate_via_approle(self, vault):
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "auth": {"client_token": "s.test-token-123"}
        }
        mock_response.raise_for_status = MagicMock()

        with patch.object(vault._http, "post", new_callable=AsyncMock, return_value=mock_response):
            await vault._ensure_token()
            assert vault._token == "s.test-token-123"

    @pytest.mark.asyncio
    async def test_sign_public_key(self, vault):
        vault._token = "s.test-token"  # skip auth
        vault._token_acquired_at = time.monotonic()
        vault._token_ttl = 3600

        mock_response = MagicMock()
        mock_response.json.return_value = {
            "data": {
                "signed_key": "ssh-rsa-cert-v01@openssh.com SIGNED_KEY",
                "serial_number": "67890",
                "lease_duration": 300,
            }
        }
        mock_response.raise_for_status = MagicMock()

        with patch.object(vault._http, "put", new_callable=AsyncMock, return_value=mock_response):
            cert = await vault.sign_public_key("ssh-ed25519 AAAA... autopatch-jit")
            assert cert.serial_number == "67890"
            assert cert.lease_duration == 300
            assert "SIGNED_KEY" in cert.signed_key

    @pytest.mark.asyncio
    async def test_get_ca_public_key(self, vault):
        vault._token = "s.test-token"
        vault._token_acquired_at = time.monotonic()
        vault._token_ttl = 3600

        mock_response = MagicMock()
        mock_response.json.return_value = {
            "data": {"public_key": "ssh-rsa AAAA_CA_KEY"}
        }
        mock_response.raise_for_status = MagicMock()

        with patch.object(vault._http, "get", new_callable=AsyncMock, return_value=mock_response):
            ca_key = await vault.get_ca_public_key()
            assert ca_key == "ssh-rsa AAAA_CA_KEY"


class TestVaultTokenRefresh:
    @pytest.mark.asyncio
    async def test_token_refreshes_when_near_expiry(self, vault):
        """Token should be re-fetched when within 60s of TTL expiry."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "auth": {"client_token": "s.first-token", "lease_duration": 3600}
        }
        mock_response.raise_for_status = MagicMock()

        with patch.object(vault._http, "post", new_callable=AsyncMock, return_value=mock_response):
            await vault._ensure_token()
            assert vault._token == "s.first-token"

        # Simulate time passing beyond TTL - 60s
        mock_response2 = MagicMock()
        mock_response2.json.return_value = {
            "auth": {"client_token": "s.refreshed-token", "lease_duration": 3600}
        }
        mock_response2.raise_for_status = MagicMock()

        with (
            patch.object(vault._http, "post", new_callable=AsyncMock, return_value=mock_response2),
            mock_patch("time.monotonic", return_value=vault._token_acquired_at + 3550),
        ):
            await vault._ensure_token()
            assert vault._token == "s.refreshed-token"

    @pytest.mark.asyncio
    async def test_token_reused_when_not_expired(self, vault):
        """Token should be reused when still valid."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "auth": {"client_token": "s.valid-token", "lease_duration": 3600}
        }
        mock_response.raise_for_status = MagicMock()

        with patch.object(vault._http, "post", new_callable=AsyncMock, return_value=mock_response) as mock_post:
            await vault._ensure_token()
            await vault._ensure_token()  # second call should not POST
            assert mock_post.call_count == 1
            assert vault._token == "s.valid-token"
