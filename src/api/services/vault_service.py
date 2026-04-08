"""HashiCorp Vault integration — SSH CA signing and JIT certificate flow."""

from __future__ import annotations

import logging
import time
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

import httpx

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)

VAULT_SSH_SIGN_PATH = "ssh/sign/autopatch-executor"
VAULT_SSH_CA_PATH = "ssh/config/ca"
VAULT_APPROLE_LOGIN = "auth/approle/login"


@dataclass(frozen=True)
class SignedCertificate:
    """A short-lived SSH certificate returned by Vault."""

    signed_key: str
    serial_number: str
    lease_duration: int

    def write_to_tempfile(self) -> Path:
        """Write the signed certificate to a temporary file and return its path."""
        tmp = tempfile.NamedTemporaryFile(
            prefix="autopatch-cert-",
            suffix="-cert.pub",
            delete=False,
            mode="w",
        )
        tmp.write(self.signed_key)
        tmp.close()
        return Path(tmp.name)


class VaultClient:
    """Thin async wrapper around the Vault HTTP API for SSH CA operations."""

    def __init__(self, addr: str, role_id: str, secret_id: str) -> None:
        self._addr = addr.rstrip("/")
        self._role_id = role_id
        self._secret_id = secret_id
        self._token: str | None = None
        self._token_acquired_at: float = 0.0
        self._token_ttl: int = 0
        self._http = httpx.AsyncClient(base_url=self._addr, timeout=10.0)

    # -- Authentication -------------------------------------------------------

    async def _ensure_token(self) -> None:
        """Authenticate via AppRole and cache the client token.

        Re-authenticates when the token is within 60 seconds of expiry.
        """
        now = time.monotonic()
        if self._token is not None and (now - self._token_acquired_at) < (self._token_ttl - 60):
            return
        resp = await self._http.post(
            f"/v1/{VAULT_APPROLE_LOGIN}",
            json={"role_id": self._role_id, "secret_id": self._secret_id},
        )
        resp.raise_for_status()
        data = resp.json()
        self._token = data["auth"]["client_token"]
        self._token_ttl = data["auth"].get("lease_duration", 3600)
        self._token_acquired_at = now
        logger.info("Authenticated to Vault via AppRole (ttl=%ds)", self._token_ttl)

    async def _get_headers(self) -> dict[str, str]:
        """Return Vault request headers, refreshing the token if needed."""
        await self._ensure_token()
        return {"X-Vault-Token": self._token}  # type: ignore[dict-item]

    # -- SSH CA operations ----------------------------------------------------

    async def sign_public_key(
        self,
        public_key: str,
        *,
        valid_principals: str = "autopatch",
        ttl: str = "5m",
    ) -> SignedCertificate:
        """Sign an SSH public key and return a short-lived certificate.

        This is the core JIT certificate flow: generate a keypair locally,
        send the public key to Vault for signing, receive a cert that
        expires in *ttl*.
        """
        headers = await self._get_headers()
        resp = await self._http.put(
            f"/v1/{VAULT_SSH_SIGN_PATH}",
            headers=headers,
            json={
                "public_key": public_key,
                "valid_principals": valid_principals,
                "ttl": ttl,
            },
        )
        resp.raise_for_status()
        payload = resp.json()["data"]
        cert = SignedCertificate(
            signed_key=payload["signed_key"],
            serial_number=payload["serial_number"],
            lease_duration=int(payload.get("lease_duration", 300)),
        )
        logger.info(
            "Signed SSH cert serial=%s ttl=%s principals=%s",
            cert.serial_number,
            ttl,
            valid_principals,
        )
        return cert

    async def get_ca_public_key(self) -> str:
        """Fetch the SSH CA public key (for configuring target hosts)."""
        headers = await self._get_headers()
        resp = await self._http.get(
            f"/v1/{VAULT_SSH_CA_PATH}",
            headers=headers,
        )
        resp.raise_for_status()
        return resp.json()["data"]["public_key"]

    # -- Lifecycle ------------------------------------------------------------

    async def close(self) -> None:
        await self._http.aclose()

    async def __aenter__(self) -> "VaultClient":
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.close()


def build_vault_client_from_settings() -> VaultClient:
    """Create a VaultClient from application settings."""
    from src.api.config import Settings

    settings = Settings()
    return VaultClient(
        addr=settings.vault_addr,
        role_id=settings.vault_role_id,
        secret_id=settings.vault_secret_id,
    )
