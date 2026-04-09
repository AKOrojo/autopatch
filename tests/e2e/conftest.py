# tests/e2e/conftest.py
"""E2E test fixtures — Proxmox VM cloning, scanning, and teardown."""

import os
import pytest

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://autopatch:autopatch_dev@localhost:5432/autopatch")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("JWT_SECRET_KEY", "test-secret")
os.environ.setdefault("API_KEYS", "key1")
os.environ.setdefault("PROXMOX_API_URL", "https://10.100.201.24:8006")
os.environ.setdefault(
    "PROXMOX_API_TOKEN",
    "terraform@pam!terraform=dd134b21-9038-41d8-9d1c-204ddeda089a",
)
os.environ.setdefault("PROXMOX_NODE", "pve")


CLONE_TEMPLATE_ID = 101  # meta2-temp


@pytest.fixture(scope="session")
def clone_service():
    from src.api.services.clone_service import CloneService
    return CloneService()


@pytest.fixture(scope="session")
def cloned_vm(clone_service):
    """Clone Metasploitable 2 from template, yield clone info, destroy on teardown."""
    from src.api.services.clone_service import CloneRequest

    result = clone_service.create_clone(CloneRequest(
        name="e2e-meta2-test",
        template_id=CLONE_TEMPLATE_ID,
        cores=2,
        memory=2048,
        disk_size="32G",
        network_bridge="vmbr0",
    ))
    assert result.success, f"Clone creation failed: {result.error}"
    assert result.vm_id is not None

    yield result

    # Teardown: destroy clone
    clone_service.destroy_clone("e2e-meta2-test")


@pytest.fixture(scope="session")
def clone_ip(cloned_vm):
    """Return the IP address of the cloned VM."""
    ip = cloned_vm.vm_ip or cloned_vm.ssh_host
    assert ip, "No IP address for cloned VM"
    return ip
