"""Live terraform tests — validates modules and checks Proxmox connectivity.
Run with: pytest -m live_terraform

Tests are ordered: init → validate → plan → connectivity → lifecycle.
"""
import os
import subprocess

import pytest

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://autopatch:autopatch_dev@localhost:5432/autopatch")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("JWT_SECRET_KEY", "test-secret")
os.environ.setdefault("API_KEYS", "key1")

TF_SERVICE = ["docker", "compose", "exec", "-T", "terraform"]

PROXMOX_API_URL = os.environ.get("PROXMOX_API_URL", "https://10.100.201.24:8006")
PROXMOX_API_TOKEN = os.environ.get(
    "PROXMOX_API_TOKEN",
    "terraform@pam!terraform=dd134b21-9038-41d8-9d1c-204ddeda089a",
)


def _run_tf(args: list[str], timeout: int = 120) -> subprocess.CompletedProcess:
    return subprocess.run(
        TF_SERVICE + ["terraform"] + args,
        capture_output=True, text=True, timeout=timeout,
    )


@pytest.mark.live_terraform
def test_terraform_container_running():
    """Terraform container is up and responsive."""
    result = subprocess.run(
        TF_SERVICE + ["terraform", "version"],
        capture_output=True, text=True, timeout=15,
    )
    assert result.returncode == 0, f"Terraform container not running: {result.stderr}"
    assert "Terraform" in result.stdout


@pytest.mark.live_terraform
def test_terraform_init():
    """Terraform init succeeds (downloads providers)."""
    result = _run_tf(["init", "-input=false"], timeout=180)
    assert result.returncode == 0, f"terraform init failed: {result.stderr}"


@pytest.mark.live_terraform
def test_terraform_validate():
    """All modules pass terraform validate (requires init first)."""
    # Ensure init has run
    _run_tf(["init", "-input=false"], timeout=180)
    result = _run_tf(["validate", "-json"])
    assert result.returncode == 0, f"terraform validate failed: {result.stdout}"
    assert '"valid": true' in result.stdout or '"valid":true' in result.stdout


@pytest.mark.live_terraform
def test_terraform_plan_dry_run():
    """Terraform plan runs without errors (no resources applied)."""
    result = _run_tf([
        "plan",
        "-input=false",
        "-var", "clones={}",
        "-out=/dev/null",
    ])
    assert result.returncode == 0, f"terraform plan failed: {result.stderr}"


@pytest.mark.live_terraform
def test_proxmox_connectivity():
    """Proxmox API is reachable and authenticated from the terraform container."""
    result = subprocess.run(
        TF_SERVICE + [
            "sh", "-c",
            f'wget -q --no-check-certificate '
            f'--header="Authorization: PVEAPIToken={PROXMOX_API_TOKEN}" '
            f'-O- {PROXMOX_API_URL}/api2/json/version',
        ],
        capture_output=True, text=True, timeout=15,
    )
    assert result.returncode == 0, f"Cannot reach Proxmox at {PROXMOX_API_URL}: {result.stderr}"
    assert "version" in result.stdout


# ---------------------------------------------------------------------------
# Full clone lifecycle: create → verify → snapshot → delete snapshot → destroy
# ---------------------------------------------------------------------------

CLONE_TEST_NAME = "e2e-test-clone"
CLONE_TEMPLATE_ID = 101  # win10-iot template


@pytest.fixture(scope="module")
def clone_service():
    from src.api.services.clone_service import CloneService
    return CloneService()


@pytest.mark.live_terraform
def test_clone_lifecycle(clone_service):
    """Create a clone, optionally snapshot, then destroy — full round trip."""
    from src.api.services.clone_service import CloneRequest

    # --- Create ---
    result = clone_service.create_clone(CloneRequest(
        name=CLONE_TEST_NAME,
        template_id=CLONE_TEMPLATE_ID,
        cores=2,
        memory=2048,
        disk_size="32G",
        network_bridge="vmbr0",
    ))
    assert result.success, f"Clone creation failed: {result.error}"
    assert result.vm_id is not None, "No VM ID returned"
    vm_id = result.vm_id

    try:
        # --- Verify clone exists in state ---
        clones = clone_service.list_clones()
        matching = [c for c in clones if CLONE_TEST_NAME in c]
        assert len(matching) > 0, f"Clone {CLONE_TEST_NAME} not found in state"

        # --- Snapshot (only if we can delete it) ---
        snap_result = clone_service.snapshot_clone(vm_id=vm_id, snapshot_name="e2e-test-snap")
        if snap_result.success:
            # Clean up: delete the snapshot
            del_result = clone_service.delete_snapshot(vm_id=vm_id, snapshot_name="e2e-test-snap")
            assert del_result.success, f"Snapshot deletion failed: {del_result.error}"

    finally:
        # --- Destroy (always clean up) ---
        destroy_result = clone_service.destroy_clone(CLONE_TEST_NAME)
        assert destroy_result.success, f"Clone destruction failed: {destroy_result.error}"
