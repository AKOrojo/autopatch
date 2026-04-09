"""VM cloning service — drives Terraform to clone, snapshot, and destroy VMs on Proxmox."""

from __future__ import annotations

import json
import logging
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

TF_DIR = Path(__file__).resolve().parents[3] / "terraform" / "environments" / "dev"
DOCKER_SERVICE = "terraform"


@dataclass
class CloneRequest:
    """Parameters for a VM clone operation."""

    name: str
    template_id: int
    cores: int = 2
    memory: int = 2048
    disk_size: str = "32G"
    storage_pool: str = "local-lvm"
    network_bridge: str = ""
    ip_address: str = ""
    full_clone: bool = True
    cloud_init: bool = True


@dataclass
class CloneResult:
    success: bool
    vm_id: int | None = None
    vm_ip: str | None = None
    ssh_host: str | None = None
    snapshot_name: str | None = None
    error: str | None = None
    raw_output: dict[str, Any] = field(default_factory=dict)


class TerraformRunner:
    """Execute Terraform commands inside the terraform Docker container."""

    def __init__(self, docker_compose_cmd: str = "docker compose"):
        self.compose = docker_compose_cmd

    def _run(self, *tf_args: str, capture_json: bool = False) -> subprocess.CompletedProcess:
        cmd = [
            *self.compose.split(),
            "exec", "-T", DOCKER_SERVICE,
            "terraform", *tf_args,
        ]
        if capture_json:
            cmd.insert(cmd.index("terraform") + 1, "-json")

        logger.info("terraform: %s", " ".join(tf_args))
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600,
        )
        if result.returncode != 0:
            logger.error("terraform failed: %s", result.stderr)
        return result

    def init(self) -> subprocess.CompletedProcess:
        return self._run("init", "-input=false")

    def plan(self, var_file: str | None = None) -> subprocess.CompletedProcess:
        args = ["plan", "-input=false", "-out=tfplan"]
        if var_file:
            args.append(f"-var-file={var_file}")
        return self._run(*args)

    def apply(self) -> subprocess.CompletedProcess:
        return self._run("apply", "-auto-approve", "-input=false", "tfplan")

    def destroy(self, target: str | None = None) -> subprocess.CompletedProcess:
        args = ["destroy", "-auto-approve", "-input=false"]
        if target:
            args.extend(["-target", target])
        return self._run(*args)

    def output(self) -> dict[str, Any]:
        result = self._run("output", "-json")
        if result.returncode == 0 and result.stdout.strip():
            return json.loads(result.stdout)
        return {}

    def state_list(self) -> list[str]:
        result = self._run("state", "list")
        if result.returncode == 0:
            return [line.strip() for line in result.stdout.splitlines() if line.strip()]
        return []


class CloneService:
    """High-level service for VM clone lifecycle management."""

    def __init__(self):
        self.tf = TerraformRunner()
        self._initialized = False

    def _ensure_init(self) -> None:
        if not self._initialized:
            result = self.tf.init()
            if result.returncode != 0:
                raise RuntimeError(f"Terraform init failed: {result.stderr}")
            self._initialized = True

    def discover_ip(self, mac: str, timeout: int = 180, poll_interval: int = 10) -> str:
        """Discover a VM's IP by matching its MAC in the Windows ARP table.

        Runs on the Windows host (not inside Docker). Pings the subnet
        broadcast to populate the ARP cache, then matches the MAC.

        Args:
            mac: MAC address from Terraform output (e.g. "BC:24:11:F0:FB:F6")
            timeout: Max seconds to wait for discovery
            poll_interval: Seconds between attempts
        """
        import os
        import platform
        import re
        import time

        if not mac:
            logger.warning("No MAC address provided for IP discovery")
            return ""

        # Normalize MAC to lowercase with both colon and hyphen formats
        mac_lower = mac.lower()
        mac_hyphen = mac_lower.replace(":", "-")
        mac_colon = mac_lower.replace("-", ":")

        # Determine subnet from Proxmox host IP
        proxmox_url = os.environ.get("PROXMOX_API_URL", "")
        proxmox_ip = re.search(r"(\d+\.\d+\.\d+)\.\d+", proxmox_url)
        subnet_prefix = proxmox_ip.group(1) if proxmox_ip else "10.100.201"

        logger.info("Discovering IP for MAC %s on %s.0/24...", mac, subnet_prefix)

        elapsed = 0
        while elapsed < timeout:
            # Ping broadcast to populate ARP cache
            try:
                if platform.system() == "Windows":
                    # Windows: ping broadcast doesn't always work, ping a range
                    for octet in range(1, 255, 10):
                        subprocess.run(
                            ["ping", "-n", "1", "-w", "200", f"{subnet_prefix}.{octet}"],
                            capture_output=True, timeout=3,
                        )
                else:
                    subprocess.run(
                        ["ping", "-c", "1", "-W", "1", "-b", f"{subnet_prefix}.255"],
                        capture_output=True, timeout=3,
                    )
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass

            # Read ARP table and match MAC
            try:
                arp = subprocess.run(
                    ["arp", "-a"], capture_output=True, text=True, timeout=10,
                )
                for line in arp.stdout.splitlines():
                    line_lower = line.lower()
                    if mac_hyphen in line_lower or mac_colon in line_lower:
                        # Extract IP — Windows: "  10.100.201.27  bc-24-11-..."
                        ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
                        if ip_match:
                            ip = ip_match.group(1)
                            logger.info("Discovered IP %s for MAC %s via ARP", ip, mac)
                            return ip
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass

            time.sleep(poll_interval)
            elapsed += poll_interval
            logger.info("Waiting for MAC %s in ARP table... (%ds/%ds)", mac, elapsed, timeout)

        logger.warning("Could not discover IP for MAC %s after %ds", mac, timeout)
        return ""

    def create_clone(self, request: CloneRequest) -> CloneResult:
        """Clone a VM from template with isolated networking and pre-patch snapshot."""
        self._ensure_init()

        # Write a temporary tfvars for this clone
        clone_vars = {
            "clones": {
                request.name: {
                    "template_id": request.template_id,
                    "full_clone": request.full_clone,
                    "cores": request.cores,
                    "memory": request.memory,
                    "disk_size": request.disk_size,
                    "storage_pool": request.storage_pool,
                    **({"network_bridge": request.network_bridge} if request.network_bridge else {}),
                    "ip_address": request.ip_address,
                    "cloud_init": request.cloud_init,
                }
            }
        }
        vars_path = TF_DIR / f"clone-{request.name}.auto.tfvars.json"
        vars_path.write_text(json.dumps(clone_vars, indent=2))

        try:
            plan_result = self.tf.plan()
            if plan_result.returncode != 0:
                return CloneResult(success=False, error=plan_result.stderr)

            apply_result = self.tf.apply()
            if apply_result.returncode != 0:
                return CloneResult(success=False, error=apply_result.stderr)

            outputs = self.tf.output()
            clone_vms = outputs.get("clone_vms", {}).get("value", {})
            snapshots = outputs.get("snapshots", {}).get("value", {})

            vm_info = clone_vms.get(request.name, {})
            snap_info = snapshots.get(request.name, {})

            vm_id = vm_info.get("vm_id")
            vm_ip = vm_info.get("vm_ip", "")
            vm_mac = vm_info.get("vm_mac", "")

            # If Terraform couldn't get the IP (no cloud-init/guest-agent),
            # discover it via MAC/ARP lookup from the Windows host
            if not vm_ip and vm_mac:
                vm_ip = self.discover_ip(vm_mac)

            ssh_host = vm_info.get("ssh_host", "")
            if vm_ip and (not ssh_host or ssh_host.endswith("@")):
                ssh_user = request.ip_address.split("@")[0] if "@" in request.ip_address else "root"
                ssh_host = f"{ssh_user}@{vm_ip}" if ssh_user else vm_ip

            return CloneResult(
                success=True,
                vm_id=vm_id,
                vm_ip=vm_ip,
                ssh_host=ssh_host,
                snapshot_name=snap_info.get("snapshot_name"),
                raw_output=outputs,
            )
        except Exception as exc:
            logger.exception("Clone creation failed")
            return CloneResult(success=False, error=str(exc))

    def destroy_clone(self, name: str) -> CloneResult:
        """Destroy a specific clone (rolls back to snapshot first via Terraform destroy)."""
        self._ensure_init()

        # Remove the auto-generated tfvars
        vars_path = TF_DIR / f"clone-{name}.auto.tfvars.json"
        if vars_path.exists():
            vars_path.unlink()

        result = self.tf.plan()
        if result.returncode != 0:
            return CloneResult(success=False, error=result.stderr)

        result = self.tf.apply()
        if result.returncode != 0:
            return CloneResult(success=False, error=result.stderr)

        return CloneResult(success=True)

    def list_clones(self) -> list[str]:
        """List active clone resources in Terraform state."""
        self._ensure_init()
        resources = self.tf.state_list()
        return [r for r in resources if "test_clone" in r]

    def snapshot_clone(self, vm_id: int, snapshot_name: str = "manual") -> CloneResult:
        """Create an ad-hoc snapshot on an existing clone via Proxmox API."""
        import os

        api_url = os.environ.get("PROXMOX_API_URL", "")
        api_token = os.environ.get("PROXMOX_API_TOKEN", "")
        node = os.environ.get("PROXMOX_NODE", "")

        cmd = [
            "curl", "-sk", "-X", "POST",
            "-H", f"Authorization: PVEAPIToken={api_token}",
            f"{api_url}/api2/json/nodes/{node}/qemu/{vm_id}/snapshot",
            "-d", f"snapname={snapshot_name}",
            "-d", "description=Autopatch manual snapshot",
            "-d", "vmstate=0",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if result.returncode != 0:
            return CloneResult(success=False, error=result.stderr)

        return CloneResult(success=True, vm_id=vm_id, snapshot_name=snapshot_name)

    def delete_snapshot(self, vm_id: int, snapshot_name: str) -> CloneResult:
        """Delete a snapshot from a VM without rolling back."""
        import os

        api_url = os.environ.get("PROXMOX_API_URL", "")
        api_token = os.environ.get("PROXMOX_API_TOKEN", "")
        node = os.environ.get("PROXMOX_NODE", "")

        cmd = [
            "curl", "-sk", "-X", "DELETE",
            "-H", f"Authorization: PVEAPIToken={api_token}",
            f"{api_url}/api2/json/nodes/{node}/qemu/{vm_id}/snapshot/{snapshot_name}",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if result.returncode != 0:
            return CloneResult(success=False, error=result.stderr)

        return CloneResult(success=True, vm_id=vm_id, snapshot_name=snapshot_name)

    def rollback_snapshot(self, vm_id: int, snapshot_name: str) -> CloneResult:
        """Rollback a VM to a specific snapshot."""
        import os

        api_url = os.environ.get("PROXMOX_API_URL", "")
        api_token = os.environ.get("PROXMOX_API_TOKEN", "")
        node = os.environ.get("PROXMOX_NODE", "")

        cmd = [
            "curl", "-sk", "-X", "POST",
            "-H", f"Authorization: PVEAPIToken={api_token}",
            f"{api_url}/api2/json/nodes/{node}/qemu/{vm_id}/snapshot/{snapshot_name}/rollback",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if result.returncode != 0:
            return CloneResult(success=False, error=result.stderr)

        return CloneResult(success=True, vm_id=vm_id, snapshot_name=snapshot_name)
