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

    def discover_ip(self, mac: str, timeout: int = 180, poll_interval: int = 15) -> str:
        """Discover a VM's IP by MAC address using nmap ARP scan.

        Uses nmap -sn -PR (ARP-only scan) to find which IP has the given MAC.
        On Windows: runs nmap directly (requires Npcap).
        On Linux: runs nmap in the tools container (network_mode: host for L2 access).

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

        mac_colon = mac.lower().replace("-", ":")

        # Determine subnet from Proxmox host IP
        proxmox_url = os.environ.get("PROXMOX_API_URL", "")
        m = re.search(r"(\d+\.\d+\.\d+)\.\d+", proxmox_url)
        subnet = f"{m.group(1)}.0/24" if m else "10.100.201.0/24"

        is_windows = platform.system() == "Windows"

        # Build nmap command — local on Windows, tools container on Linux
        if is_windows:
            nmap_cmd = ["nmap", "-sn", "-PR", subnet]
        else:
            nmap_cmd = [*self.tf.compose.split(), "exec", "-T", "tools",
                        "nmap", "-sn", "-PR", subnet]

        logger.info("Discovering IP for MAC %s on %s...", mac, subnet)

        elapsed = 0
        while elapsed < timeout:
            try:
                result = subprocess.run(
                    nmap_cmd, capture_output=True, text=True, timeout=60,
                )
                # nmap output format:
                #   Nmap scan report for 10.100.201.27
                #   Host is up (0.0018s latency).
                #   MAC Address: BC:24:11:87:A3:85 (Proxmox Server Solutions GmbH)
                current_ip = ""
                for line in result.stdout.splitlines():
                    ip_match = re.search(r"Nmap scan report for (\d+\.\d+\.\d+\.\d+)", line)
                    if ip_match:
                        current_ip = ip_match.group(1)
                    if mac_colon in line.lower() and current_ip:
                        logger.info("Discovered IP %s for MAC %s via nmap ARP scan", current_ip, mac)
                        return current_ip
            except (subprocess.TimeoutExpired, FileNotFoundError) as e:
                logger.warning("nmap ARP scan failed: %s", e)

            time.sleep(poll_interval)
            elapsed += poll_interval
            logger.info("Waiting for MAC %s... (%ds/%ds)", mac, elapsed, timeout)

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
