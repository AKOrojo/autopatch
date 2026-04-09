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

    def _get_vm_mac(self, vm_id: int) -> str:
        """Get the MAC address of a VM's first network interface from Proxmox."""
        import os
        api_url = os.environ.get("PROXMOX_API_URL", "")
        api_token = os.environ.get("PROXMOX_API_TOKEN", "")
        node = os.environ.get("PROXMOX_NODE", "pve")

        cmd = [
            "curl", "-sk",
            "-H", f"Authorization: PVEAPIToken={api_token}",
            f"{api_url}/api2/json/nodes/{node}/qemu/{vm_id}/config",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        if result.returncode != 0:
            return ""
        try:
            config = json.loads(result.stdout).get("data", {})
            net0 = config.get("net0", "")
            # Format: "virtio=BC:24:11:87:A3:85,bridge=vmbr0,..."
            for part in net0.split(","):
                if "=" in part and part.split("=")[0] in ("virtio", "e1000", "rtl8139"):
                    return part.split("=")[1].lower()
        except (json.JSONDecodeError, IndexError):
            pass
        return ""

    def discover_ip(self, vm_id: int, timeout: int = 120, poll_interval: int = 10) -> str:
        """Discover a VM's IP by matching its MAC in the Proxmox ARP table.

        Polls the Proxmox host's ARP table until the VM's MAC address appears.
        This works for VMs without cloud-init or qemu-guest-agent (like Metasploitable 2).
        """
        import os
        import time

        mac = self._get_vm_mac(vm_id)
        if not mac:
            logger.warning("Could not get MAC address for VM %d", vm_id)
            return ""

        api_url = os.environ.get("PROXMOX_API_URL", "")
        api_token = os.environ.get("PROXMOX_API_TOKEN", "")
        node = os.environ.get("PROXMOX_NODE", "pve")

        logger.info("Waiting for VM %d (MAC %s) to get an IP...", vm_id, mac)
        elapsed = 0
        while elapsed < timeout:
            # Query Proxmox node's network interfaces for ARP entries
            cmd = [
                "curl", "-sk",
                "-H", f"Authorization: PVEAPIToken={api_token}",
                f"{api_url}/api2/json/nodes/{node}/network",
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)

            # Also try reading ARP table directly via Proxmox API task
            arp_cmd = [
                "curl", "-sk",
                "-H", f"Authorization: PVEAPIToken={api_token}",
                f"{api_url}/api2/json/nodes/{node}/qemu/{vm_id}/agent/network-get-interfaces",
            ]
            arp_result = subprocess.run(arp_cmd, capture_output=True, text=True, timeout=15)
            if arp_result.returncode == 0 and arp_result.stdout.strip():
                try:
                    ifaces = json.loads(arp_result.stdout).get("data", {}).get("result", [])
                    for iface in ifaces:
                        for addr in iface.get("ip-addresses", []):
                            ip = addr.get("ip-address", "")
                            if ip and addr.get("ip-address-type") == "ipv4" and not ip.startswith("127."):
                                logger.info("VM %d IP discovered via guest agent: %s", vm_id, ip)
                                return ip
                except (json.JSONDecodeError, KeyError, AttributeError):
                    pass

            # Fallback: ping sweep and check ARP on the host running this code
            try:
                arp_scan = subprocess.run(
                    ["arp", "-a"], capture_output=True, text=True, timeout=10,
                )
                for line in arp_scan.stdout.splitlines():
                    if mac.replace(":", "-") in line.lower() or mac in line.lower():
                        # Parse IP from ARP output (format varies by OS)
                        parts = line.strip().split()
                        for part in parts:
                            cleaned = part.strip("()")
                            if cleaned.count(".") == 3 and all(
                                seg.isdigit() and 0 <= int(seg) <= 255
                                for seg in cleaned.split(".")
                            ):
                                logger.info("VM %d IP discovered via ARP: %s", vm_id, cleaned)
                                return cleaned
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass

            time.sleep(poll_interval)
            elapsed += poll_interval
            logger.info("Waiting for VM %d IP... (%ds/%ds)", vm_id, elapsed, timeout)

        logger.warning("Could not discover IP for VM %d after %ds", vm_id, timeout)
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

            # If Terraform couldn't get the IP (no cloud-init/guest-agent),
            # discover it via MAC/ARP lookup
            if vm_id and not vm_ip:
                vm_ip = self.discover_ip(vm_id)

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
