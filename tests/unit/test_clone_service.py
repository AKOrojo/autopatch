"""Unit tests for the VM clone service."""

from __future__ import annotations

import json
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from src.api.services.clone_service import (
    CloneRequest,
    CloneResult,
    CloneService,
    TerraformRunner,
)


class TestCloneRequest:
    def test_defaults(self):
        req = CloneRequest(name="test-vm", template_id=100)
        assert req.cores == 2
        assert req.memory == 2048
        assert req.disk_size == "32G"
        assert req.full_clone is True
        assert req.ip_address == ""

    def test_custom_values(self):
        req = CloneRequest(
            name="win10-test",
            template_id=200,
            cores=4,
            memory=8192,
            disk_size="64G",
            ip_address="10.200.100.10/24",
        )
        assert req.name == "win10-test"
        assert req.template_id == 200
        assert req.cores == 4
        assert req.memory == 8192


class TestCloneResult:
    def test_success_result(self):
        result = CloneResult(success=True, vm_id=101, vm_ip="10.200.100.10")
        assert result.success is True
        assert result.vm_id == 101
        assert result.error is None

    def test_failure_result(self):
        result = CloneResult(success=False, error="terraform init failed")
        assert result.success is False
        assert result.error == "terraform init failed"
        assert result.vm_id is None


class TestTerraformRunner:
    @patch("src.api.services.clone_service.subprocess.run")
    def test_init(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="Initialized", stderr=""
        )
        runner = TerraformRunner()
        result = runner.init()
        assert result.returncode == 0
        call_args = mock_run.call_args[0][0]
        assert "terraform" in call_args
        assert "init" in call_args

    @patch("src.api.services.clone_service.subprocess.run")
    def test_plan(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="Plan: 2 to add", stderr=""
        )
        runner = TerraformRunner()
        result = runner.plan()
        assert result.returncode == 0
        call_args = mock_run.call_args[0][0]
        assert "plan" in call_args
        assert "-out=tfplan" in call_args

    @patch("src.api.services.clone_service.subprocess.run")
    def test_apply(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="Apply complete", stderr=""
        )
        runner = TerraformRunner()
        result = runner.apply()
        assert result.returncode == 0
        call_args = mock_run.call_args[0][0]
        assert "apply" in call_args
        assert "-auto-approve" in call_args

    @patch("src.api.services.clone_service.subprocess.run")
    def test_output_json(self, mock_run):
        tf_output = {"clone_vms": {"value": {"test": {"vm_id": 101}}}}
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=json.dumps(tf_output), stderr=""
        )
        runner = TerraformRunner()
        result = runner.output()
        assert result["clone_vms"]["value"]["test"]["vm_id"] == 101

    @patch("src.api.services.clone_service.subprocess.run")
    def test_output_failure_returns_empty(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=1, stdout="", stderr="error"
        )
        runner = TerraformRunner()
        result = runner.output()
        assert result == {}

    @patch("src.api.services.clone_service.subprocess.run")
    def test_state_list(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout="module.test_clone[\"vm1\"].proxmox_vm_qemu.clone\nmodule.clone_network.null_resource.isolated_bridge\n",
            stderr="",
        )
        runner = TerraformRunner()
        result = runner.state_list()
        assert len(result) == 2
        assert "test_clone" in result[0]

    @patch("src.api.services.clone_service.subprocess.run")
    def test_destroy_with_target(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="Destroy complete", stderr=""
        )
        runner = TerraformRunner()
        result = runner.destroy(target='module.test_clone["vm1"]')
        call_args = mock_run.call_args[0][0]
        assert "-target" in call_args


class TestCloneService:
    @patch.object(TerraformRunner, "init")
    @patch.object(TerraformRunner, "plan")
    @patch.object(TerraformRunner, "apply")
    @patch.object(TerraformRunner, "output")
    def test_create_clone_success(self, mock_output, mock_apply, mock_plan, mock_init, tmp_path):
        mock_init.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        mock_plan.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        mock_apply.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        mock_output.return_value = {
            "clone_vms": {
                "value": {
                    "test-vm": {
                        "vm_id": 101,
                        "vm_ip": "10.200.100.10",
                        "ssh_host": "autopatch@10.200.100.10",
                    }
                }
            },
            "snapshots": {
                "value": {
                    "test-vm": {
                        "snapshot_name": "pre-patch-20260408",
                    }
                }
            },
        }

        svc = CloneService()
        # Patch the TF_DIR to use tmp_path so auto.tfvars.json is written there
        with patch("src.api.services.clone_service.TF_DIR", tmp_path):
            result = svc.create_clone(CloneRequest(name="test-vm", template_id=100))

        assert result.success is True
        assert result.vm_id == 101
        assert result.vm_ip == "10.200.100.10"
        assert result.snapshot_name == "pre-patch-20260408"

    @patch.object(TerraformRunner, "init")
    @patch.object(TerraformRunner, "plan")
    def test_create_clone_plan_failure(self, mock_plan, mock_init, tmp_path):
        mock_init.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        mock_plan.return_value = subprocess.CompletedProcess(
            args=[], returncode=1, stdout="", stderr="Error: Invalid template"
        )

        svc = CloneService()
        with patch("src.api.services.clone_service.TF_DIR", tmp_path):
            result = svc.create_clone(CloneRequest(name="bad-vm", template_id=999))

        assert result.success is False
        assert "Invalid template" in result.error

    @patch.object(TerraformRunner, "init")
    @patch.object(TerraformRunner, "state_list")
    def test_list_clones(self, mock_state, mock_init):
        mock_init.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        mock_state.return_value = [
            'module.test_clone["vm1"].proxmox_vm_qemu.clone',
            'module.test_clone["vm2"].proxmox_vm_qemu.clone',
            "module.clone_network.null_resource.isolated_bridge",
        ]

        svc = CloneService()
        clones = svc.list_clones()
        assert len(clones) == 2
        assert all("test_clone" in c for c in clones)

    @patch("src.api.services.clone_service.subprocess.run")
    def test_snapshot_clone(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout='{"data": "UPID"}', stderr=""
        )
        svc = CloneService()
        svc._initialized = True  # skip init
        with patch.dict("os.environ", {
            "PROXMOX_API_URL": "https://10.100.201.24:8006",
            "PROXMOX_API_TOKEN": "terraform@pam!terraform=test-uuid",
            "PROXMOX_NODE": "meta2-temp",
        }):
            result = svc.snapshot_clone(vm_id=101, snapshot_name="test-snap")

        assert result.success is True
        assert result.snapshot_name == "test-snap"

    @patch("src.api.services.clone_service.subprocess.run")
    def test_rollback_snapshot(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout='{"data": "UPID"}', stderr=""
        )
        svc = CloneService()
        svc._initialized = True
        with patch.dict("os.environ", {
            "PROXMOX_API_URL": "https://10.100.201.24:8006",
            "PROXMOX_API_TOKEN": "terraform@pam!terraform=test-uuid",
            "PROXMOX_NODE": "meta2-temp",
        }):
            result = svc.rollback_snapshot(vm_id=101, snapshot_name="pre-patch")

        assert result.success is True
        assert result.vm_id == 101
