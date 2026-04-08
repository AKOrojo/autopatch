"""Unit tests for the Ansible tool."""

import json

from src.agents.tools.ansible_tool import (
    PlaybookSpec,
    generate_inventory,
    generate_playbook,
)


class TestPlaybookSpec:
    def test_vendor_patch_role_mapping(self):
        spec = PlaybookSpec(name="test", hosts="target", strategy="vendor_patch")
        assert spec.role_name == "patch-package"

    def test_config_workaround_role_mapping(self):
        spec = PlaybookSpec(name="test", hosts="target", strategy="config_workaround")
        assert spec.role_name == "config-fix"

    def test_compensating_control_role_mapping(self):
        spec = PlaybookSpec(name="test", hosts="target", strategy="compensating_control")
        assert spec.role_name == "compensating-control"

    def test_unknown_strategy_defaults_to_patch(self):
        spec = PlaybookSpec(name="test", hosts="target", strategy="unknown")
        assert spec.role_name == "patch-package"


class TestGeneratePlaybook:
    def test_generates_valid_json(self):
        spec = PlaybookSpec(
            name="patch-vuln-001",
            hosts="target",
            strategy="vendor_patch",
            variables={"package_name": "nginx"},
        )
        content = generate_playbook(spec)
        parsed = json.loads(content)
        assert isinstance(parsed, list)
        assert len(parsed) == 1

    def test_playbook_structure(self):
        spec = PlaybookSpec(
            name="patch-vuln-001",
            hosts="target",
            strategy="vendor_patch",
            variables={"package_name": "nginx"},
        )
        content = generate_playbook(spec)
        pb = json.loads(content)[0]
        assert pb["name"] == "patch-vuln-001"
        assert pb["hosts"] == "target"
        assert pb["become"] is True
        assert pb["vars"]["package_name"] == "nginx"
        assert pb["roles"][0]["role"] == "patch-package"
        assert len(pb["pre_tasks"]) == 1

    def test_playbook_includes_pre_check_role(self):
        spec = PlaybookSpec(name="test", hosts="target", strategy="vendor_patch")
        pb = json.loads(generate_playbook(spec))[0]
        pre_task = pb["pre_tasks"][0]
        assert pre_task["ansible.builtin.include_role"]["name"] == "pre-check"


class TestGenerateInventory:
    def test_basic_inventory(self):
        inv = generate_inventory("10.0.0.5", "autopatch")
        assert "[target]" in inv
        assert "10.0.0.5" in inv
        assert "ansible_user=autopatch" in inv

    def test_inventory_with_cert(self):
        inv = generate_inventory(
            "10.0.0.5", "autopatch",
            cert_file="/tmp/cert.pub",
            private_key="/tmp/id_ed25519",
        )
        assert "CertificateFile=/tmp/cert.pub" in inv
        assert "ansible_ssh_private_key_file=/tmp/id_ed25519" in inv

    def test_custom_port(self):
        inv = generate_inventory("10.0.0.5", "autopatch", port=2222)
        assert "ansible_port=2222" in inv


class TestInventoryFormatting:
    def test_all_host_vars_on_single_line(self):
        """All host variables must be on the same line as the host for Ansible INI."""
        inv = generate_inventory(
            "10.0.0.5", "autopatch",
            cert_file="/tmp/cert.pub",
            private_key="/tmp/id_ed25519",
        )
        lines = [l for l in inv.strip().splitlines() if l.strip()]
        # Should have exactly 2 lines: [target] header and host line
        assert len(lines) == 2
        assert lines[0] == "[target]"
        assert "10.0.0.5" in lines[1]
        assert "ansible_user=autopatch" in lines[1]
        assert "CertificateFile=/tmp/cert.pub" in lines[1]
        assert "ansible_ssh_private_key_file=/tmp/id_ed25519" in lines[1]
