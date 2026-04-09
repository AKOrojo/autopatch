# tests/unit/test_dead_letter.py
"""Unit tests for the dead letter node."""

import pytest
from unittest.mock import patch, MagicMock, AsyncMock

from src.agents.nodes.dead_letter import dead_letter_node


def _make_state(**overrides):
    base = {
        "vulnerability_id": "vuln-1",
        "asset_id": "asset-1",
        "cve_id": "CVE-2024-1234",
        "scan_data": {"severity": "high"},
        "strategy": "vendor_patch",
        "remediation_plan": {"target_host": "10.0.0.5", "vm_id": 200, "clone_name": "test-clone"},
        "dead_letter_reason": "all_strategies_exhausted",
        "strategy_history": [
            {"strategy": "vendor_patch", "attempt": 1, "error": "package not found"},
            {"strategy": "vendor_patch", "attempt": 2, "error": "repo unreachable"},
        ],
        "verification_results": {"overall": "fail", "failure_reason": "still vulnerable"},
        "execution_result": {"pre_commands": [], "playbook": {"exit_code": 1}},
        "total_attempts": 2,
    }
    base.update(overrides)
    return base


class TestDeadLetterNode:
    @pytest.mark.asyncio
    async def test_bundles_artifacts_to_minio(self):
        with patch("src.agents.nodes.dead_letter.get_minio_client") as mock_minio, \
             patch("src.agents.nodes.dead_letter.ensure_bucket") as mock_bucket, \
             patch("src.agents.nodes.dead_letter.upload_json") as mock_upload, \
             patch("src.agents.nodes.dead_letter.upload_text") as mock_upload_text, \
             patch("src.agents.nodes.dead_letter.notify_dead_letter", new_callable=AsyncMock) as mock_notify, \
             patch("src.agents.nodes.dead_letter.CloneService") as mock_clone:

            mock_clone_instance = MagicMock()
            mock_clone.return_value = mock_clone_instance
            mock_clone_instance.destroy_clone.return_value = MagicMock(success=True)
            mock_upload.return_value = "autopatch/dead_letter/vuln-1/strategy_history.json"

            result = await dead_letter_node(_make_state())
            assert result["status"] == "dead_letter"
            assert result["artifact_bundle_path"] is not None
            assert mock_upload.call_count >= 2
            mock_notify.assert_called_once()

    @pytest.mark.asyncio
    async def test_destroys_clone_on_dead_letter(self):
        with patch("src.agents.nodes.dead_letter.get_minio_client") as mock_minio, \
             patch("src.agents.nodes.dead_letter.ensure_bucket"), \
             patch("src.agents.nodes.dead_letter.upload_json"), \
             patch("src.agents.nodes.dead_letter.upload_text"), \
             patch("src.agents.nodes.dead_letter.notify_dead_letter", new_callable=AsyncMock), \
             patch("src.agents.nodes.dead_letter.CloneService") as mock_clone:

            mock_clone_instance = MagicMock()
            mock_clone.return_value = mock_clone_instance
            mock_clone_instance.destroy_clone.return_value = MagicMock(success=True)

            state = _make_state()
            await dead_letter_node(state)
            mock_clone_instance.destroy_clone.assert_called_once()
