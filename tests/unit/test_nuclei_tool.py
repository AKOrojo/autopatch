"""Unit tests for the Nuclei scan runner tool."""

import json
import pytest
from unittest.mock import AsyncMock, patch, MagicMock

from src.agents.tools.nuclei_tool import run_nuclei_scan, NucleiResult


class TestNucleiTool:
    @pytest.mark.asyncio
    async def test_successful_scan_parses_findings(self):
        mock_output = json.dumps({"info": {"name": "test"}, "matched-at": "http://10.0.0.5:80"}) + "\n"
        mock_proc = MagicMock()
        mock_proc.communicate = AsyncMock(return_value=(mock_output.encode(), b""))
        mock_proc.returncode = 0

        with patch("asyncio.create_subprocess_exec", new_callable=AsyncMock, return_value=mock_proc):
            result = await run_nuclei_scan("10.0.0.5", template_ids=["CVE-2024-1234"])
            assert result.exit_code == 0
            assert len(result.findings) == 1

    @pytest.mark.asyncio
    async def test_no_findings_returns_empty(self):
        mock_proc = MagicMock()
        mock_proc.communicate = AsyncMock(return_value=(b"", b""))
        mock_proc.returncode = 0

        with patch("asyncio.create_subprocess_exec", new_callable=AsyncMock, return_value=mock_proc):
            result = await run_nuclei_scan("10.0.0.5")
            assert result.exit_code == 0
            assert result.findings == []

    @pytest.mark.asyncio
    async def test_timeout_returns_error(self):
        mock_proc = MagicMock()
        mock_proc.communicate = AsyncMock(side_effect=TimeoutError())
        mock_proc.kill = MagicMock()

        with patch("asyncio.create_subprocess_exec", new_callable=AsyncMock, return_value=mock_proc):
            result = await run_nuclei_scan("10.0.0.5", timeout=5)
            assert result.exit_code == -1
            assert "timeout" in result.stderr.lower()
