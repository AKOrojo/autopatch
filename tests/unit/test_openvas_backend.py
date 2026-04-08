import pytest
from unittest.mock import MagicMock, patch
from pathlib import Path
from src.api.services.scanners.openvas import OpenVASBackend

FIXTURES = Path(__file__).parent.parent / "fixtures"

@pytest.fixture
def mock_gmp():
    gmp = MagicMock()
    gmp.create_target = MagicMock(return_value='<create_target_response status="201" id="target-uuid-1"/>')
    gmp.create_task = MagicMock(return_value='<create_task_response status="201" id="task-uuid-1"/>')
    gmp.start_task = MagicMock(return_value='<start_task_response status="202"><report_id>report-uuid-1</report_id></start_task_response>')
    gmp.get_task = MagicMock(return_value='<get_tasks_response><task><status>Done</status></task></get_tasks_response>')
    gmp.create_alert = MagicMock(return_value='<create_alert_response status="201" id="alert-uuid-1"/>')
    xml_results = (FIXTURES / "openvas_results.xml").read_text()
    gmp.get_results = MagicMock(return_value=xml_results)
    return gmp

@pytest.mark.asyncio
async def test_start_scan(mock_gmp):
    with patch.object(OpenVASBackend, "_get_gmp", return_value=mock_gmp):
        backend = OpenVASBackend()
        task_id = await backend.start_scan("10.0.1.10", {})
        assert task_id == "task-uuid-1"
        mock_gmp.create_target.assert_called_once()
        mock_gmp.create_task.assert_called_once()
        mock_gmp.start_task.assert_called_once()

@pytest.mark.asyncio
async def test_get_scan_status(mock_gmp):
    with patch.object(OpenVASBackend, "_get_gmp", return_value=mock_gmp):
        backend = OpenVASBackend()
        status = await backend.get_scan_status("task-uuid-1")
        assert status == "completed"

@pytest.mark.asyncio
async def test_get_results(mock_gmp):
    with patch.object(OpenVASBackend, "_get_gmp", return_value=mock_gmp):
        backend = OpenVASBackend()
        results = await backend.get_results("task-uuid-1")
        assert len(results) == 2
        assert results[0]["title"] == "Apache HTTP Server < 2.4.58 Multiple Vulnerabilities"

@pytest.mark.asyncio
async def test_configure_alert(mock_gmp):
    with patch.object(OpenVASBackend, "_get_gmp", return_value=mock_gmp):
        backend = OpenVASBackend()
        await backend.configure_alert("task-uuid-1", "http://api:8000/api/v1/scans/webhook/openvas?scan_id=123")
        mock_gmp.create_alert.assert_called_once()
