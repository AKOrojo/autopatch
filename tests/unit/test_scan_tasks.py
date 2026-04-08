import os
import uuid
import pytest
from unittest.mock import patch, AsyncMock, MagicMock
from datetime import datetime, timezone

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://x:x@localhost:5432/x")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("JWT_SECRET_KEY", "test-secret")
os.environ.setdefault("API_KEYS", "key1")
os.environ.setdefault("CELERY_BROKER_URL", "redis://localhost:6379/1")
os.environ.setdefault("CELERY_RESULT_BACKEND", "redis://localhost:6379/2")

from src.workers.scan_tasks import _run_scan_async, _ingest_results_async

@pytest.mark.asyncio
async def test_run_scan_dispatches_to_backend():
    mock_backend = AsyncMock()
    mock_backend.start_scan.return_value = "scanner-task-123"
    mock_backend.configure_alert = AsyncMock()

    scan_id = str(uuid.uuid4())
    asset_ip = "10.0.1.10"

    with patch("src.workers.scan_tasks.get_scanner_backend", return_value=mock_backend), \
         patch("src.workers.scan_tasks._get_scan", return_value={
             "id": scan_id, "scanner_type": "openvas", "config": {},
             "asset_ip": asset_ip, "asset_id": str(uuid.uuid4()),
         }), \
         patch("src.workers.scan_tasks._update_scan") as mock_update:
        await _run_scan_async(scan_id)
        mock_backend.start_scan.assert_called_once_with(asset_ip, {})
        mock_backend.configure_alert.assert_called_once()
        assert mock_update.call_count >= 1

@pytest.mark.asyncio
async def test_ingest_results_creates_vulnerabilities():
    mock_backend = AsyncMock()
    mock_backend.get_results.return_value = [
        {
            "title": "Test Vuln", "severity": "high", "cvss_score": 7.5,
            "cve_ids": ["CVE-2023-1234"], "cwe_id": "CWE-400",
            "port": "80/tcp", "description": "A test vulnerability",
            "affected_package": None, "affected_version": None, "fixed_version": None,
        }
    ]
    scan_id = str(uuid.uuid4())
    asset_id = str(uuid.uuid4())

    with patch("src.workers.scan_tasks.get_scanner_backend", return_value=mock_backend), \
         patch("src.workers.scan_tasks._get_scan", return_value={
             "id": scan_id, "scanner_type": "openvas",
             "scanner_task_id": "task-123", "asset_id": asset_id,
         }), \
         patch("src.workers.scan_tasks._update_scan") as mock_update, \
         patch("src.workers.scan_tasks._create_vulnerabilities") as mock_create:
        await _ingest_results_async(scan_id)
        mock_backend.get_results.assert_called_once_with("task-123")
        mock_create.assert_called_once()
        vuln_list = mock_create.call_args[0][0]
        assert len(vuln_list) == 1
        assert vuln_list[0]["title"] == "Test Vuln"
