import os
os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://x:x@localhost:5432/x")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("JWT_SECRET_KEY", "test-secret")
os.environ.setdefault("API_KEYS", "key1")

from unittest.mock import MagicMock
from src.agents.tools.nvd_tool import nvd_lookup

def test_nvd_lookup_from_cache():
    mock_session = MagicMock()
    mock_row = MagicMock()
    mock_row.cve_id = "CVE-2023-44487"
    mock_row.description = "HTTP/2 Rapid Reset"
    mock_row.cvss_v3_score = 7.5
    mock_row.cvss_v3_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
    mock_row.references = ["https://example.com/advisory"]
    mock_row.affected_configs = []
    mock_session.execute.return_value.scalar_one_or_none.return_value = mock_row

    result = nvd_lookup("CVE-2023-44487", session=mock_session)
    assert result["cve_id"] == "CVE-2023-44487"
    assert result["description"] == "HTTP/2 Rapid Reset"
    assert result["cvss_v3_score"] == 7.5
    assert len(result["references"]) == 1

def test_nvd_lookup_not_found():
    mock_session = MagicMock()
    mock_session.execute.return_value.scalar_one_or_none.return_value = None
    result = nvd_lookup("CVE-9999-0001", session=mock_session)
    assert result is None
