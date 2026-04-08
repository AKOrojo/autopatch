import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path
from src.api.services.scanners.trivy import TrivyBackend

FIXTURES = Path(__file__).parent.parent / "fixtures"

@pytest.fixture
def trivy_output():
    return (FIXTURES / "trivy_output.json").read_text()

@pytest.fixture
def mock_docker_client():
    return MagicMock()

@pytest.mark.asyncio
async def test_start_scan(mock_docker_client, trivy_output):
    container = MagicMock()
    container.wait.return_value = {"StatusCode": 0}
    container.logs.return_value = trivy_output.encode()
    mock_docker_client.containers.run.return_value = container
    with patch("src.api.services.scanners.trivy.docker.from_env", return_value=mock_docker_client):
        backend = TrivyBackend()
        task_id = await backend.start_scan("", {"image": "nginx:1.25"})
        assert task_id is not None

@pytest.mark.asyncio
async def test_get_results(mock_docker_client, trivy_output):
    container = MagicMock()
    container.wait.return_value = {"StatusCode": 0}
    container.logs.return_value = trivy_output.encode()
    mock_docker_client.containers.run.return_value = container
    with patch("src.api.services.scanners.trivy.docker.from_env", return_value=mock_docker_client):
        backend = TrivyBackend()
        task_id = await backend.start_scan("", {"image": "nginx:1.25"})
        results = await backend.get_results(task_id)
        assert len(results) == 2
        assert results[0]["cve_ids"] == ["CVE-2023-44487"]
        assert results[0]["affected_package"] == "libnghttp2-14"

@pytest.mark.asyncio
async def test_start_scan_requires_image():
    backend = TrivyBackend()
    with pytest.raises(ValueError, match="image"):
        await backend.start_scan("", {})
