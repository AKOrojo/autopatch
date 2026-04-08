import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path
from src.api.services.scanners.nuclei import NucleiBackend

FIXTURES = Path(__file__).parent.parent / "fixtures"

@pytest.fixture
def nuclei_output():
    return (FIXTURES / "nuclei_output.jsonl").read_text()

@pytest.fixture
def mock_docker_client():
    return MagicMock()

@pytest.mark.asyncio
async def test_start_scan(mock_docker_client, nuclei_output):
    container = MagicMock()
    container.wait.return_value = {"StatusCode": 0}
    container.logs.return_value = nuclei_output.encode()
    mock_docker_client.containers.run.return_value = container
    with patch("src.api.services.scanners.nuclei.docker.from_env", return_value=mock_docker_client):
        backend = NucleiBackend()
        task_id = await backend.start_scan("10.0.1.10", {})
        assert task_id is not None
        mock_docker_client.containers.run.assert_called_once()

@pytest.mark.asyncio
async def test_get_results(mock_docker_client, nuclei_output):
    container = MagicMock()
    container.wait.return_value = {"StatusCode": 0}
    container.logs.return_value = nuclei_output.encode()
    mock_docker_client.containers.run.return_value = container
    with patch("src.api.services.scanners.nuclei.docker.from_env", return_value=mock_docker_client):
        backend = NucleiBackend()
        task_id = await backend.start_scan("10.0.1.10", {})
        results = await backend.get_results(task_id)
        assert len(results) == 2
        assert results[0]["severity"] == "high"
