import pytest
from unittest.mock import patch, MagicMock, AsyncMock
from src.agents.tools.docs_tool import html_to_text, fetch_url

def test_html_to_text_basic():
    html = "<html><body><h1>Title</h1><p>Some text here.</p><script>var x=1;</script></body></html>"
    text = html_to_text(html)
    assert "Title" in text
    assert "Some text here" in text
    assert "var x=1" not in text

def test_html_to_text_plain():
    text = html_to_text("Just plain text with no HTML")
    assert text == "Just plain text with no HTML"

@pytest.mark.asyncio
async def test_fetch_url_success():
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.text = "<html><body><p>Advisory content</p></body></html>"
    mock_response.headers = {"content-type": "text/html"}
    mock_response.raise_for_status = MagicMock()

    with patch("src.agents.tools.docs_tool.httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.get.return_value = mock_response
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client_cls.return_value = mock_client

        result = await fetch_url("https://example.com/advisory")
        assert "Advisory content" in result
        assert "<html>" not in result

@pytest.mark.asyncio
async def test_fetch_url_failure():
    with patch("src.agents.tools.docs_tool.httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.get.side_effect = Exception("Connection failed")
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client_cls.return_value = mock_client

        result = await fetch_url("https://example.com/dead-link")
        assert result is None
