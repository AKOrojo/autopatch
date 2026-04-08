"""URL fetcher with HTML-to-text conversion."""
import logging
import httpx
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

def html_to_text(html_content: str) -> str:
    soup = BeautifulSoup(html_content, "html.parser")
    for tag in soup(["script", "style", "nav", "footer", "header"]):
        tag.decompose()
    text = soup.get_text(separator="\n", strip=True)
    lines = [line.strip() for line in text.splitlines()]
    lines = [line for line in lines if line]
    return "\n".join(lines)

async def fetch_url(url: str, timeout: float = 30.0) -> str | None:
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            resp = await client.get(url)
            resp.raise_for_status()
            content_type = resp.headers.get("content-type", "")
            if "html" in content_type:
                return html_to_text(resp.text)
            else:
                return resp.text
    except Exception:
        logger.warning("Failed to fetch URL: %s", url, exc_info=True)
        return None
