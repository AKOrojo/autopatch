"""Shared OpenAI-compatible LLM client for all agents."""

from openai import OpenAI

_client: OpenAI | None = None


def get_llm_client(base_url: str | None = None, api_key: str = "not-needed") -> OpenAI:
    """Return a shared OpenAI client. Reuses singleton if base_url unchanged."""
    global _client
    if _client is None or (base_url and _client.base_url != base_url):
        if base_url is None:
            from src.api.config import Settings
            settings = Settings()
            base_url = settings.llm_base_url
        _client = OpenAI(base_url=base_url, api_key=api_key)
    return _client


def get_model_name() -> str:
    """Return the configured model name."""
    from src.api.config import Settings
    return Settings().llm_model


def reset_client():
    """Reset the singleton (for testing)."""
    global _client
    _client = None
