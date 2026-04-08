"""Shared OpenAI-compatible LLM client factory."""
from openai import OpenAI
from src.api.config import Settings

_client: OpenAI | None = None

def get_llm_client() -> OpenAI:
    global _client
    if _client is None:
        settings = Settings()
        _client = OpenAI(base_url=settings.llm_base_url, api_key="not-needed")
    return _client

def get_model_name() -> str:
    return Settings().llm_model
