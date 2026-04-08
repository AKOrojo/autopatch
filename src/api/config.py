from typing import Annotated

from pydantic import BeforeValidator
from pydantic_settings import BaseSettings, NoDecode


def _parse_comma_separated(v: str | list[str]) -> list[str]:
    if isinstance(v, str):
        return [key.strip() for key in v.split(",") if key.strip()]
    return v


CommaSeparatedList = Annotated[list[str], NoDecode, BeforeValidator(_parse_comma_separated)]


class Settings(BaseSettings):
    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
    }

    # Database
    database_url: str

    # Redis
    redis_url: str

    # JWT
    jwt_secret_key: str
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 60

    # API Keys
    api_keys: CommaSeparatedList

    # App
    app_name: str = "Autopatch"
    debug: bool = False
    log_level: str = "INFO"
