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
        "extra": "ignore",
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

    # Greenbone GMP
    gmp_host: str = "gvmd"
    gmp_port: int = 9390
    gmp_username: str = "admin"
    gmp_password: str = "admin"

    # Celery
    celery_broker_url: str = "redis://localhost:6379/1"
    celery_result_backend: str = "redis://localhost:6379/2"

    # Scanner webhook base URL
    webhook_base_url: str = "http://api:8000"

    # NVD API (optional)
    nvd_api_key: str | None = None

    # LLM (OpenAI-compatible endpoint)
    llm_base_url: str = "http://vllm:8001/v1"
    llm_model: str = "Qwen/Qwen3-30B-A3B"

    # HashiCorp Vault
    vault_addr: str = "http://vault:8200"
    vault_role_id: str = ""
    vault_secret_id: str = ""

    # Executor sandbox
    executor_ssh_user: str = "autopatch"
    executor_cert_ttl: str = "5m"

    # MinIO
    minio_endpoint: str = "minio:9000"
    minio_access_key: str = "autopatch"
    minio_secret_key: str = "autopatch_dev"
    minio_bucket: str = "autopatch"
    minio_secure: bool = False

    # Notifications
    notification_webhook_url: str = ""

    # SMTP
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_from_email: str = "autopatch@localhost"

    # Global settings
    global_mode: str = "auto"
