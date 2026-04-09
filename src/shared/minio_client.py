"""MinIO object storage client for artifact management."""

from __future__ import annotations

import io
import json
import logging

from minio import Minio

logger = logging.getLogger(__name__)


def get_minio_client() -> Minio:
    """Build a MinIO client from settings."""
    from src.api.config import Settings
    settings = Settings()
    return Minio(
        settings.minio_endpoint,
        access_key=settings.minio_access_key,
        secret_key=settings.minio_secret_key,
        secure=settings.minio_secure,
    )


def ensure_bucket(client: Minio, bucket: str) -> None:
    """Create the bucket if it doesn't exist."""
    if not client.bucket_exists(bucket):
        client.make_bucket(bucket)
        logger.info("Created MinIO bucket: %s", bucket)


def upload_json(client: Minio, bucket: str, path: str, data: dict | list) -> str:
    """Upload a JSON object to MinIO. Returns the object path."""
    content = json.dumps(data, indent=2, default=str).encode()
    client.put_object(
        bucket,
        path,
        io.BytesIO(content),
        length=len(content),
        content_type="application/json",
    )
    logger.info("Uploaded %s to MinIO (%d bytes)", path, len(content))
    return path


def upload_text(client: Minio, bucket: str, path: str, text: str) -> str:
    """Upload a text file to MinIO. Returns the object path."""
    content = text.encode()
    client.put_object(
        bucket,
        path,
        io.BytesIO(content),
        length=len(content),
        content_type="text/plain",
    )
    return path
