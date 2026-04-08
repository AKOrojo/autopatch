"""Seed the database with a default admin user and sample assets."""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import select
from src.api.config import Settings
from src.shared.database import init_engine, async_session_factory, close_engine
from src.api.models.asset import Asset


SAMPLE_ASSETS = [
    {"hostname": "web-01", "ip_address": "10.0.1.10", "os_family": "ubuntu", "os_version": "22.04", "environment": "production", "criticality": "high"},
    {"hostname": "db-01", "ip_address": "10.0.1.20", "os_family": "ubuntu", "os_version": "22.04", "environment": "production", "criticality": "critical"},
    {"hostname": "cache-01", "ip_address": "10.0.1.30", "os_family": "debian", "os_version": "12", "environment": "production", "criticality": "medium"},
    {"hostname": "dev-web-01", "ip_address": "10.0.2.10", "os_family": "ubuntu", "os_version": "24.04", "environment": "development", "criticality": "low"},
    {"hostname": "staging-app-01", "ip_address": "10.0.3.10", "os_family": "centos", "os_version": "9", "environment": "staging", "criticality": "medium"},
]


async def seed():
    settings = Settings()
    init_engine(settings.database_url)

    async with async_session_factory() as session:
        result = await session.execute(select(Asset).limit(1))
        if result.scalar_one_or_none():
            print("Database already seeded. Skipping.")
            await close_engine()
            return

        for asset_data in SAMPLE_ASSETS:
            session.add(Asset(**asset_data))
        await session.commit()
        print(f"Seeded {len(SAMPLE_ASSETS)} sample assets.")

    await close_engine()


if __name__ == "__main__":
    asyncio.run(seed())
