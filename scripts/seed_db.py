"""Seed the database with a default admin user and sample assets."""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import select
from src.api.config import Settings
from src.shared import database
from src.api.models.asset import Asset
from src.api.models.user import User
import bcrypt


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


DEFAULT_USERS = [
    {"email": "admin@autopatch.local", "name": "Admin", "password": "changeme123", "role": "admin"},
    {"email": "operator@autopatch.local", "name": "Operator", "password": "changeme123", "role": "operator"},
    {"email": "viewer@autopatch.local", "name": "Viewer", "password": "changeme123", "role": "viewer"},
]

SAMPLE_ASSETS = [
    {"hostname": "web-01", "ip_address": "10.0.1.10", "os_family": "ubuntu", "os_version": "22.04", "environment": "production", "criticality": "high"},
    {"hostname": "db-01", "ip_address": "10.0.1.20", "os_family": "ubuntu", "os_version": "22.04", "environment": "production", "criticality": "critical"},
    {"hostname": "cache-01", "ip_address": "10.0.1.30", "os_family": "debian", "os_version": "12", "environment": "production", "criticality": "medium"},
    {"hostname": "dev-web-01", "ip_address": "10.0.2.10", "os_family": "ubuntu", "os_version": "24.04", "environment": "development", "criticality": "low"},
    {"hostname": "staging-app-01", "ip_address": "10.0.3.10", "os_family": "centos", "os_version": "9", "environment": "staging", "criticality": "medium"},
]


async def seed():
    settings = Settings()
    database.init_engine(settings.database_url)

    async with database.async_session_factory() as session:
        # Seed users
        existing_user = await session.execute(select(User).limit(1))
        if existing_user.scalar_one_or_none():
            print("Users already seeded. Skipping users.")
        else:
            for user_data in DEFAULT_USERS:
                session.add(User(
                    email=user_data["email"],
                    name=user_data["name"],
                    password_hash=hash_password(user_data["password"]),
                    role=user_data["role"],
                ))
            await session.commit()
            print(f"Seeded {len(DEFAULT_USERS)} users:")
            for u in DEFAULT_USERS:
                print(f"  - {u['email']} (role: {u['role']}, password: {u['password']})")

        # Seed assets
        existing_asset = await session.execute(select(Asset).limit(1))
        if existing_asset.scalar_one_or_none():
            print("Assets already seeded. Skipping assets.")
        else:
            for asset_data in SAMPLE_ASSETS:
                session.add(Asset(**asset_data))
            await session.commit()
            print(f"Seeded {len(SAMPLE_ASSETS)} sample assets.")

    await database.close_engine()


if __name__ == "__main__":
    asyncio.run(seed())
