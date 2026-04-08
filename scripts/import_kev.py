"""Import CISA Known Exploited Vulnerabilities (KEV) catalog."""
import asyncio
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def parse_kev_json(json_content: str) -> list[dict]:
    """Parse CISA KEV JSON content, returning list of {cve_id, is_kev, kev_due_date}."""
    data = json.loads(json_content)
    results = []
    for vuln in data.get("vulnerabilities", []):
        results.append(
            {
                "cve_id": vuln["cveID"],
                "is_kev": True,
                "kev_due_date": vuln.get("dueDate"),
            }
        )
    return results


async def run_kev_import() -> int:
    """Download CISA KEV JSON, parse, and upsert is_kev and kev_due_date into cve_enrichment."""
    import httpx
    from src.api.config import Settings
    from src.shared import database
    from sqlalchemy import text

    settings = Settings()
    database.init_engine(settings.database_url)

    async with httpx.AsyncClient(timeout=60) as client:
        response = await client.get(KEV_URL)
        response.raise_for_status()
        json_content = response.text

    records = parse_kev_json(json_content)
    if not records:
        await database.close_engine()
        return 0

    upsert_sql = text(
        """
        INSERT INTO cve_enrichment (cve_id, is_kev, kev_due_date, updated_at)
        VALUES (:cve_id, :is_kev, :kev_due_date, NOW())
        ON CONFLICT (cve_id) DO UPDATE SET
            is_kev = EXCLUDED.is_kev,
            kev_due_date = EXCLUDED.kev_due_date,
            updated_at = EXCLUDED.updated_at
        """
    )

    async with database.async_session_factory() as session:
        await session.execute(upsert_sql, records)
        await session.commit()

    await database.close_engine()
    return len(records)


if __name__ == "__main__":
    count = asyncio.run(run_kev_import())
    print(f"Upserted {count} KEV records.")
