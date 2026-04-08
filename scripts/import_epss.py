"""Import EPSS scores from FIRST.org / Cyentia Institute."""
import asyncio
import gzip
import io
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"


def parse_epss_csv(csv_content: str) -> list[dict]:
    """Parse EPSS CSV content, skipping comment and header lines."""
    results = []
    lines = csv_content.splitlines()
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(",")
        if parts[0].lower() == "cve":
            # header row
            continue
        cve_id, epss_score, epss_percentile = parts[0], parts[1], parts[2]
        results.append(
            {
                "cve_id": cve_id,
                "epss_score": float(epss_score),
                "epss_percentile": float(epss_percentile),
            }
        )
    return results


async def run_epss_import() -> int:
    """Download EPSS gzipped CSV, parse, and bulk upsert into cve_enrichment."""
    import httpx
    from src.api.config import Settings
    from src.shared import database

    settings = Settings()
    database.init_engine(settings.database_url)

    async with httpx.AsyncClient(timeout=120) as client:
        response = await client.get(EPSS_URL)
        response.raise_for_status()
        compressed = response.content

    with gzip.open(io.BytesIO(compressed), "rt", encoding="utf-8") as f:
        csv_content = f.read()

    records = parse_epss_csv(csv_content)
    if not records:
        await database.close_engine()
        return 0

    from sqlalchemy import text

    upsert_sql = text(
        """
        INSERT INTO cve_enrichment (cve_id, epss_score, epss_percentile, epss_updated_at, updated_at)
        VALUES (:cve_id, :epss_score, :epss_percentile, NOW(), NOW())
        ON CONFLICT (cve_id) DO UPDATE SET
            epss_score = EXCLUDED.epss_score,
            epss_percentile = EXCLUDED.epss_percentile,
            epss_updated_at = EXCLUDED.epss_updated_at,
            updated_at = EXCLUDED.updated_at
        """
    )

    async with database.async_session_factory() as session:
        await session.execute(upsert_sql, records)
        await session.commit()

    await database.close_engine()
    return len(records)


if __name__ == "__main__":
    count = asyncio.run(run_epss_import())
    print(f"Upserted {count} EPSS records.")
