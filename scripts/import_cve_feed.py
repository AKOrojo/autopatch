"""Import CVE data from NVD 2.0 API."""
import argparse
import asyncio
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_PAGE_SIZE = 2000


def parse_nvd_response(data: dict) -> list[dict]:
    """Parse NVD 2.0 API response into a list of enrichment dicts."""
    results = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id")

        # Description (English preferred)
        description = ""
        for desc in cve.get("descriptions", []):
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break

        # CVSS v3 metrics — try V31 then V30
        cvss_v3_score = None
        cvss_v3_vector = None
        metrics = cve.get("metrics", {})
        for metric_key in ("cvssMetricV31", "cvssMetricV30"):
            metric_list = metrics.get(metric_key, [])
            if metric_list:
                cvss_data = metric_list[0].get("cvssData", {})
                cvss_v3_score = cvss_data.get("baseScore")
                cvss_v3_vector = cvss_data.get("vectorString")
                break

        # References — list of URLs
        references = [ref.get("url") for ref in cve.get("references", []) if ref.get("url")]

        # Affected configurations
        affected_configs = cve.get("configurations", [])

        results.append(
            {
                "cve_id": cve_id,
                "description": description,
                "cvss_v3_score": cvss_v3_score,
                "cvss_v3_vector": cvss_v3_vector,
                "references": references,
                "affected_configs": affected_configs,
            }
        )
    return results


async def run_nvd_import(since_hours: int = 24) -> int:
    """Paginated fetch from NVD 2.0, upsert into cve_enrichment. Returns total count."""
    import httpx
    from src.api.config import Settings
    from src.shared import database
    from sqlalchemy import text

    settings = Settings()
    database.init_engine(settings.database_url)

    api_key = settings.nvd_api_key
    rate_delay = 1.0 if api_key else 6.0

    headers = {}
    if api_key:
        headers["apiKey"] = api_key

    from datetime import datetime, timedelta, timezone

    now = datetime.now(timezone.utc)
    pub_start = (now - timedelta(hours=since_hours)).strftime("%Y-%m-%dT%H:%M:%S.000")
    pub_end = now.strftime("%Y-%m-%dT%H:%M:%S.000")

    all_records: list[dict] = []
    start_index = 0

    async with httpx.AsyncClient(timeout=60, headers=headers) as client:
        while True:
            params = {
                "pubStartDate": pub_start,
                "pubEndDate": pub_end,
                "resultsPerPage": NVD_PAGE_SIZE,
                "startIndex": start_index,
            }
            response = await client.get(NVD_BASE_URL, params=params)
            response.raise_for_status()
            data = response.json()

            page_records = parse_nvd_response(data)
            all_records.extend(page_records)

            total = data.get("totalResults", 0)
            start_index += len(page_records)
            if start_index >= total or not page_records:
                break

            await asyncio.sleep(rate_delay)

    if not all_records:
        await database.close_engine()
        return 0

    upsert_sql = text(
        """
        INSERT INTO cve_enrichment (
            cve_id, description, cvss_v3_score, cvss_v3_vector,
            "references", affected_configs, updated_at
        )
        VALUES (
            :cve_id, :description, :cvss_v3_score, :cvss_v3_vector,
            :references, :affected_configs, NOW()
        )
        ON CONFLICT (cve_id) DO UPDATE SET
            description = EXCLUDED.description,
            cvss_v3_score = EXCLUDED.cvss_v3_score,
            cvss_v3_vector = EXCLUDED.cvss_v3_vector,
            "references" = EXCLUDED."references",
            affected_configs = EXCLUDED.affected_configs,
            updated_at = EXCLUDED.updated_at
        """
    )

    # Serialize JSONB fields
    db_records = [
        {
            **rec,
            "references": json.dumps(rec["references"]),
            "affected_configs": json.dumps(rec["affected_configs"]),
        }
        for rec in all_records
    ]

    async with database.async_session_factory() as session:
        await session.execute(upsert_sql, db_records)
        await session.commit()

    await database.close_engine()
    return len(all_records)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Import CVEs from NVD 2.0 API")
    parser.add_argument("--hours", type=int, default=24, help="Look back N hours (default: 24)")
    args = parser.parse_args()

    count = asyncio.run(run_nvd_import(since_hours=args.hours))
    print(f"Upserted {count} NVD CVE records.")
