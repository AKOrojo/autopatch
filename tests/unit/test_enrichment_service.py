from src.api.services.enrichment_service import enrich_vuln_dicts

def test_enrich_vuln_dicts_matches():
    enrichment_data = {
        "CVE-2023-44487": {
            "epss_score": 0.94271, "epss_percentile": 0.99926,
            "is_kev": True, "cvss_v3_score": 7.5,
        },
    }
    vuln_dicts = [
        {"cve_ids": ["CVE-2023-44487"], "cvss_score": None, "title": "Test", "severity": "high"},
        {"cve_ids": ["CVE-9999-0001"], "cvss_score": 5.0, "title": "Unknown", "severity": "medium"},
        {"cve_ids": [], "cvss_score": None, "title": "No CVE", "severity": "low"},
    ]
    enriched = enrich_vuln_dicts(vuln_dicts, enrichment_data)
    assert len(enriched) == 3
    assert enriched[0]["epss_score"] == 0.94271
    assert enriched[0]["epss_percentile"] == 0.99926
    assert enriched[0]["is_kev"] is True
    assert enriched[0]["cvss_score"] == 7.5
    assert enriched[1].get("epss_score") is None
    assert enriched[1]["cvss_score"] == 5.0
    assert enriched[2].get("epss_score") is None

def test_enrich_vuln_dicts_empty_enrichment():
    vuln_dicts = [{"cve_ids": ["CVE-2023-1234"], "cvss_score": 7.0, "title": "X", "severity": "high"}]
    enriched = enrich_vuln_dicts(vuln_dicts, {})
    assert enriched[0].get("epss_score") is None
    assert enriched[0]["cvss_score"] == 7.0
