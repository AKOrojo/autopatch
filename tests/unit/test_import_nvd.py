import json
from pathlib import Path
from scripts.import_cve_feed import parse_nvd_response

FIXTURES = Path(__file__).parent.parent / "fixtures"

def test_parse_nvd_response():
    json_content = (FIXTURES / "nvd_sample.json").read_text()
    data = json.loads(json_content)
    results = parse_nvd_response(data)
    assert len(results) == 2
    r1 = results[0]
    assert r1["cve_id"] == "CVE-2023-44487"
    assert r1["cvss_v3_score"] == 7.5
    assert "CVSS:3.1" in r1["cvss_v3_vector"]
    assert "denial of service" in r1["description"]
    assert len(r1["references"]) == 2
    r2 = results[1]
    assert r2["cve_id"] == "CVE-2023-45802"
    assert r2["cvss_v3_score"] == 5.9

def test_parse_nvd_empty():
    results = parse_nvd_response({"vulnerabilities": []})
    assert results == []
