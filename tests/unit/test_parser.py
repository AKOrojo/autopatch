from pathlib import Path
from src.api.services.scanners.parser import (
    parse_openvas_results,
    parse_nuclei_results,
)

FIXTURES = Path(__file__).parent.parent / "fixtures"

def test_parse_openvas_results():
    xml_content = (FIXTURES / "openvas_results.xml").read_text()
    results = parse_openvas_results(xml_content)
    assert len(results) == 2
    r1 = results[0]
    assert r1["title"] == "Apache HTTP Server < 2.4.58 Multiple Vulnerabilities"
    assert r1["severity"] == "high"
    assert r1["cvss_score"] == 7.5
    assert "CVE-2023-45802" in r1["cve_ids"]
    assert r1["cwe_id"] == "CWE-400"
    assert r1["port"] == "80/tcp"
    r2 = results[1]
    assert r2["severity"] == "medium"
    assert r2["cwe_id"] == "CWE-327"
    assert r2["cve_ids"] == []

def test_parse_nuclei_results():
    jsonl_content = (FIXTURES / "nuclei_output.jsonl").read_text()
    results = parse_nuclei_results(jsonl_content)
    assert len(results) == 2  # info severity filtered out
    r1 = results[0]
    assert r1["title"] == "Apache HTTP Server < 2.4.58 - DoS"
    assert r1["severity"] == "high"
    assert r1["cvss_score"] == 7.5
    assert "CVE-2023-45802" in r1["cve_ids"]
    r2 = results[1]
    assert r2["severity"] == "medium"

def test_parse_openvas_empty():
    results = parse_openvas_results('<get_results_response status="200"></get_results_response>')
    assert results == []

def test_parse_nuclei_empty():
    results = parse_nuclei_results("")
    assert results == []

