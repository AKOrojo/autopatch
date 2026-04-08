from pathlib import Path
from scripts.import_epss import parse_epss_csv

FIXTURES = Path(__file__).parent.parent / "fixtures"

def test_parse_epss_csv():
    csv_content = (FIXTURES / "epss_sample.csv").read_text()
    results = parse_epss_csv(csv_content)
    assert len(results) == 5
    r1 = results[0]
    assert r1["cve_id"] == "CVE-2023-44487"
    assert r1["epss_score"] == 0.94271
    assert r1["epss_percentile"] == 0.99926
    r4 = results[3]
    assert r4["cve_id"] == "CVE-2021-44228"
    assert r4["epss_score"] == 0.97547

def test_parse_epss_csv_empty():
    results = parse_epss_csv("#model_version:v1\ncve,epss,percentile\n")
    assert results == []
