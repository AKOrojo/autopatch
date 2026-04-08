from pathlib import Path
from scripts.import_kev import parse_kev_json

FIXTURES = Path(__file__).parent.parent / "fixtures"

def test_parse_kev_json():
    json_content = (FIXTURES / "kev_sample.json").read_text()
    results = parse_kev_json(json_content)
    assert len(results) == 3
    r1 = results[0]
    assert r1["cve_id"] == "CVE-2021-44228"
    assert r1["is_kev"] is True
    assert r1["kev_due_date"] == "2021-12-24"

def test_parse_kev_json_empty():
    results = parse_kev_json('{"vulnerabilities": []}')
    assert results == []
