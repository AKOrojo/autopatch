"""Parse scanner output into normalized vulnerability dicts."""
import json
import xml.etree.ElementTree as ET

def _severity_normalize(s: str) -> str:
    s = s.lower().strip()
    if s in ("critical", "high", "medium", "low"):
        return s
    return "info"

def parse_openvas_results(xml_content: str) -> list[dict]:
    root = ET.fromstring(xml_content)
    results = []
    for result_el in root.findall(".//result"):
        nvt = result_el.find("nvt")
        if nvt is None:
            continue
        title = nvt.findtext("name", "")
        description = result_el.findtext("description", "")
        threat = result_el.findtext("threat", "")
        port = result_el.findtext("port", "")
        cvss_score = None
        severity_el = nvt.find(".//severities/severity[@type='cvss_base_v3']/score")
        if severity_el is not None and severity_el.text:
            cvss_score = float(severity_el.text)
        else:
            cvss_base = nvt.find(".//cvss_base/value")
            if cvss_base is not None and cvss_base.text:
                cvss_score = float(cvss_base.text)
        cve_ids = []
        cwe_id = None
        refs = nvt.find("refs")
        if refs is not None:
            for ref in refs.findall("ref"):
                if ref.get("type") == "cve":
                    cve_ids.append(ref.get("id", ""))
                elif ref.get("type") == "cwe" and cwe_id is None:
                    cwe_id = ref.get("id")
        severity = _severity_normalize(threat)
        results.append({
            "title": title, "description": description, "severity": severity,
            "cvss_score": cvss_score, "cve_ids": cve_ids, "cwe_id": cwe_id,
            "port": port, "affected_package": None, "affected_version": None,
            "fixed_version": None,
        })
    return results

def parse_nuclei_results(jsonl_content: str) -> list[dict]:
    results = []
    for line in jsonl_content.strip().splitlines():
        if not line.strip():
            continue
        entry = json.loads(line)
        info = entry.get("info", {})
        severity = _severity_normalize(info.get("severity", "info"))
        if severity == "info":
            continue
        classification = info.get("classification", {})
        cve_ids = classification.get("cve-id", []) or []
        cwe_ids = classification.get("cwe-id", []) or []
        cvss_score = classification.get("cvss-score")
        results.append({
            "title": info.get("name", ""), "description": info.get("description", ""),
            "severity": severity, "cvss_score": float(cvss_score) if cvss_score else None,
            "cve_ids": cve_ids, "cwe_id": cwe_ids[0] if cwe_ids else None,
            "port": entry.get("port", ""), "affected_package": None,
            "affected_version": None, "fixed_version": None,
        })
    return results
