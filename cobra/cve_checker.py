import os
import json
import requests

CVE_CACHE = os.path.join(os.path.dirname(__file__), "data", "cves.json")

def fetch_cves():
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"keywordSearch": "cobol", "resultsPerPage": 100}
    headers = {"User-Agent": "cobra-Scanner/1.0"}

    response = requests.get(url, params=params, headers=headers)
    data = response.json()

    extracted = []
    for vuln in data.get("vulnerabilities", []):
        cve = vuln["cve"]
        desc = cve["descriptions"][0]["value"]
        keywords = [kw.strip().lower() for kw in desc.split() if len(kw) > 5]
        extracted.append({
            "id": cve["id"],
            "summary": desc[:120] + "...",
            "keywords": keywords[:10]  # Limit for performance
        })

    os.makedirs(os.path.dirname(CVE_CACHE), exist_ok=True)
    with open(CVE_CACHE, "w") as f:
        json.dump(extracted, f, indent=2)

def load_cached_cves():
    if not os.path.exists(CVE_CACHE):
        return []
    with open(CVE_CACHE, "r") as f:
        return json.load(f)
