import json
import os
import time
import logging
import requests

# Configure logging
logging.basicConfig(level=logging.DEBUG, filename="cobra.log", format="%(asctime)s - %(levelname)s - %(message)s")

CVE_CACHE_FILE = "cve_cache.json"
UPDATE_INTERVAL = 24 * 60 * 60  # 24 hours in seconds

def fetch_cves():
    """Fetch and cache CVE data from the NVD API."""
    try:
        logging.debug("Fetching CVE data from NVD API...")
        cve_data = []
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {
            "keywordSearch": "cobol gnucobol visual cobol micro focus cobc",  # Broader keywords
            "resultsPerPage": 2000,  # Max results per page
            "startIndex": 0
        }
        headers = {
            "User-Agent": "CobRA/1.0 (COBOL Risk Analyzer)"
        }

        # Handle pagination
        while True:
            response = requests.get(url, params=params, headers=headers, timeout=10)
            response.raise_for_status()
            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])
            total_results = data.get("totalResults", 0)

            for item in vulnerabilities:
                cve = item.get("cve", {})
                cve_id = cve.get("id", "")
                summary = cve.get("descriptions", [{}])[0].get("value", "No description available")
                # Extract CVSS score
                cvss_score = 0.0
                for metric in cve.get("metrics", {}).values():
                    for m in metric:
                        if "cvssData" in m and "baseScore" in m["cvssData"]:
                            cvss_score = m["cvssData"]["baseScore"]
                            break
                    if cvss_score:
                        break
                # Extract keywords
                keywords = []
                summary_lower = summary.lower()
                for term in [
                    "buffer overflow", "stack-based", "authentication", "username", "password",
                    "user-id", "gnucobol", "visual cobol", "cobol", "cobc/field.c", "cobc/tree.c",
                    "scanner.l", "typeck.c", "micro focus", "cobc"
                ]:
                    if term in summary_lower:
                        keywords.append(term)
                keywords = list(set(keywords))

                cve_data.append({
                    "id": cve_id,
                    "keywords": keywords,
                    "summary": summary,
                    "cvss_score": cvss_score
                })

            # Check for more results
            params["startIndex"] += params["resultsPerPage"]
            if params["startIndex"] >= total_results:
                break

        # Fallback: Add prior CVEs if too few fetched
        if len(cve_data) < 10:
            logging.warning("NVD API returned fewer CVEs than expected. Adding fallback CVEs.")
            fallback_cves = [
                {
                    "id": "CVE-2019-14486",
                    "keywords": ["buffer overflow", "gnucobol", "cobc/field.c", "cobol"],
                    "summary": "GnuCOBOL 2.2 has a buffer overflow in cb_evaluate_expr in cobc/field.c via crafted COBOL source code.",
                    "cvss_score": 7.5
                },
                {
                    "id": "CVE-2019-14528",
                    "keywords": ["buffer overflow", "gnucobol", "scanner.l", "cobol"],
                    "summary": "GnuCOBOL 2.2 has a heap-based buffer overflow in read_literal in cobc/scanner.l via crafted COBOL source code.",
                    "cvss_score": 7.5
                },
                {
                    "id": "CVE-2019-14541",
                    "keywords": ["buffer overflow", "gnucobol", "typeck.c", "cobol"],
                    "summary": "GnuCOBOL 2.2 has a stack-based buffer overflow in cb_encode_program_id in cobc/typeck.c via crafted COBOL source code.",
                    "cvss_score": 7.5
                },
                {
                    "id": "CVE-2012-0918",
                    "keywords": ["cobol", "hitachi"],
                    "summary": "Unspecified vulnerability in Hitachi COBOL2002 Net Developer, Net Server Suite, and Net Client Suite.",
                    "cvss_score": 5.0
                },
                {
                    "id": "CVE-2012-4274",
                    "keywords": ["cobol", "hitachi"],
                    "summary": "Unspecified vulnerability in Hitachi Cobol GUI Option.",
                    "cvss_score": 5.0
                },
                {
                    "id": "CVE-2023-32265",
                    "keywords": ["cobol", "micro focus", "escwa"],
                    "summary": "A potential security vulnerability in the Enterprise Server Common Web Administration (ESCWA) component.",
                    "cvss_score": 6.5
                },
                {
                    "id": "CVE-2001-0208",
                    "keywords": ["cobol", "microfocus"],
                    "summary": "MicroFocus Cobol 4.1 with AppTrack feature installs mfaslmf directory with insecure permissions.",
                    "cvss_score": 4.6
                }
            ]
            existing_ids = {cve["id"] for cve in cve_data}
            for fallback_cve in fallback_cves:
                if fallback_cve["id"] not in existing_ids:
                    cve_data.append(fallback_cve)

        # Save to cache
        cache_data = {
            "last_updated": int(time.time()),
            "cves": cve_data
        }
        with open(CVE_CACHE_FILE, "w") as f:
            json.dump(cache_data, f, indent=4)
        logging.info(f"CVE database updated successfully. {len(cve_data)} CVEs cached.")
        return cve_data
    except Exception as e:
        logging.error(f"Failed to fetch CVE data: {str(e)}")
        return load_cached_cves()

def load_cached_cves():
    """Load cached CVE data if available."""
    try:
        if os.path.exists(CVE_CACHE_FILE):
            with open(CVE_CACHE_FILE, "r") as f:
                cache_data = json.load(f)
            logging.debug(f"Loaded {len(cache_data.get('cves', []))} cached CVEs.")
            return cache_data.get("cves", [])
        logging.warning("No CVE cache found.")
        return []
    except Exception as e:
        logging.error(f"Failed to load cached CVEs: {str(e)}")
        return []

def should_update_cves():
    """Check if CVE cache needs updating based on last update time."""
    try:
        if os.path.exists(CVE_CACHE_FILE):
            with open(CVE_CACHE_FILE, "r") as f:
                cache_data = json.load(f)
            last_updated = cache_data.get("last_updated", 0)
            if (time.time() - last_updated) < UPDATE_INTERVAL:
                logging.debug("CVE cache is up-to-date.")
                return False
        return True
    except Exception as e:
        logging.error(f"Error checking CVE cache: {str(e)}")
        return True