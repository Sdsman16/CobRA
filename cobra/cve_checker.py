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
        # NVD API endpoint with query parameters to filter COBOL-related CVEs
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {
            "keywordSearch": "cobol gnucobol visual cobol",  # Search for COBOL-related terms
            "resultsPerPage": 2000,  # Max results per page (NVD limit)
            "startIndex": 0  # Start at the beginning
        }
        headers = {
            "User-Agent": "CobRA/1.0 (COBOL Risk Analyzer)"
        }
        response = requests.get(url, params=params, headers=headers, timeout=10)
        response.raise_for_status()
        data = response.json()

        cve_data = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")
            summary = cve.get("descriptions", [{}])[0].get("value", "No description available")
            # Extract CVSS score (use v3.1 or v3.0 if available)
            cvss_score = 0.0
            for metric in cve.get("metrics", {}).values():
                for m in metric:
                    if "cvssData" in m and "baseScore" in m["cvssData"]:
                        cvss_score = m["cvssData"]["baseScore"]
                        break
                if cvss_score:
                    break
            # Extract keywords from summary
            keywords = []
            summary_lower = summary.lower()
            for term in ["buffer overflow", "stack-based", "authentication", "username", "password", "user-id", "gnucobol", "visual cobol", "cobol", "cobc/field.c", "cobc/tree.c"]:
                if term in summary_lower:
                    keywords.append(term)
            # Add additional keywords based on CVE context
            if "gnucobol" in summary_lower:
                keywords.append("cobc")
            if "visual cobol" in summary_lower:
                keywords.append("micro focus")
            # Ensure unique keywords
            keywords = list(set(keywords))

            cve_data.append({
                "id": cve_id,
                "keywords": keywords,
                "summary": summary,
                "cvss_score": cvss_score
            })

        # Save to cache with timestamp
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