import json
import os
import time
import logging
import requests  # Assuming CVE data is fetched via an API

# Configure logging
logging.basicConfig(level=logging.DEBUG, filename="cobra.log", format="%(asctime)s - %(levelname)s - %(message)s")

CVE_CACHE_FILE = "cve_cache.json"
UPDATE_INTERVAL = 24 * 60 * 60  # 24 hours in seconds

def fetch_cves():
    """Fetch and cache CVE data from a source (e.g., NVD API)."""
    try:
        logging.debug("Fetching CVE data...")
        # Example: Fetch from NVD API (replace with actual source, e.g., NIST NVD)
        response = requests.get("https://services.nvd.nist.gov/rest/json/cves/2.0", timeout=10)
        response.raise_for_status()
        cve_data = response.json().get("vulnerabilities", [])

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