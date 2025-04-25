import json
import os
import click
from cobra.scanner import scan_directory
from cobra.cve_checker import fetch_cves, load_cached_cves, should_update_cves
from cobra.utils import generate_uid
from cobra.vuln_checker import (
    check_for_xss,
    check_for_sql_injection,
    check_for_command_injection,
    check_for_insecure_cryptographic_storage,
    check_for_csrf
)

@click.group()
def cli():
    """cobra - COBOL Risk Analyzer"""
    pass

@cli.command()
@click.argument("path")
@click.option("--output", type=click.Path(), help="Path to save results.")
@click.option("--format", type=click.Choice(["json", "sarif"]), help="Export format.")
@click.option("--line-tolerance", type=int, default=10, help="Line number tolerance for matching ignored findings.")
@click.option("--quiet", is_flag=True, help="Suppress all non-critical console output during scan.")
@click.option("--verbose", is_flag=True, help="Show detailed debug logs of findings.")
@click.option("--no-update", is_flag=True, help="Skip automatic CVE database update.")
def scan(path, output, format, line_tolerance, quiet, verbose, no_update):
    """Scan COBOL files in the provided directory for CVEs and vulnerabilities."""
    # Update CVE database unless --no-update is specified
    if not no_update and should_update_cves():
        if not quiet:
            click.echo("[Info] Updating CVE database...")
        fetch_cves()
    cves = load_cached_cves()
    if not quiet and not cves:
        click.echo("[Warning] CVE database is empty. Run 'cobra update-cve-db' to populate it.")

    # Load ignored findings
    ignored_findings = load_ignored_uids()
    if not quiet and ignored_findings:
        click.echo(f"[Info] Loaded {len(ignored_findings)} ignored findings.")

    # Collect CVE results
    if not quiet:
        click.echo("[Debug] Starting scan_directory")
    try:
        results = scan_directory(path, cves, quiet=quiet)
        if results is None:
            if not quiet:
                click.echo("[Error] scan_directory returned None. Check for errors in the scanner or input path.")
            results = []
        else:
            if not quiet:
                click.echo(f"[Info] Found {len(results)} CVE-related issues.")
            if verbose:
                click.echo("[Debug] CVE results:")
                for result in results:
                    click.echo(result)
    except Exception as e:
        if not quiet:
            click.echo(f"[Error] Failed to scan directory: {str(e)}")
        results = []

    # Collect vulnerability results
    if not quiet:
        click.echo("[Debug] Starting scan_vulnerabilities")
    vulnerability_results = scan_vulnerabilities(path, quiet=quiet)
    if not quiet:
        click.echo(f"[Info] Found {len(vulnerability_results)} vulnerability issues.")
    if verbose:
        click.echo("[Debug] Vulnerability results:")
        for result in vulnerability_results:
            click.echo(result)

    # Combine results
    results.extend(vulnerability_results)

    # Filter out ignored findings
    filtered_results = []
    unmatched_ignores = set(ignored_findings.keys())
    for result in results:
        uid = result["uid"]
        if uid in ignored_findings:
            # Verify match with line tolerance and code snippet
            ignored = ignored_findings[uid]
            line_diff = abs(result["line"] - ignored["line"])
            snippet_match = result["code_snippet"] == ignored["code_snippet"]
            if line_diff <= line_tolerance and snippet_match:
                unmatched_ignores.discard(uid)
                continue
        filtered_results.append(result)
    results = filtered_results

    # Warn about unmatched ignored findings
    if not quiet and unmatched_ignores:
        click.echo(f"[Warning] {len(unmatched_ignores)} ignored findings no longer match any vulnerabilities. Run 'cobra ignore-list' to review.")

    if not quiet:
        click.echo(f"[Info] Total findings after ignoring: {len(results)}")
    if verbose:
        click.echo("[Debug] Results before export:")
        for result in results:
            click.echo(result)

    # Export results if output is specified
    if output:
        if not quiet and os.path.exists(output):
            click.echo(f"[Warning] {output} already exists and will be overwritten.")
        elif not quiet:
            click.echo(f"[Info] Creating new file: {output}")

        # Export results to the requested format
        export_results(results, output, format, quiet=quiet)
        if not quiet:
            click.echo(f"[Success] Results have been saved to: {os.path.abspath(output)}")

@cli.command()
def update_cve_db():
    """Update the local CVE cache."""
    fetch_cves()
    click.echo("CVE database updated.")

@cli.command()
@click.argument("uid")
@click.option("--file", type=click.Path(exists=True), help="File associated with the finding.")
@click.option("--vulnerability", help="Vulnerability type (e.g., CVE-2019-14468).")
@click.option("--line", type=int, help="Line number of the finding.")
@click.option("--code-snippet", help="Code snippet associated with the finding.")
def ignore(uid, file, vulnerability, line, code_snippet):
    """Add a finding UID to the ignore list."""
    ignored_findings = load_ignored_uids()
    if uid not in ignored_findings:
        ignored_findings[uid] = {
            "file": file,
            "vulnerability": vulnerability,
            "line": line,
            "code_snippet": code_snippet
        }
        try:
            with open("ignore.json", "w") as f:
                json.dump({"ignored_findings": ignored_findings}, f, indent=4)
            click.echo(f"[Success] UID {uid} added to ignore list.")
        except IOError as e:
            click.echo(f"[Error] Failed to update ignore.json: {str(e)}")
    else:
        click.echo(f"[Info] UID {uid} is already in the ignore list.")

@cli.command()
@click.option("--prune", is_flag=True, help="Remove unmatched ignored findings.")
def ignore_list(prune):
    """List all ignored findings and optionally prune unmatched ones."""
    ignored_findings = load_ignored_uids()
    if not ignored_findings:
        click.echo("[Info] No ignored findings.")
        return

    click.echo("[Info] Ignored findings:")
    for uid, details in ignored_findings.items():
        click.echo(
            f"UID: {uid}, File: {details['file']}, Vulnerability: {details['vulnerability']}, "
            f"Line: {details['line']}, Snippet: {details['code_snippet'][:50]}..."
        )

    if prune:
        click.echo("[Warning] Pruning requires a scan to identify unmatched findings. Run 'cobra scan' to detect outdated ignores.")

def load_ignored_uids():
    """Load the dictionary of ignored findings from ignore.json."""
    try:
        if not os.path.exists("ignore.json"):
            # Initialize empty ignore.json
            with open("ignore.json", "w") as f:
                json.dump({"ignored_findings": {}}, f)
            logging.info("Created empty ignore.json")
            return {}
        with open("ignore.json", "r") as f:
            data = json.load(f)
            return data.get("ignored_findings", {})
    except (IOError, json.JSONDecodeError) as e:
        logging.warning(f"Failed to load ignore.json: {str(e)}. Initializing empty ignore list.")
        try:
            with open("ignore.json", "w") as f:
                json.dump({"ignored_findings": {}}, f)
        except IOError as e:
            logging.error(f"Failed to create ignore.json: {str(e)}")
        return {}

def scan_vulnerabilities(path, quiet=False):
    """Check COBOL files for common vulnerabilities."""
    findings = []

    def analyze_file(file_path):
        filename = os.path.basename(file_path)
        try:
            with open(file_path, "r", errors="ignore") as file:
                lines = file.readlines()
            code = "".join(lines)
        except IOError as e:
            if not quiet:
                click.echo(f"[Error] Failed to read {file_path}: {str(e)}")
            return

        # Check for COBOL-specific vulnerabilities (e.g., ACCEPT statements)
        for i, line in enumerate(lines, 1):
            if "ACCEPT" in line.upper():
                code_snippet = "".join(lines[max(0, i-2):min(len(lines), i+1)]).strip()
                findings.append({
                    "file": file_path,
                    "vulnerability": "Unvalidated Input",
                    "message": f"Use of ACCEPT statement (unvalidated input) at line {i}",
                    "severity": "Medium",
                    "line": i,
                    "uid": generate_uid(file_path, "Unvalidated Input", i, code_snippet),
                    "code_snippet": code_snippet
                })
                if not quiet:
                    click.echo(f"Unvalidated Input vulnerability found in {filename}: ACCEPT statement at line {i}")

        # Check for XSS vulnerabilities
        xss_issues = check_for_xss(code)
        for issue in xss_issues:
            code_snippet = "N/A"
            findings.append({
                "file": file_path,
                "vulnerability": "XSS",
                "message": issue,
                "severity": "Medium",
                "line": 0,
                "uid": generate_uid(file_path, "XSS", 0, code_snippet),
                "code_snippet": code_snippet
            })
            if not quiet:
                click.echo(f"XSS vulnerability found in {filename}: {issue}")

        # Check for SQL Injection vulnerabilities
        sql_issues = check_for_sql_injection(code)
        for issue in sql_issues:
            code_snippet = "N/A"
            findings.append({
                "file": file_path,
                "vulnerability": "SQL Injection",
                "message": issue,
                "severity": "High",
                "line": 0,
                "uid": generate_uid(file_path, "SQL Injection", 0, code_snippet),
                "code_snippet": code_snippet
            })
            if not quiet:
                click.echo(f"SQL Injection vulnerability found in {filename}: {issue}")

        # Check for Command Injection vulnerabilities
        command_issues = check_for_command_injection(code)
        for issue in command_issues:
            code_snippet = "N/A"
            findings.append({
                "file": file_path,
                "vulnerability": "Command Injection",
                "message": issue,
                "severity": "High",
                "line": 0,
                "uid": generate_uid(file_path, "Command Injection", 0, code_snippet),
                "code_snippet": code_snippet
            })
            if not quiet:
                click.echo(f"Command Injection vulnerability found in {filename}: {issue}")

        # Check for Insecure Cryptographic Storage vulnerabilities
        cryptographic_issues = check_for_insecure_cryptographic_storage(code)
        for issue in cryptographic_issues:
            code_snippet = "N/A"
            findings.append({
                "file": file_path,
                "vulnerability": "Insecure Cryptographic Storage",
                "message": issue,
                "severity": "Medium",
                "line": 0,
                "uid": generate_uid(file_path, "Insecure Cryptographic Storage", 0, code_snippet),
                "code_snippet": code_snippet
            })
            if not quiet:
                click.echo(f"Insecure Cryptographic Storage issue found in {filename}: {issue}")

        # Check for CSRF vulnerabilities
        csrf_issues = check_for_csrf(code)
        for issue in csrf_issues:
            code_snippet = "N/A"
            findings.append({
                "file": file_path,
                "vulnerability": "CSRF",
                "message": issue,
                "severity": "Medium",
                "line": 0,
                "uid": generate_uid(file_path, "CSRF", 0, code_snippet),
                APDATE_INTERVAL = 24 * 60 * 60  # 24 hours in seconds

def fetch_cves():
    """Fetch and cache CVE data from a source (e.g., NVD API)."""
    try:
        logging.debug("Fetching CVE data...")
        # Mock data for testing; replace with actual API call
        cve_data = [
            {
                "id": "CVE-2019-14468",
                "keywords": ["buffer overflow", "gnucobol", "cobc/field.c"],
                "summary": "GnuCOBOL 2.2 has a buffer overflow in cb_push_op in cobc/field.c via crafted COBOL source code.",
                "cvss_score": 7.5
            },
            {
                "id": "CVE-2019-16395",
                "keywords": ["stack-based buffer overflow", "gnucobol", "cobc/tree.c"],
                "summary": "GnuCOBOL 2.2 has a stack-based buffer overflow in the cb_name() function in cobc/tree.c via crafted COBOL source code.",
                "cvss_score": 7.8
            },
            {
                "id": "CVE-2023-4501",
                "keywords": ["authentication", "visual cobol", "username", "password"],
                "summary": "User authentication with username and password credentials is ineffective in OpenText (Micro Focus) Visual COBOL.",
                "cvss_score": 6.5
            }
        ]
        # Example: Fetch from NVD API (uncomment for real use)
        # response = requests.get("https://services.nvd.nist.gov/rest/json/cves/2.0", timeout=10)
        # response.raise_for_status()
        # cve_data = response.json().get("vulnerabilities", [])

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