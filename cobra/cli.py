import json
import os
import click
import logging
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

# Configure logging
logging.basicConfig(level=logging.DEBUG, filename="cobra.log", format="%(asctime)s - %(levelname)s - %(message)s")

@click.group()
def cli():
    """cobra - COBOL Risk Analyzer"""
    pass

def get_fix_recommendation(vulnerability, message):
    """Return a fix recommendation based on the vulnerability type."""
    if "CVE-" in vulnerability:
        if "buffer overflow" in message.lower():
            return "Implement bounds checking on array accesses and use safe COBOL constructs like INSPECT to validate data lengths."
        return "Review the CVE description for specific mitigation steps and update COBOL runtime or compiler settings accordingly."
    elif vulnerability == "Unvalidated Input":
        return "Validate and sanitize user input before using ACCEPT; consider using a validation routine or restricting input length."
    elif vulnerability == "XSS":
        return "Sanitize user input and escape output in COBOL DISPLAY statements to prevent script injection."
    elif vulnerability == "SQL Injection":
        return "Use parameterized queries or EXEC SQL PREPARE for database operations in COBOL to prevent injection."
    elif vulnerability == "Command Injection":
        return "Avoid dynamic CALL statements with user input; use static CALLs or validate inputs strictly."
    elif vulnerability == "Insecure Cryptographic Storage":
        return "Use secure COBOL libraries for encryption (e.g., COBOL SSL extensions) and avoid hardcoded keys."
    elif vulnerability == "CSRF":
        return "Implement CSRF tokens in COBOL web interactions and validate requests on the server side."
    return "Review COBOL best practices for secure coding and apply input validation or runtime checks."

def filter_by_severity(results, severity=None, severity_and_lower=None):
    """Filter findings based on severity threshold or severity and lower."""
    if severity is None and severity_and_lower is None:
        return results

    # Define severity hierarchy
    severity_levels = {"high": 3, "medium": 2, "low": 1}

    filtered_results = []
    for result in results:
        result_severity = result["severity"].lower()
        result_level = severity_levels.get(result_severity, 0)

        if severity is not None:
            # Exact severity match
            if result_severity == severity.lower():
                filtered_results.append(result)
        elif severity_and_lower is not None:
            # Severity and lower
            threshold_level = severity_levels.get(severity_and_lower.lower(), 0)
            if result_level <= threshold_level and result_level > 0:
                filtered_results.append(result)

    return filtered_results

@cli.command()
@click.argument("directory")
@click.option("--output", type=click.Path(), help="Path to save results.")
@click.option("--format", type=click.Choice(["json", "sarif"]), help="Export format.")
@click.option("--line-tolerance", type=int, default=10, help="Line number tolerance for matching ignored findings.")
@click.option("--quiet", is_flag=True, help="Suppress all non-critical console output during scan.")
@click.option("--verbose", is_flag=True, help="Show detailed debug logs of findings.")
@click.option("--no-update", is_flag=True, help="Skip automatic CVE database update.")
@click.option("--severity", type=click.Choice(["high", "medium", "low"], case_sensitive=False), help="Show only findings of the specified severity.")
@click.option("--severity-and-lower", type=click.Choice(["high", "medium", "low"], case_sensitive=False), help="Show findings of the specified severity and lower.")
def scan(directory, output, format, line_tolerance, quiet, verbose, no_update, severity, severity_and_lower):
    """Scan COBOL files in the provided directory for CVEs and vulnerabilities."""
    # Validate mutually exclusive options
    if severity is not None and severity_and_lower is not None:
        raise click.UsageError("Options --severity and --severity-and-lower are mutually exclusive.")

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
        results = scan_directory(directory, cves, quiet=quiet)
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
    vulnerability_results = scan_vulnerabilities(directory, quiet=quiet)
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

    # Apply severity filter
    results = filter_by_severity(results, severity=severity, severity_and_lower=severity_and_lower)

    if not quiet:
        click.echo(f"[Info] Total findings after filtering: {len(results)}")
    if verbose:
        click.echo("[Debug] Results before export:")
        for result in results:
            click.echo(result)

    # Export results if output is specified
    if output:
        if not quiet and os.path.exists(output):
            click.echo(f"[Warning] {output} already exists even after filtering and will be overwritten.")
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
                vulnerability = "Unvalidated Input"
                message = f"Use of ACCEPT statement (unvalidated input) at line {i}"
                finding = {
                    "file": file_path,
                    "vulnerability": vulnerability,
                    "message": message,
                    "severity": "Medium",
                    "line": i,
                    "uid": generate_uid(file_path, vulnerability, i, code_snippet),
                    "code_snippet": code_snippet,
                    "fix": get_fix_recommendation(vulnerability, message)
                }
                findings.append(finding)
                if not quiet:
                    click.echo(f"Unvalidated Input vulnerability found in {filename}: ACCEPT statement at line {i}")
                    click.echo(f"    [Fix] {finding['fix']}")

        # Check for XSS vulnerabilities
        xss_issues = check_for_xss(code)
        for issue in xss_issues:
            code_snippet = "N/A"
            vulnerability = "XSS"
            finding = {
                "file": file_path,
                "vulnerability": vulnerability,
                "message": issue,
                "severity": "Medium",
                "line": 0,
                "uid": generate_uid(file_path, vulnerability, 0, code_snippet),
                "code_snippet": code_snippet,
                "fix": get_fix_recommendation(vulnerability, issue)
            }
            findings.append(finding)
            if not quiet:
                click.echo(f"XSS vulnerability found in {filename}: {issue}")
                click.echo(f"    [Fix] {finding['fix']}")

        # Check for SQL Injection vulnerabilities
        sql_issues = check_for_sql_injection(code)
        for issue in sql_issues:
            code_snippet = "N/A"
            vulnerability = "SQL Injection"
            finding = {
                "file": file_path,
                "vulnerability": vulnerability,
                "message": issue,
                "severity": "High",
                "line": 0,
                "uid": generate_uid(file_path, vulnerability, 0, code_snippet),
                "code_snippet": code_snippet,
                "fix": get_fix_recommendation(vulnerability, issue)
            }
            findings.append(finding)
            if not quiet:
                click.echo(f"SQL Injection vulnerability found in {filename}: {issue}")
                click.echo(f"    [Fix] {finding['fix']}")

        # Check for Command Injection vulnerabilities
        command_issues = check_for_command_injection(code)
        for issue in command_issues:
            code_snippet = "N/A"
            vulnerability = "Command Injection"
            finding = {
                "file": file_path,
                "vulnerability": vulnerability,
                "message": issue,
                "severity": "High",
                "line": 0,
                "uid": generate_uid(file_path, vulnerability, 0, code_snippet),
                "code_snippet": code_snippet,
                "fix": get_fix_recommendation(vulnerability, issue)
            }
            findings.append(finding)
            if not quiet:
                click.echo(f"Command Injection vulnerability found in {filename}: {issue}")
                click.echo(f"    [Fix] {finding['fix']}")

        # Check for Insecure Cryptographic Storage vulnerabilities
        cryptographic_issues = check_for_insecure_cryptographic_storage(code)
        for issue in cryptographic_issues:
            code_snippet = "N/A"
            vulnerability = "Insecure Cryptographic Storage"
            finding = {
                "file": file_path,
                "vulnerability": vulnerability,
                "message": issue,
                "severity": "Medium",
                "line": 0,
                "uid": generate_uid(file_path, vulnerability, 0, code_snippet),
                "code_snippet": code_snippet,
                "fix": get_fix_recommendation(vulnerability, issue)
            }
            findings.append(finding)
            if not quiet:
                click.echo(f"Insecure Cryptographic Storage issue found in {filename}: {issue}")
                click.echo(f"    [Fix] {finding['fix']}")

        # Check for CSRF vulnerabilities
        csrf_issues = check_for_csrf(code)
        for issue in csrf_issues:
            code_snippet = "N/A"
            vulnerability = "CSRF"
            finding = {
                "file": file_path,
                "vulnerability": vulnerability,
                "message": issue,
                "severity": "Medium",
                "line": 0,
                "uid": generate_uid(file_path, vulnerability, 0, code_snippet),
                "code_snippet": code_snippet,
                "fix": get_fix_recommendation(vulnerability, issue)
            }
            findings.append(finding)
            if not quiet:
                click.echo(f"CSRF vulnerability found in {filename}: {issue}")
                click.echo(f"    [Fix] {finding['fix']}")

    # Handle both file and directory input
    if os.path.isdir(path):
        for root, _, files in os.walk(path):
            for file in files:
                if file.endswith(".cbl"):
                    analyze_file(os.path.join(root, file))
    elif os.path.isfile(path):
        if path.endswith(".cbl"):
            analyze_file(path)
        else:
            if not quiet:
                click.echo(f"[Error] {path} is not a .cbl file.")
    else:
        if not quiet:
            click.echo(f"[Error] {path} is not a valid file or directory.")

    return findings

def export_results(results, output, format, quiet=False):
    """Export the scan results to the specified format (JSON/SARIF)."""
    if not results:
        if not quiet:
            click.echo("[Warning] No results to export.")
        return

    if format == "json":
        try:
            with open(output, "w") as json_file:
                json.dump(results, json_file, indent=4)
            if not quiet:
                click.echo(f"[Info] Results exported to {output} in JSON format.")
        except IOError as e:
            click.echo(f"[Error] Failed to write JSON file: {str(e)}")

    elif format == "sarif":
        # Create SARIF-compatible structure
        sarif_results = {
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "cobra",
                        "version": "1.0"
                    }
                },
                "results": [{
                    "ruleId": result.get("vulnerability", "Unknown"),
                    "level": result.get("severity", "warning").lower(),
                    "message": {
                        "text": result.get("message", "No details")
                    },
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": result.get("file", "unknown")
                            },
                            "region": {
                                "startLine": result.get("line", 1)
                            }
                        }
                    }],
                    "properties": {
                        "uid": result.get("uid", "unknown"),
                        "code_snippet": result.get("code_snippet", "N/A"),
                        "cvss_score": result.get("cvss_score", 0.0),
                        "fix": result.get("fix", "No fix available")
                    }
                } for result in results]
            }]
        }

        try:
            with open(output, "w") as sarif_file:
                json.dump(sarif_results, sarif_file, indent=4)
            if not quiet:
                click.echo(f"[Info] Results exported to {output} in SARIF format.")
        except IOError as e:
            click.echo(f"[Error] Failed to write SARIF file: {str(e)}")

if __name__ == "__main__":
    cli()