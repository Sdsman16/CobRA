import json
import os
import click
import logging
import sys
import re
from cobra.scanner import scan_directory
from cobra.cve_checker import fetch_cves, load_cached_cves, should_update_cves
from cobra.utils import generate_uid
from cobra.vuln_checker import (
    check_for_xss,
    check_for_sql_injection,
    check_for_command_injection,
    check_for_insecure_cryptographic_storage,
    check_for_csrf,
    check_for_file_handling_vulnerabilities,
    check_for_hardcoded_sensitive_data,
    check_for_arithmetic_overflows,
    check_for_insecure_data_transmission,
    check_for_improper_error_handling,
    check_for_insecure_session_management
)
from rich.console import Console

# Configure logging
logging.basicConfig(level=logging.DEBUG, filename="cobra.log", format="%(asctime)s - %(levelname)s - %(message)s")

console = Console()

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
        if "Severity: High" in message:
            return "User input detected in CALL statement with injection patterns; strictly validate and sanitize input to prevent command injection (e.g., reject '&', '|', ';' sequences)."
        elif "Severity: Medium" in message:
            return "User input detected in CALL statement; validate inputs strictly or use static CALLs to prevent potential command injection."
        return "Avoid dynamic CALL statements with variables that could be manipulated; use static CALLs or validate inputs."
    elif vulnerability == "Insecure Cryptographic Storage":
        return "Use secure COBOL libraries for encryption (e.g., COBOL SSL extensions) and avoid hardcoded keys."
    elif vulnerability == "CSRF":
        return "Implement CSRF tokens in COBOL web interactions and validate requests on the server side."
    elif vulnerability == "File Traversal":
        if "Severity: High" in message:
            return "User input detected in file name; strictly validate and sanitize input to prevent path traversal (e.g., reject '../' sequences)."
        return "Validate file names in SELECT statements and avoid using user input directly in file paths."
    elif vulnerability == "Resource Exhaustion":
        return "Ensure all opened files are properly closed using CLOSE statements to prevent resource leaks."
    elif vulnerability == "Hardcoded Sensitive Data":
        return "Remove hardcoded sensitive data; use environment variables or a secure vault to store credentials and keys."
    elif vulnerability == "Arithmetic Overflow":
        return "Add ON SIZE ERROR clause to arithmetic operations to handle overflows gracefully."
    elif vulnerability == "Divide-by-Zero":
        return "Add a check for zero divisor before DIVIDE statements to prevent crashes."
    elif vulnerability == "Insecure Data Transmission":
        return "Use secure communication protocols like HTTPS or SSL/TLS for data transmission."
    elif vulnerability == "Improper Error Handling":
        return "Add ON ERROR or AT END clauses to handle errors properly and avoid displaying sensitive information."
    elif vulnerability == "Insecure Session Management":
        return "Use secure, unique session tokens and regenerate them on login/logout to prevent session hijacking."
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

def load_ignored_uids():
    """Load the dictionary of ignored findings from ignore.json."""
    try:
        if not os.path.exists("ignore.json"):
            # Initialize empty ignore.json
            with open("ignore.json", "w") as f:
                json.dump({"ignored_findings": {}}, f)
            logging.info("Created empty ignore.json")
            console.print("[bold blue][Info] Created empty ignore.json[/bold blue]")
            return {}
        with open("ignore.json", "r") as f:
            data = json.load(f)
            return data.get("ignored_findings", {})
    except (IOError, json.JSONDecodeError) as e:
        logging.warning(f"Failed to load ignore.json: {str(e)}. Initializing empty ignore list.")
        console.print(f"[bold yellow][Warning] Failed to load ignore.json: {str(e)}. Initializing empty ignore list.[/bold yellow]")
        try:
            with open("ignore.json", "w") as f:
                json.dump({"ignored_findings": {}}, f)
        except IOError as e:
            logging.error(f"Failed to create ignore.json: {str(e)}")
            console.print(f"[bold red][Error] Failed to create ignore.json: {str(e)}[/bold red]")
        return {}

def compare_results(current_results, delta_path):
    """Compare current scan results with previous results to identify net new vulnerabilities."""
    if not os.path.exists(delta_path):
        console.print(f"[bold yellow][Warning] Delta results file {delta_path} does not exist. Treating all findings as new.[/bold yellow]")
        return current_results

    try:
        with open(delta_path, "r") as f:
            previous_results = json.load(f)
    except (IOError, json.JSONDecodeError) as e:
        console.print(f"[bold red][Error] Failed to load delta results from {delta_path}: {str(e)}. Treating all findings as new.[/bold red]")
        return current_results

    # Extract UIDs from previous results
    previous_uids = {result["uid"] for result in previous_results}

    # Identify net new vulnerabilities (present in current but not in previous)
    new_vulnerabilities = [result for result in current_results if result["uid"] not in previous_uids]

    if new_vulnerabilities and not previous_results:
        console.print(f"[bold yellow][Info] No previous vulnerabilities found in {delta_path}. All {len(new_vulnerabilities)} vulnerabilities are considered new.[/bold yellow]")
    elif new_vulnerabilities:
        console.print(f"[bold yellow][Info] Found {len(new_vulnerabilities)} net new vulnerabilities compared to previous scan.[/bold yellow]")
        for vuln in new_vulnerabilities:
            severity = vuln["severity"].capitalize()
            color = "red" if severity == "High" else "yellow" if severity == "Medium" else "white"
            console.print(
                f"  [{color}]{severity.upper()}[/{color}] (line {vuln['line']}): {vuln['message']} "
                f"[cyan](UID: {vuln['uid'][:8]}..., CVSS: {vuln['cvss_score']})[/cyan]"
            )
            console.print(f"    [bold green]Fix:[/bold green] {vuln['fix']}")
    else:
        console.print("[bold green][Info] No net new vulnerabilities found compared to previous scan.[/bold green]")

    return new_vulnerabilities

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
@click.option("--delta", type=click.Path(exists=True), help="Path to previous scan results for delta comparison to identify net new vulnerabilities.")
def scan(directory, output, format, line_tolerance, quiet, verbose, no_update, severity, severity_and_lower, delta):
    """Scan COBOL files in the provided directory for CVEs and vulnerabilities."""
    # Validate mutually exclusive options
    if severity is not None and severity_and_lower is not None:
        raise click.UsageError("Options --severity and --severity-and-lower are mutually exclusive.")

    # Update CVE database unless --no-update is specified
    if not no_update and should_update_cves():
        if not quiet:
            console.print("[bold blue][Info] Updating CVE database...[/bold blue]")
        fetch_cves()
    cves = load_cached_cves()
    if not quiet and not cves:
        console.print("[bold yellow][Warning] CVE database is empty. Run 'cobra update-cve-db' to populate it.[/bold yellow]")

    # Load ignored findings
    ignored_findings = load_ignored_uids()
    if not quiet and ignored_findings:
        console.print(f"[bold blue][Info] Loaded {len(ignored_findings)} ignored findings.[/bold blue]")

    # Collect CVE results
    if not quiet:
        console.print("[bold blue][Debug] Starting scan_directory[/bold blue]")
    try:
        results = scan_directory(directory, cves, quiet=quiet, severity=severity, severity_and_lower=severity_and_lower)
        if results is None:
            if not quiet:
                console.print("[bold red][Error] scan_directory returned None. Check for errors in the scanner or input path.[/bold red]")
            results = []
        else:
            if not quiet:
                console.print(f"[bold blue][Info] Found {len(results)} CVE-related issues after severity filtering.[/bold blue]")
            if verbose:
                console.print("[bold blue][Debug] CVE results:[/bold blue]")
                for result in results:
                    console.print(result)
    except Exception as e:
        if not quiet:
            console.print(f"[bold red][Error] Failed to scan directory: {str(e)}[/bold red]")
        results = []

    # Collect vulnerability results
    if not quiet:
        console.print("[bold blue][Debug] Starting scan_vulnerabilities[/bold blue]")
    vulnerability_results = scan_vulnerabilities(directory, quiet=quiet)
    if not quiet:
        console.print(f"[bold blue][Info] Found {len(vulnerability_results)} vulnerability issues before severity filtering.[/bold blue]")
    if verbose:
        console.print("[bold blue][Debug] Vulnerability results:[/bold blue]")
        for result in vulnerability_results:
            console.print(result)

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
        console.print(f"[bold yellow][Warning] {len(unmatched_ignores)} ignored findings no longer match any vulnerabilities. Run 'cobra ignore-list' to review.[/bold yellow]")

    # Apply severity filter to combined results
    total_before_filter = len(results)
    results = filter_by_severity(results, severity=severity, severity_and_lower=severity_and_lower)

    if not quiet:
        console.print(f"[bold blue][Info] Total findings before filtering: {total_before_filter}[/bold blue]")
        console.print(f"[bold blue][Info] Total findings after severity filtering: {len(results)}[/bold blue]")
    if verbose:
        console.print("[bold blue][Debug] Results before export:[/bold blue]")
        for result in results:
            console.print(result)

    # Compare with previous results if specified
    new_vulnerabilities = []
    if delta:
        new_vulnerabilities = compare_results(results, delta)
        if new_vulnerabilities:
            console.print(f"[bold red][Error] Found {len(new_vulnerabilities)} net new vulnerabilities. Breaking the build.[/bold red]")
            sys.exit(1)  # Exit with non-zero status to break the build

    # Check if total vulnerabilities were found and break the build if necessary
    if results and not delta:  # Only check total if not doing delta comparison
        if severity is not None:
            console.print(f"[bold red][Error] Found {len(results)} vulnerabilities of severity '{severity.upper()}'. Breaking the build.[/bold red]")
            sys.exit(1)  # Exit with non-zero status to break the build
        elif severity_and_lower is not None:
            console.print(f"[bold red][Error] Found {len(results)} vulnerabilities of severity '{severity_and_lower.upper()}' or lower. Breaking the build.[/bold red]")
            sys.exit(1)  # Exit with non-zero status to break the build
        else:
            console.print(f"[bold red][Error] Found {len(results)} vulnerabilities. Breaking the build.[/bold red]")
            sys.exit(1)  # Exit with non-zero status to break the build

    # Export results if output is specified
    if output:
        if not quiet and os.path.exists(output):
            console.print(f"[bold yellow][Warning] {output} already exists even after filtering and will be overwritten.[/bold yellow]")
        elif not quiet:
            console.print(f"[bold blue][Info] Creating new file: {output}[/bold blue]")

        # Export results to the requested format
        export_results(results, output, format, quiet=quiet)
        if not quiet:
            console.print(f"[bold green][Success] Results have been saved to: {os.path.abspath(output)}[/bold green]")

@cli.command()
def update_cve_db():
    """Update the local CVE cache."""
    fetch_cves()
    console.print("[bold green]CVE database updated.[/bold green]")

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
            console.print(f"[bold green][Success] UID {uid} added to ignore list.[/bold green]")
        except IOError as e:
            console.print(f"[bold red][Error] Failed to update ignore.json: {str(e)}[/bold red]")
    else:
        console.print(f"[bold blue][Info] UID {uid} is already in the ignore list.[/bold blue]")

@cli.command()
@click.option("--prune", is_flag=True, help="Remove unmatched ignored findings.")
def ignore_list(prune):
    """List all ignored findings and optionally prune unmatched ones."""
    ignored_findings = load_ignored_uids()
    if not ignored_findings:
        console.print("[bold blue][Info] No ignored findings.[/bold blue]")
        return

    console.print("[bold blue][Info] Ignored findings:[/bold blue]")
    for uid, details in ignored_findings.items():
        console.print(
            f"UID: {uid}, File: {details['file']}, Vulnerability: {details['vulnerability']}, "
            f"Line: {details['line']}, Snippet: {details['code_snippet'][:50]}..."
        )

    if prune:
        console.print("[bold yellow][Warning] Pruning requires a scan to identify unmatched findings. Run 'cobra scan' to detect outdated ignores.[/bold yellow]")

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
                console.print(f"[bold red][Error] Failed to read {file_path}: {str(e)}[/bold red]")
            return

        # Check for COBOL-specific vulnerabilities (e.g., ACCEPT statements)
        for i, line in enumerate(lines, 1):
            if "ACCEPT" in line.upper():
                code_snippet = "".join(lines[max(0, i-2):min(len(lines), i+1)]).strip()
                vulnerability = "Unvalidated Input"
                message = f"Use of ACCEPT statement (unvalidated input) at line {i}. Consider validating input length."
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

        # Check for Command Injection vulnerabilities
        command_issues = check_for_command_injection(code)
        for issue in command_issues:
            code_snippet = "N/A"
            vulnerability = "Command Injection"
            # Extract severity from the message
            severity_match = re.search(r"Severity: (\w+)", issue)
            severity = severity_match.group(1) if severity_match else "Medium"
            finding = {
                "file": file_path,
                "vulnerability": vulnerability,
                "message": issue,
                "severity": severity,
                "line": 0,
                "uid": generate_uid(file_path, vulnerability, 0, code_snippet),
                "code_snippet": code_snippet,
                "fix": get_fix_recommendation(vulnerability, issue)
            }
            findings.append(finding)

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

        # Check for File Handling vulnerabilities
        file_issues = check_for_file_handling_vulnerabilities(code)
        for issue in file_issues:
            code_snippet = "N/A"
            vulnerability = "File Traversal" if "File Traversal" in issue else "Resource Exhaustion"
            severity_match = re.search(r"Severity: (\w+)", issue)
            severity = severity_match.group(1) if severity_match else ("Medium" if vulnerability == "File Traversal" else "Low")
            finding = {
                "file": file_path,
                "vulnerability": vulnerability,
                "message": issue,
                "severity": severity,
                "line": 0,
                "uid": generate_uid(file_path, vulnerability, 0, code_snippet),
                "code_snippet": code_snippet,
                "fix": get_fix_recommendation(vulnerability, issue)
            }
            findings.append(finding)

        # Check for Hardcoded Sensitive Data
        hakked_issues = check_for_hardcoded_sensitive_data(code)
        for issue in hardcoded_issues:
            code_snippet = "N/A"
            vulnerability = "Hardcoded Sensitive Data"
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

        # Check for Arithmetic Overflows
        arithmetic_issues = check_for_arithmetic_overflows(code)
        for issue in arithmetic_issues:
            code_snippet = "N/A"
            vulnerability = "Arithmetic Overflow" if "Overflow" in issue else "Divide-by-Zero"
            severity = "Medium" if vulnerability == "Arithmetic Overflow" else "High"
            finding = {
                "file": file_path,
                "vulnerability": vulnerability,
                "message": issue,
                "severity": severity,
                "line": 0,
                "uid": generate_uid(file_path, vulnerability, 0, code_snippet),
                "code_snippet": code_snippet,
                "fix": get_fix_recommendation(vulnerability, issue)
            }
            findings.append(finding)

        # Check for Insecure Data Transmission
        transmission_issues = check_for_insecure_data_transmission(code)
        for issue in transmission_issues:
            code_snippet = "N/A"
            vulnerability = "Insecure Data Transmission"
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

        # Check for Improper Error Handling
        error_handling_issues = check_for_improper_error_handling(code)
        for issue in error_handling_issues:
            code_snippet = "N/A"
            vulnerability = "Improper Error Handling" if "ON ERROR" not in issue else "Information Disclosure"
            severity = "Medium" if vulnerability == "Information Disclosure" else "Low"
            finding = {
                "file": file_path,
                "vulnerability": vulnerability,
                "message": issue,
                "severity": severity,
                "line": 0,
                "uid": generate_uid(file_path, vulnerability, 0, code_snippet),
                "code_snippet": code_snippet,
                "fix": get_fix_recommendation(vulnerability, issue)
            }
            findings.append(finding)

        # Check for Insecure Session Management
        session_issues = check_for_insecure_session_management(code)
        for issue in session_issues:
            code_snippet = "N/A"
            vulnerability = "Insecure Session Management"
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
                console.print(f"[bold red][Error] {path} is not a .cbl file.[/bold red]")
    else:
        if not quiet:
            console.print(f"[bold red][Error] {path} is not a valid file or directory.[/bold red]")

    return findings

def export_results(results, output, format, quiet=False):
    """Export the scan results to the specified format (JSON/SARIF)."""
    if not results:
        if not quiet:
            console.print("[bold yellow][Warning] No results to export.[/bold yellow]")
        return

    if format == "json":
        try:
            with open(output, "w") as json_file:
                json.dump(results, json_file, indent=4)
            if not quiet:
                console.print(f"[bold blue][Info] Results exported to {output} in JSON format.[/bold blue]")
        except IOError as e:
            console.print(f"[bold red][Error] Failed to write JSON file: {str(e)}[/bold red]")

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
                console.print(f"[bold blue][Info] Results exported to {output} in SARIF format.[/bold blue]")
        except IOError as e:
            console.print(f"[bold red][Error] Failed to write SARIF file: {str(e)}[/bold red]")

if __name__ == "__main__":
    cli()