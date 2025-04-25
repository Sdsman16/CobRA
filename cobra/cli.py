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

    console