import os
import click
from cobra.scanner import scan_directory
from cobra.cve_checker import fetch_cves, load_cached_cves
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
def scan(path, output, format):
    """Scan COBOL files in the provided directory for CVEs and vulnerabilities."""
    cves = load_cached_cves()

    # Collect CVE results
    results = scan_directory(path, cves)

    # Collect vulnerability results
    vulnerability_results = scan_vulnerabilities(path)

    # If there are vulnerabilities, add them to the results
    if vulnerability_results:
        results += vulnerability_results
        click.echo(f"[Info] Found vulnerabilities: {len(vulnerability_results)}")
    else:
        click.echo("[Info] No vulnerabilities found.")

    # Check if output file exists and warn user
    if output:
        if os.path.exists(output):
            click.echo(f"[Warning] {output} already exists and will be overwritten.")
        else:
            click.echo(f"[Info] Creating new file: {output}")

        # Export results to the requested format
        from cobra.exporter import export_results
        export_results(results, output, format)

        # Inform the user that the file has been saved and where
        click.echo(f"[Success] Results have been saved to: {os.path.abspath(output)}")

@cli.command()
def update_cve_db():
    """Update the local CVE cache."""
    fetch_cves()
    click.echo("CVE database updated.")

def scan_vulnerabilities(path):
    """Check COBOL files for common vulnerabilities."""
    findings = []  # This will collect the vulnerability results

    def analyze_file(file_path):
        filename = os.path.basename(file_path)
        with open(file_path, "r", errors="ignore") as file:
            cobol_code = file.read()

        # Check for XSS vulnerabilities
        xss_issues = check_for_xss(cobol_code)
        if xss_issues:
            findings.append(f"[{filename}] Potential XSS Vulnerabilities:")
            for issue in xss_issues:
                findings.append(f"- {issue}")
            click.echo(f"XSS vulnerabilities found in {filename}: {xss_issues}")

        # Check for SQL Injection vulnerabilities
        sql_issues = check_for_sql_injection(cobol_code)
        if sql_issues:
            findings.append(f"[{filename}] Potential SQL Injection Vulnerabilities:")
            for issue in sql_issues:
                findings.append(f"- {issue}")
            click.echo(f"SQL Injection vulnerabilities found in {filename}: {sql_issues}")

        # Check for Command Injection vulnerabilities
        command_issues = check_for_command_injection(cobol_code)
        if command_issues:
            findings.append(f"[{filename}] Potential Command Injection Vulnerabilities:")
            for issue in command_issues:
                findings.append(f"- {issue}")
            click.echo(f"Command Injection vulnerabilities found in {filename}: {command_issues}")

        # Check for Insecure Cryptographic Storage vulnerabilities
        cryptographic_issues = check_for_insecure_cryptographic_storage(cobol_code)
        if cryptographic_issues:
            findings.append(f"[{filename}] Potential Insecure Cryptographic Storage Issues:")
            for issue in cryptographic_issues:
                findings.append(f"- {issue}")
            click.echo(f"Insecure Cryptographic Storage issues found in {filename}: {cryptographic_issues}")

        # Check for CSRF vulnerabilities
        csrf_issues = check_for_csrf(cobol_code)
        if csrf_issues:
            findings.append(f"[{filename}] Potential CSRF Vulnerabilities:")
            for issue in csrf_issues:
                findings.append(f"- {issue}")
            click.echo(f"CSRF vulnerabilities found in {filename}: {csrf_issues}")

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
            click.echo(f"[Error] {path} is not a .cbl file.")
    else:
        click.echo(f"[Error] {path} is not a valid file or directory.")

    # Return the collected findings
    if findings:
        click.echo(f"[Info] Collected {len(findings)} findings.")
    else:
        click.echo("[Info] No vulnerabilities found.")

    return findings

if __name__ == "__main__":
    cli()
