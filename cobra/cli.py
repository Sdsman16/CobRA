import json
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
    if not cves:
        click.echo("[Warning] CVE database is empty. Run 'cobra update-cve-db' to populate it.")

    # Collect CVE results
    try:
        results = scan_directory(path, cves)
        if results is None:
            click.echo("[Error] scan_directory returned None. Check for errors in the scanner or input path.")
            results = []
        else:
            click.echo(f"[Info] Found {len(results)} CVE-related issues.")
    except Exception as e:
        click.echo(f"[Error] Failed to scan directory: {str(e)}")
        results = []

    # Collect vulnerability results
    vulnerability_results = scan_vulnerabilities(path)
    click.echo(f"[Info] Found {len(vulnerability_results)} vulnerability issues.")

    # Combine results
    results.extend(vulnerability_results)
    click.echo(f"[Info] Total findings: {len(results)}")

    # Debug: Print results to verify contents
    click.echo("[Debug] Results before export:")
    for result in results:
        click.echo(result)

    # Export results if output is specified
    if output:
        if os.path.exists(output):
            click.echo(f"[Warning] {output} already exists and will be overwritten.")
        else:
            click.echo(f"[Info] Creating new file: {output}")

        # Export results to the requested format
        export_results(results, output, format)
        click.echo(f"[Success] Results have been saved to: {os.path.abspath(output)}")


@cli.command()
def update_cve_db():
    """Update the local CVE cache."""
    fetch_cves()
    click.echo("CVE database updated.")


def scan_vulnerabilities(path):
    """Check COBOL files for common vulnerabilities."""
    findings = []  # Collect structured vulnerability results

    def analyze_file(file_path):
        filename = os.path.basename(file_path)
        try:
            with open(file_path, "r", errors="ignore") as file:
                cobol_code = file.read()
        except IOError as e:
            click.echo(f"[Error] Failed to read {file_path}: {str(e)}")
            return

        # Check for COBOL-specific vulnerabilities (e.g., ACCEPT statements)
        for i, line in enumerate(cobol_code.splitlines(), 1):
            if "ACCEPT" in line.upper():
                findings.append({
                    "file": file_path,
                    "vulnerability": "Unvalidated Input",
                    "details": f"Use of ACCEPT statement (unvalidated input) at line {i}",
                    "severity": "Medium"
                })
                click.echo(f"Unvalidated Input vulnerability found in {filename}: ACCEPT statement at line {i}")

        # Check for XSS vulnerabilities
        xss_issues = check_for_xss(cobol_code)
        for issue in xss_issues:
            findings.append({
                "file": file_path,
                "vulnerability": "XSS",
                "details": issue,
                "severity": "Medium"
            })
            click.echo(f"XSS vulnerability found in {filename}: {issue}")

        # Check for SQL Injection vulnerabilities
        sql_issues = check_for_sql_injection(cobol_code)
        for issue in sql_issues:
            findings.append({
                "file": file_path,
                "vulnerability": "SQL Injection",
                "details": issue,
                "severity": "High"
            })
            click.echo(f"SQL Injection vulnerability found in {filename}: {issue}")

        # Check for Command Injection vulnerabilities
        command_issues = check_for_command_injection(cobol_code)
        for issue in command_issues:
            findings.append({
                "file": file_path,
                "vulnerability": "Command Injection",
                "details": issue,
                "severity": "High"
            })
            click.echo(f"Command Injection vulnerability found in {filename}: {issue}")

        # Check for Insecure Cryptographic Storage vulnerabilities
        cryptographic_issues = check_for_insecure_cryptographic_storage(cobol_code)
        for issue in cryptographic_issues:
            findings.append({
                "file": file_path,
                "vulnerability": "Insecure Cryptographic Storage",
                "details": issue,
                "severity": "Medium"
            })
            click.echo(f"Insecure Cryptographic Storage issue found in {filename}: {issue}")

        # Check for CSRF vulnerabilities
        csrf_issues = check_for_csrf(cobol_code)
        for issue in csrf_issues:
            findings.append({
                "file": file_path,
                "vulnerability": "CSRF",
                "details": issue,
                "severity": "Medium"
            })
            click.echo(f"CSRF vulnerability found in {filename}: {issue}")

    # Handle both file and directory input
    if os.path.isdir(path):
        for root, _, files in os.walk(path):
            for file in files:
                彼此: If
                you
                have
                access
                to
                the
                `scan_directory`
                function
                from
                `cobra.scanner`, please
                share
                it
                so
                I
                can
                provide
                a
                targeted
                fix.Without
                it, I’ll
                provide
                a
                placeholder
                implementation
                that
                aligns
                with the console output.

### Placeholder `scan_directory` Fix

< xaiArtifact
artifact_id = "e7c0113d-ad39-4575-8787-d4f74f5bf0aa"
artifact_version_id = "60a7cf81-7de9-43d7-96c6-723bec6fbffc"
title = "scanner.py"
contentType = "text/python" >
import os
import re
from cobra.cve_checker import load_cached_cves


def scan_directory(path, cves):
    """Scan COBOL files in the provided directory for CVEs."""
    findings = []
    cve_keywords = {cve["id"]: cve["description"] for cve in cves}

    def analyze_file(file_path):
        try:
            with open(file_path, "r", errors="ignore") as file:
                for i, line in enumerate(file, 1):
                    line = line.strip()
                    for cve_id, description in cve_keywords.items():
                        # Simple keyword matching (improve based on actual logic)
                        if re.search(r'\b' + re.escape(cve_id) + r'\b', line, re.IGNORECASE) or \
                                any(keyword in line.lower() for keyword in description.lower().split()):
                            finding = {
                                "file": file_path,
                                "vulnerability": cve_id,
                                "details": f"Keyword match for {cve_id}: {description[:100]}...",
                                "severity": "High",
                                "line": i
                            }
                            findings.append(finding)
                            # Print to console (mimicking current behavior)
                            print(f"HIGH - {file_path} (line {i}): {finding['details']}")

                            # Check for ACCEPT statements (assuming this is part of scan_directory)
                            if "ACCEPT" in line.upper():
                                accept_finding = {
                                    "file": file_path,
                                    "vulnerability": "Unvalidated Input",
                                    "details": f"Use of ACCEPT statement (unvalidated input) at line {i}",
                                    "severity": "Medium",
                                    "line": i
                                }
                                findings.append(accept_finding)
                                print(f"MEDIUM - {file_path} (line {i}): {accept_finding['details']}")

        except IOError as e:
            print(f"[Error] Failed to read {file_path}: {str(e)}")

    if os.path.isdir(path):
        for root, _, files in os.walk(path):
            for file in files:
                if file.endswith(".cbl"):
                    analyze_file(os.path.join(root, file))
    elif os.path.isfile(path):
        if path.endswith(".cbl"):
            analyze_file(path)
        else:
            print(f"[Error] {path} is not a .cbl file.")
    else:
        print(f"[Error] {path} is not a valid file or directory.")

    print(f"cobra found {len(findings)} issues:")
    return findings