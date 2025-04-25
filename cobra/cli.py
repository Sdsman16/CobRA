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
def scan(path):
    """Scan COBOL files in the provided directory for CVEs and vulnerabilities."""
    # Load the CVE data
    cves = load_cached_cves()

    # Scan the file or directory for CVE vulnerabilities
    scan_directory(path, cves)

    # Check for additional vulnerabilities
    scan_vulnerabilities(path)

@cli.command()
def update_cve_db():
    """Update the local CVE cache."""
    fetch_cves()
    click.echo("CVE database updated.")

def scan_vulnerabilities(path):
    """Check COBOL files for common vulnerabilities."""

    def analyze_file(file_path):
        filename = os.path.basename(file_path)
        with open(file_path, "r", errors="ignore") as file:
            cobol_code = file.read()

        # Check for XSS vulnerabilities
        xss_issues = check_for_xss(cobol_code)
        if xss_issues:
            print(f"[{filename}] Potential XSS Vulnerabilities:")
            for issue in xss_issues:
                print(f"- {issue}")

        # Check for SQL Injection vulnerabilities
        sql_issues = check_for_sql_injection(cobol_code)
        if sql_issues:
            print(f"[{filename}] Potential SQL Injection Vulnerabilities:")
            for issue in sql_issues:
                print(f"- {issue}")

        # Check for Command Injection vulnerabilities
        command_issues = check_for_command_injection(cobol_code)
        if command_issues:
            print(f"[{filename}] Potential Command Injection Vulnerabilities:")
            for issue in command_issues:
                print(f"- {issue}")

        # Check for Insecure Cryptographic Storage vulnerabilities
        cryptographic_issues = check_for_insecure_cryptographic_storage(cobol_code)
        if cryptographic_issues:
            print(f"[{filename}] Potential Insecure Cryptographic Storage Issues:")
            for issue in cryptographic_issues:
                print(f"- {issue}")

        # Check for CSRF vulnerabilities
        csrf_issues = check_for_csrf(cobol_code)
        if csrf_issues:
            print(f"[{filename}] Potential CSRF Vulnerabilities:")
            for issue in csrf_issues:
                print(f"- {issue}")

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
            print(f"[Error] {path} is not a .cbl file.")
    else:
        print(f"[Error] {path} is not a valid file or directory.")
