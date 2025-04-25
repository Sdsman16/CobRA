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

    # Collect results
    results = scan_directory(path, cves) or []
    results += scan_vulnerabilities(path)

    # Export if requested
    if output and format:
        from cobra.exporter import export_results
        export_results(results, output, format)

@cli.command()
def update_cve_db():
    """Update the local CVE cache."""
    fetch_cves()
    click.echo("CVE database updated.")

def scan_vulnerabilities(path):
    """Check COBOL files for common vulnerabilities."""
    findings = []

    def analyze_file(file_path):
        filename = os.path.basename(file_path)
        with open(file_path, "r", errors="ignore") as file:
            cobol_code = file.read()

        checks = [
            ("xss", "XSS", check_for_xss),
            ("sql_injection", "SQL Injection", check_for_sql_injection),
            ("command_injection", "Command Injection", check_for_command_injection),
            ("crypto", "Insecure Cryptographic Storage", check_for_insecure_cryptographic_storage),
            ("csrf", "CSRF", check_for_csrf)
        ]

        for vuln_type, description, func in checks:
            issues = func(cobol_code)
            if issues:
                print(f"[{filename}] Potential {description} Vulnerabilities:")
                for issue in issues:
                    print(f"- {issue}")
                    findings.append({
                        "file": file_path,
                        "line": 1,  # You can improve this if you want to locate actual line
                        "message": issue,
                        "severity": "HIGH",  # Default, or improve with detection logic
                        "type": vuln_type
                    })

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

    return findings
