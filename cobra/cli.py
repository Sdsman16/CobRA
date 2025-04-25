import click
from cobra.scanner import scan_directory
from cobra.cve_checker import fetch_cves, load_cached_cves

@click.group()
def cli():
    """cobra - COBOL Risk Analyzer"""
    pass

@cli.command()
@click.argument("path")
def scan(path):
    """Scan COBOL files in the provided directory."""
    cves = load_cached_cves()
    scan_directory(path, cves)

@cli.command()
def update_cve_db():
    """Update the local CVE cache."""
    fetch_cves()
    click.echo("CVE database updated.")
