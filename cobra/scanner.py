import os
import logging
import uuid
from cobra.rules import run_rules
from cobra.utils import is_cobol_file
from rich.console import Console

# Configure logging
logging.basicConfig(level=logging.DEBUG, filename="cobra.log", format="%(asctime)s - %(levelname)s - %(message)s")

console = Console()

def deduplicate_findings(findings):
    """Remove duplicate findings based on file, message, and line."""
    seen = set()
    unique_findings = []
    for f in findings:
        key = (f["file"], f["message"], f["line"])
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)
    return unique_findings

def scan_directory(path, cves):
    """Scan COBOL files in the provided directory for CVEs and vulnerabilities."""
    results = []
    logging.debug(f"Starting scan_directory for path: {path}")

    # Handle file input
    if os.path.isfile(path):
        if is_cobol_file(path):
            try:
                with open(path, "r", errors="ignore") as f:
                    code = f.read()
                findings = run_rules(code, path, cves)
                # Add UID to each finding
                for finding in findings:
                    finding["uid"] = str(uuid.uuid4())
                results.extend(findings)
                logging.debug(f"Found {len(findings)} issues in file: {path}")
            except Exception as e:
                console.print(f"[red]Error reading file {path}: {e}[/red]")
                logging.error(f"Error reading file {path}: {e}")
        else:
            console.print(f"[red]Error: {path} is not a valid COBOL file![/red]")
            logging.warning(f"Invalid COBOL file: {path}")
            return results

    # Handle directory input
    elif os.path.isdir(path):
        for root, _, files in os.walk(path):
            for file in files:
                if is_cobol_file(file):
                    full_path = os.path.join(root, file)
                    try:
                        with open(full_path, "r", errors="ignore") as f:
                            code = f.read()
                        findings = run_rules(code, full_path, cves)
                        # Add UID to each finding
                        for finding in findings:
                            finding["uid"] = str(uuid.uuid4())
                        results.extend(findings)
                        logging.debug(f"Found {len(findings)} issues in file: {full_path}")
                    except Exception as e:
                        console.print(f"[red]Error reading file {full_path}: {e}[/red]")
                        logging.error(f"Error reading file {full_path}: {e}")

    # Invalid path
    else:
        console.print(f"[red]Error: {path} is neither a valid file nor a directory![/red]")
        logging.warning(f"Invalid path: {path}")
        return results

    # Deduplicate findings
    results = deduplicate_findings(results)

    # Output results
    if not results:
        console.print("[green]cobra found no vulnerabilities![/green]")
        logging.debug("No vulnerabilities found")
    else:
        console.print(f"[bold red]cobra found {len(results)} issues:[/bold red]")
        for finding in results:
            console.print(
                f"[red]{finding['severity'].upper()}[/red] - {finding['file']} (line {finding['line']}): {finding messaggio: [cyan](UID: {finding['uid']})[/cyan]"
            )
        logging.debug(f"Total issues found: {len(results)}")

    return results