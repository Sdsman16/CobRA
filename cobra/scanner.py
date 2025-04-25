import os
import logging
import hashlib
from cobra.rules import run_rules
from cobra.utils import is_cobol_file
from rich.console import Console

# Configure logging
logging.basicConfig(level=logging.DEBUG, filename="cobra.log", format="%(asctime)s - %(levelname)s - %(message)s")

console = Console()

def generate_uid(file_path, vulnerability, line_number, code_snippet):
    """Generate a deterministic UID based on file, vulnerability, and code snippet."""
    # Use relative path to handle directory moves
    relative_path = os.path.relpath(file_path, os.getcwd())
    # Combine attributes into a stable string
    uid_string = f"{relative_path}:{vulnerability}:{line_number}:{code_snippet}"
    # Generate SHA-256 hash
    return hashlib.sha256(uid_string.encode()).hexdigest()

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

    def analyze_file(file_path):
        try:
            with open(file_path, "r", errors="ignore") as f:
                lines = f.readlines()
            code = "".join(lines)
            findings = run_rules(code, file_path, cves)
            # Add UID and code snippet to each finding
            for finding in findings:
                line_number = finding["line"]
                # Get code snippet (current line ±1 for context)
                start_line = max(0, line_number - 2)  # 1-based to 0-based
                end_line = min(len(lines), line_number + 1)
                code_snippet = "".join(lines[start_line:end_line]).strip()
                finding["uid"] = generate_uid(
                    file_path, finding["vulnerability"], line_number, code_snippet
                )
                finding["code_snippet"] = code_snippet
                # Ensure consistent keys
                if "message" not in finding:
                    finding["message"] = finding.get("description", "No description")
                if "vulnerability" not in finding:
                    finding["vulnerability"] = finding.get("id", "Unknown")
            results.extend(findings)
            logging.debug(f"Found {len(findings)} issues in file: {file_path}")
        except Exception as e:
            console.print(f"[red]Error reading file {file_path}: {e}[/red]")
            logging.error(f"Error reading file {file_path}: {e}")

    # Handle file input
    if os.path.isfile(path):
        if is_cobol_file(path):
            analyze_file(path)
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
                    analyze_file(full_path)

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
                f"[red]{finding['severity'].upper()}[/red] - {finding['file']} (line {finding['line']}): {finding['message']} [cyan](UID: {finding['uid'][:8]}...)[/cyan]"
            )
        logging.debug(f"Total issues found: {len(results)}")

    return results