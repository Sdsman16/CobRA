import os
import logging
import re
from cobra.rules import run_rules
from cobra.utils import is_cobol_file, generate_uid
from rich.console import Console
from concurrent.futures import ThreadPoolExecutor, as_completed

# Configure logging
logging.basicConfig(level=logging.DEBUG, filename="cobra.log", format="%(asctime)s - %(levelname)s - %(message)s")

console = Console()

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

def deduplicate_findings(findings):
    """Remove duplicate findings based on file, message, line, and vulnerability."""
    seen = set()
    unique_findings = []
    for f in findings:
        key = (f["file"], f["message"], f["line"], f["vulnerability"])
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)
    return unique_findings

def scan_directory(path, cves, quiet=False, severity=None, severity_and_lower=None):
    """Scan COBOL files in the provided directory for CVEs and vulnerabilities using parallel scanning."""
    results = []
    logging.debug(f"Starting scan_directory for path: {path}")

    def analyze_file(file_path):
        local_results = []
        try:
            with open(file_path, "r", errors="ignore") as f:
                lines = f.readlines()
            code = "".join(lines)
            findings = run_rules(code, file_path, cves)
            logging.debug(f"run_rules output for {file_path}: {findings}")
            for finding in findings:
                line_number = finding["line"]
                start_line = max(0, line_number - 2)
                end_line = min(len(lines), line_number + 1)
                code_snippet = "".join(lines[start_line:end_line]).strip()
                vulnerability = finding.get("vulnerability")
                if not vulnerability:
                    message = finding.get("message", "")
                    cve_match = re.search(r"CVE-\d{4}-\d{4,}", message)
                    vulnerability = cve_match.group(0) if cve_match else "Unknown"
                finding["vulnerability"] = vulnerability
                finding["message"] = finding.get("message", "No description")
                finding["severity"] = finding.get("severity", "Medium").capitalize()
                finding["uid"] = generate_uid(file_path, vulnerability, line_number, code_snippet)
                finding["code_snippet"] = code_snippet
                finding["cvss_score"] = finding.get("cvss_score", 0.0)
                # Add fix recommendation
                finding["fix"] = get_fix_recommendation(vulnerability, finding["message"])
                local_results.append(finding)
            logging.debug(f"Found {len(findings)} issues in file: {file_path}")
        except Exception as e:
            if not quiet:
                console.print(f"[red]Error reading file {file_path}: {e}[/red]")
            logging.error(f"Error reading file {file_path}: {e}")
        return local_results

    file_paths = []
    if os.path.isfile(path):
        if is_cobol_file(path):
            file_paths.append(path)
        else:
            if not quiet:
                console.print(f"[red]Error: {path} is not a valid COBOL file![/red]")
            logging.warning(f"Invalid COBOL file: {path}")
            return results
    elif os.path.isdir(path):
        for root, _, files in os.walk(path):
            for file in files:
                if is_cobol_file(file):
                    file_paths.append(os.path.join(root, file))
    else:
        if not quiet:
            console.print(f"[red]Error: {path} is neither a valid file nor a directory![/red]")
        logging.warning(f"Invalid path: {path}")
        return results

    # Parallel scanning
    with ThreadPoolExecutor() as executor:
        futures = {executor.submit(analyze_file, fp): fp for fp in file_paths}
        for future in as_completed(futures):
            findings = future.result()
            results.extend(findings)

    # Deduplicate findings
    results = deduplicate_findings(results)

    # Apply severity filter
    if severity is not None or severity_and_lower is not None:
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
        results = filtered_results

    from collections import defaultdict

    if not quiet:
        if not results:
            console.print("[green]cobra found no vulnerabilities![/green]")
        else:
            console.print(f"[bold red]cobra found {len(results)} issues grouped by file:[/bold red]")
            findings_by_file = defaultdict(list)
            for finding in results:
                findings_by_file[finding["file"]].append(finding)

            for file, findings in findings_by_file.items():
                console.print(f"\n[bold underline]{file}[/bold underline]")
                for finding in findings:
                    severity = finding["severity"].capitalize()
                    if severity == "High":
                        color = "red"
                    elif severity == "Medium":
                        color = "yellow"
                    else:
                        color = "white"
                    console.print(
                        f"  [{color}]{severity.upper()}[/{color}] (line {finding['line']}): {finding['message']} "
                        f"[cyan](UID: {finding['uid'][:8]}..., CVSS: {finding['cvss_score']})[/cyan]"
                    )
                    console.print(f"    [bold green]Fix:[/bold green] {finding['fix']}")

    logging.debug(f"Total issues found: {len(results)}")
    return results