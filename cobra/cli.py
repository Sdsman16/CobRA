import json
import os
import click
import logging
import sys
import re
import hashlib
from multiprocessing import Pool
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
    check_for_buffer_overflows,
    check_for_insecure_data_transmission,
    check_for_improper_error_handling,
    check_for_insecure_session_management
)
from rich.console import Console

# Configure logging
logging.basicConfig(level=logging.DEBUG, filename="cobra.log", format="%(asctime)s - %(levelname)s - %(message)s")

console = Console()

# Cache for incremental scanning
FILE_HASH_CACHE = "file_hashes.json"


@click.group()
def cli():
    """cobra - COBOL Risk Analyzer"""
    pass


def get_fix_recommendation(vulnerability, message):
    """Return a fix recommendation based on the vulnerability type with COBOL examples."""
    fixes = {
        "CVE-": {
            "buffer overflow": (
                "Implement bounds checking on array accesses and use safe COBOL constructs like INSPECT to validate data lengths.",
                ""
            ),
            "default": (
                "Review the CVE description for specific mitigation steps and update COBOL runtime or compiler settings accordingly.",
                ""
            )
        },
        "Unvalidated Input": (
            "Validate and sanitize user input before using ACCEPT; consider using a validation routine or restricting input length.",
            """
            PROCEDURE DIVISION.
                ACCEPT USER-INPUT
                IF USER-INPUT NOT MATCHES "[A-Z0-9]+" THEN
                    DISPLAY "Invalid input"
                    STOP RUN
                END-IF
            """
        ),
        "XSS": (
            "Sanitize user input and escape output in COBOL DISPLAY statements to prevent script injection.",
            """
            PROCEDURE DIVISION.
                MOVE FUNCTION UPPER-CASE(USER-INPUT) TO SANITIZED-INPUT
                INSPECT SANITIZED-INPUT REPLACING ALL "<" BY "<"
                DISPLAY SANITIZED-INPUT
            """
        ),
        "SQL Injection": (
            "Use parameterized queries or EXEC SQL PREPARE for database operations in COBOL to prevent injection.",
            """
            EXEC SQL
                PREPARE STMT FROM "SELECT * FROM TABLE WHERE ID = ?"
            END-EXEC
            EXEC SQL
                EXECUTE STMT USING :USER-ID
            END-EXEC
            """
        ),
        "Command Injection": {
            "Severity: High": (
                "User input detected in CALL statement with injection patterns; strictly validate and sanitize input to prevent command injection (e.g., reject '&', '|', ';' sequences).",
                """
                PROCEDURE DIVISION.
                    ACCEPT PROG-NAME
                    INSPECT PROG-NAME REPLACING ALL "&" BY " "
                    INSPECT PROG-NAME REPLACING ALL "|" BY " "
                    IF PROG-NAME NOT MATCHES "[A-Z0-9]+" THEN
                        DISPLAY "Invalid program name"
                        STOP RUN
                    END-IF
                    CALL PROG-NAME
                """
            ),
            "Severity: Medium": (
                "User input detected in CALL statement; validate inputs strictly or use static CALLs to prevent potential command injection.",
                """
                PROCEDURE DIVISION.
                    ACCEPT PROG-NAME
                    IF PROG-NAME NOT MATCHES "[A-Z0-9]+" THEN
                        DISPLAY "Invalid program name"
                        STOP RUN
                    END-IF
                    CALL PROG-NAME
                """
            ),
            "default": (
                "Avoid dynamic CALL statements with variables that could be manipulated; use static CALLs or validate inputs.",
                """
                PROCEDURE DIVISION.
                    CALL "SAFE-PROGRAM"
                """
            )
        },
        "Insecure Cryptographic Storage": (
            "Use secure COBOL libraries for encryption (e.g., COBOL SSL extensions) and avoid hardcoded keys.",
            """
            PROCEDURE DIVISION.
                MOVE FUNCTION ENCRYPT(PASSWORD, "AES256") TO ENCRYPTED-PASS
            """
        ),
        "CSRF": (
            "Implement CSRF tokens in COBOL web interactions and validate requests on the server side.",
            """
            EXEC CICS WEB
                SEND TOKEN(CSRF-TOKEN)
            END-EXEC
            """
        ),
        "File Traversal": {
            "Severity: High": (
                "User input detected in file name; strictly validate and sanitize input to prevent path traversal (e.g., reject '../' sequences).",
                """
                PROCEDURE DIVISION.
                    ACCEPT FILE-NAME
                    INSPECT FILE-NAME REPLACING ALL "../" BY " "
                    IF FILE-NAME NOT MATCHES "[A-Z0-9]+" THEN
                        DISPLAY "Invalid file name"
                        STOP RUN
                    END-IF
                    SELECT MY-FILE ASSIGN TO FILE-NAME
                """
            ),
            "default": (
                "Validate file names in SELECT statements and avoid using user input directly in file paths.",
                """
                PROCEDURE DIVISION.
                    MOVE "SAFEFILE" TO FILE-NAME
                    SELECT MY-FILE ASSIGN TO FILE-NAME
                """
            )
        },
        "Resource Exhaustion": (
            "Ensure all opened files are properly closed using CLOSE statements to prevent resource leaks.",
            """
            PROCEDURE DIVISION.
                OPEN INPUT MY-FILE
                CLOSE MY-FILE
            """
        ),
        "Hardcoded Sensitive Data": (
            "Remove hardcoded sensitive data; use environment variables or a secure vault to store credentials and keys.",
            """
            PROCEDURE DIVISION.
                CALL "GET-ENV" USING "DB_PASSWORD" RETURNING DB-PASS
            """
        ),
        "Arithmetic Overflow": (
            "Add ON SIZE ERROR clause to arithmetic operations to handle overflows gracefully.",
            """
            PROCEDURE DIVISION.
                COMPUTE RESULT = A + B
                ON SIZE ERROR
                    DISPLAY "Arithmetic overflow detected"
                END-COMPUTE
            """
        ),
        "Divide-by-Zero": (
            "Add a check for zero divisor before DIVIDE statements to prevent crashes.",
            """
            PROCEDURE DIVISION.
                IF DIVISOR NOT = 0
                    DIVIDE NUM BY DIVISOR GIVING RESULT
                ELSE
                    DISPLAY "Divide by zero error"
                END-IF
            """
        ),
        "Buffer Overflow": (
            "Add ON OVERFLOW clause to STRING/UNSTRING operations to handle buffer overflows.",
            """
            PROCEDURE DIVISION.
                STRING A DELIMITED BY SIZE
                       B DELIMITED BY SIZE
                INTO RESULT
                ON OVERFLOW
                    DISPLAY "Buffer overflow in STRING operation"
                END-STRING
            """
        ),
        "Insecure Data Transmission": (
            "Use secure communication protocols like HTTPS or SSL/TLS for data transmission.",
            """
            EXEC CICS WEB
                SEND HTTPS
            END-EXEC
            """
        ),
        "Improper Error Handling": (
            "Add ON ERROR or AT END clauses to handle errors properly and avoid displaying sensitive information.",
            """
            PROCEDURE DIVISION.
                READ MY-FILE
                    AT END
                        DISPLAY "End of file reached"
                    ON ERROR
                        DISPLAY "Error reading file"
                END-READ
            """
        ),
        "Insecure Session Management": (
            "Use secure, unique session tokens and regenerate them on login/logout to prevent session hijacking.",
            """
            PROCEDURE DIVISION.
                MOVE FUNCTION GENERATE-UUID TO SESSION-TOKEN
            """
        ),
        "Format String Vulnerability": (
            "Sanitize user input in DISPLAY statements to prevent format string vulnerabilities.",
            """
            PROCEDURE DIVISION.
                ACCEPT USER-INPUT
                INSPECT USER-INPUT REPLACING ALL "%" BY " "
                DISPLAY USER-INPUT
            """
        ),
        "Insecure Dependency": (
            "Avoid calling known vulnerable programs; update or replace the dependency.",
            """
            PROCEDURE DIVISION.
                CALL "SAFE-PROGRAM"
            """
        ),
        "Custom Rule Violation": (
            "Review the custom rule definition and apply the recommended fix.",
            ""
        )
    }

    fix_dict = fixes.get(vulnerability, {
        "default": ("Review COBOL best practices for secure coding and apply input validation or runtime checks.", "")})

    if isinstance(fix_dict, dict):
        for key, (fix, example) in fix_dict.items():
            if key in message or key == "default":
                return fix, example
        return fix_dict.get("default",
                            ("Review COBOL best practices for secure coding and apply input validation or runtime checks.",
                             ""))

    return fix_dict[0], fix_dict[1]


def filter_by_severity(results, severity=None, severity_and_lower=None):
    """Filter findings based on severity threshold or severity and lower."""
    if severity is None and severity_and_lower is None:
        return results

    severity_levels = {"high": 3, "medium": 2, "low": 1}

    filtered_results = []
    for result in results:
        result_severity = result["severity"].lower()
        result_level = severity_levels.get(result_severity, 0)

        if severity is not None:
            if result_severity == severity.lower():
                filtered_results.append(result)
        elif severity_and_lower is not None:
            threshold_level = severity_levels.get(severity_and_lower.lower(), 0)
            if result_level <= threshold_level and result_level > 0:
                filtered_results.append(result)

    return filtered_results


def load_ignored_uids():
    """Load the dictionary of ignored findings from ignore.json."""
    try:
        if not os.path.exists("ignore.json"):
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
        console.print(
            f"[bold yellow][Warning] Failed to load ignore.json: {str(e)}. Initializing empty ignore list.[/bold yellow]")
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
        console.print(
            f"[bold yellow][Warning] Delta results file {delta_path} does not exist. Treating all findings as new.[/bold yellow]")
        return current_results

    try:
        with open(delta_path, "r") as f:
            previous_results = json.load(f)
    except (IOError, json.JSONDecodeError) as e:
        console.print(
            f"[bold red][Error] Failed to load delta results from {delta_path}: {str(e)}. Treating all findings as new.[/bold red]")
        return current_results

    previous_uids = {result["uid"] for result in previous_results}
    new_vulnerabilities = [result for result in current_results if result["uid"] not in previous_uids]

    if new_vulnerabilities and not previous_results:
        console.print(
            f"[bold yellow][Info] No previous vulnerabilities found in {delta_path}. All {len(new_vulnerabilities)} vulnerabilities are considered new.[/bold yellow]")
    elif new_vulnerabilities:
        console.print(
            f"[bold yellow][Info] Found {len(new_vulnerabilities)} net new vulnerabilities compared to previous scan.[/bold yellow]")
        for vuln in new_vulnerabilities:
            severity = vuln["severity"].capitalize()
            color = "red" if severity == "High" else "yellow" if severity == "Medium" else "white"
            console.print(
                f"  [{color}]{severity.upper()}[/{color}] (line {vuln['line']}): {vuln['message']} "
                f"[cyan](UID: {vuln['uid'][:8]}..., CVSS: {vuln['cvss_score']}, Exploitability: {vuln['exploitability_score']})[/cyan]"
            )
            console.print(f"    [bold green]Fix:[/bold green] {vuln['fix']}")
            if vuln['fix_example']:
                console.print(f"    [bold green]Example:[/bold green]\n{vuln['fix_example']}")
    else:
        console.print("[bold green][Info] No net new vulnerabilities found compared to previous scan.[/bold green]")

    return new_vulnerabilities


@cli.command()
@click.argument("directory")
@click.option("--output", type=click.Path(), help="Path to save results.")
@click.option("--format", type=click.Choice(["json", "sarif", "html"]), help="Export format.")
@click.option("--line-tolerance", type=int, default=10, help="Line number tolerance for matching ignored findings.")
@click.option("--quiet", is_flag=True, help="Suppress all non-critical console output during scan.")
@click.option("--verbose", is_flag=True, help="Show detailed debug logs of findings.")
@click.option("--no-update", is_flag=True, help="Skip automatic CVE database update.")
@click.option("--severity", type=click.Choice(["high", "medium", "low"], case_sensitive=False),
              help="Show only findings of the specified severity.")
@click.option("--severity-and-lower", type=click.Choice(["high", "medium", "low"], case_sensitive=False),
              help="Show findings of the specified severity and lower.")
@click.option("--delta", type=click.Path(exists=True),
              help="Path to previous scan results for delta comparison to identify net new vulnerabilities.")
@click.option("--custom-rules", type=click.Path(exists=True), help="Path to custom rules JSON file.")
@click.option("--custom-db", type=click.Path(exists=True), help="Path to custom vulnerability database JSON file.")
def scan(directory, output, format, line_tolerance, quiet, verbose, no_update, severity, severity_and_lower, delta,
         custom_rules, custom_db):
    """Scan COBOL files in the provided directory for CVEs and vulnerabilities."""
    if severity is not None and severity_and_lower is not None:
        raise click.UsageError("Options --severity and --severity-and-lower are mutually exclusive.")

    if not no_update and should_update_cves():
        if not quiet:
            console.print("[bold blue][Info] Updating CVE database...[/bold blue]")
        fetch_cves()
    cves = load_cached_cves(custom_db_path=custom_db)
    if not quiet and not cves:
        console.print(
            "[bold yellow][Warning] CVE database is empty. Run 'cobra update-cve-db' to populate it.[/bold yellow]")

    ignored_findings = load_ignored_uids()
    if not quiet and ignored_findings:
        console.print(f"[bold blue][Info] Loaded {len(ignored_findings)} ignored findings.[/bold blue]")

    if not quiet:
        console.print("[bold blue][Debug] Starting scan_directory[/bold blue]")
    try:
        results = scan_directory(directory, cves, quiet=quiet, severity=severity, severity_and_lower=severity_and_lower)
        if results is None:
            if not quiet:
                console.print(
                    "[bold red][Error] scan_directory returned None. Check for errors in the scanner or input path.[/bold red]")
            results = []
        else:
            if not quiet:
                console.print(
                    f"[bold blue][Info] Found {len(results)} CVE-related issues after severity filtering.[/bold blue]")
            if verbose:
                console.print("[bold blue][Debug] CVE results:[/bold blue]")
                for result in results:
                    console.print(result)
    except Exception as e:
        if not quiet:
            console.print(f"[bold red][Error] Failed to scan directory: {str(e)}[/bold red]")
        results = []

    if not quiet:
        console.print("[bold blue][Debug] Starting scan_vulnerabilities[/bold blue]")
    vulnerability_results = scan_vulnerabilities(directory, quiet=quiet, custom_rules=custom_rules)
    if not quiet:
        console.print(
            f"[bold blue][Info] Found {len(vulnerability_results)} vulnerability issues before severity filtering.[/bold blue]")
    if verbose:
        console.print("[bold blue][Debug] Vulnerability results:[/bold blue]")
        for result in vulnerability_results:
            console.print(result)

    results.extend(vulnerability_results)

    filtered_results = []
    unmatched_ignores = set(ignored_findings.keys())
    for result in results:
        uid = result["uid"]
        if uid in ignored_findings:
            ignored = ignored_findings[uid]
            line_diff = abs(result["line"] - ignored["line"])
            snippet_match = result["code_snippet"] == ignored["code_snippet"]
            if line_diff <= line_tolerance and snippet_match:
                unmatched_ignores.discard(uid)
                continue
        filtered_results.append(result)
    results = filtered_results

    if not quiet and unmatched_ignores:
        console.print(
            f"[bold yellow][Warning] {len(unmatched_ignores)} ignored findings no longer match any vulnerabilities. Run 'cobra ignore-list' to review.[/bold yellow]")

    total_before_filter = len(results)
    results = filter_by_severity(results, severity=severity, severity_and_lower=severity_and_lower)

    if not quiet:
        console.print(f"[bold blue][Info] Total findings before filtering: {total_before_filter}[/bold blue]")
        console.print(f"[bold blue][Info] Total findings after severity filtering: {len(results)}[/bold blue]")
    if verbose:
        console.print("[bold blue][Debug] Results before export:[/bold blue]")
        for result in results:
            console.print(result)

    new_vulnerabilities = []
    if delta:
        new_vulnerabilities = compare_results(results, delta)
        if new_vulnerabilities:
            console.print(
                f"[bold red][Error] Found {len(new_vulnerabilities)} net new vulnerabilities. Breaking the build.[/bold red]")
            sys.exit(1)

    if results and not delta:
        if severity is not None:
            console.print(
                f"[bold red][Error] Found {len(results)} vulnerabilities of severity '{severity.upper()}'. Breaking the build.[/bold red]")
            sys.exit(1)
        elif severity_and_lower is not None:
            console.print(
                f"[bold red][Error] Found {len(results)} vulnerabilities of severity '{severity_and_lower.upper()}' or lower. Breaking the build.[/bold red]")
            sys.exit(1)
        else:
            console.print(f"[bold red][Error] Found {len(results)} vulnerabilities. Breaking the build.[/bold red]")
            sys.exit(1)

    if output:
        if not quiet and os.path.exists(output):
            console.print(
                f"[bold yellow][Warning] {output} already exists even after filtering and will be overwritten.[/bold yellow]")
        elif not quiet:
            console.print(f"[bold blue][Info] Creating new file: {output}[/bold blue]")

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
        console.print(
            "[bold yellow][Warning] Pruning requires a scan to identify unmatched findings. Run 'cobra scan' to detect outdated ignores.[/bold yellow]")


@cli.command()
@click.argument("file_path")
def fix(file_path):
    """Automatically apply fixes to simple issues in a COBOL file."""
    if not os.path.isfile(file_path) or not file_path.endswith(".cbl"):
        console.print(f"[bold red][Error] {file_path} is not a valid .cbl file.[/bold red]")
        return

    try:
        with open(file_path, "r") as f:
            lines = f.readlines()
    except IOError as e:
        console.print(f"[bold red][Error] Failed to read {file_path}: {str(e)}[/bold red]")
        return

    fixed_lines = []
    for i, line in enumerate(lines):
        line_upper = line.upper().strip()
        # Fix arithmetic overflow by adding ON SIZE ERROR
        if any(op in line_upper for op in
               ["COMPUTE", "ADD", "SUBTRACT", "MULTIPLY", "DIVIDE"]) and "ON SIZE ERROR" not in line_upper:
            if "COMPUTE" in line_upper:
                fixed_lines.append(line.rstrip() + " ON SIZE ERROR DISPLAY 'Overflow Error'\n")
            else:
                fixed_lines.append(line.rstrip() + "\n")
                fixed_lines.append(" " * (len(line) - len(line.lstrip())) + "ON SIZE ERROR DISPLAY 'Overflow Error'\n")
        # Fix buffer overflow in STRING/UNSTRING
        elif ("STRING" in line_upper or "UNSTRING" in line_upper) and "ON OVERFLOW" not in line_upper:
            if "STRING" in line_upper:
                fixed_lines.append(line.rstrip() + " ON OVERFLOW DISPLAY 'Buffer Overflow Error'\n")
            else:
                fixed_lines.append(line.rstrip() + "\n")
                fixed_lines.append(
                    " " * (len(line) - len(line.lstrip())) + "ON OVERFLOW DISPLAY 'Buffer Overflow Error'\n")
        else:
            fixed_lines.append(line)

    try:
        with open(file_path + ".fixed", "w") as f:
            f.writelines(fixed_lines)
        console.print(f"[bold green][Success] Fixed file saved as {file_path}.fixed[/bold green]")
    except IOError as e:
        console.print(f"[bold red][Error] Failed to write fixed file: {str(e)}[/bold red]")


def check_custom_rules(code, rules_file):
    """Check for vulnerabilities defined in a custom rules file."""
    if not rules_file:
        return []
    try:
        with open(rules_file, "r") as f:
            rules = json.load(f)["rules"]
    except (IOError, json.JSONDecodeError) as e:
        console.print(f"[bold red][Error] Failed to load custom rules: {str(e)}[/bold red]")
        return []

    issues = []
    lines = code.split("\n")
    for i, line in enumerate(lines, 1):
        for rule in rules:
            if re.search(rule["pattern"], line.upper()):
                issues.append(f"Custom Rule Violation: {rule['message']} at line {i} (Severity: {rule['severity']})")
    return issues


def load_file_hashes():
    """Load cached file hashes for incremental scanning."""
    if os.path.exists(FILE_HASH_CACHE):
        with open(FILE_HASH_CACHE, "r") as f:
            return json.load(f)
    return {}


def save_file_hashes(hashes):
    """Save file hashes for incremental scanning."""
    with open(FILE_HASH_CACHE, "w") as f:
        json.dump(hashes, f, indent=4)


def compute_file_hash(file_path):
    """Compute the hash of a file's content."""
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def analyze_file(file_path, custom_rules=None):
    """Analyze a single COBOL file for vulnerabilities."""
    findings = []
    filename = os.path.basename(file_path)
    try:
        with open(file_path, "r", errors="ignore") as file:
            lines = file.readlines()
        code = "".join(lines)
    except IOError as e:
        console.print(f"[bold red][Error] Failed to read {file_path}: {str(e)}[/bold red]")
        return findings

    # Check for COBOL-specific vulnerabilities (e.g., ACCEPT statements)
    for i, line in enumerate(lines, 1):
        if "ACCEPT" in line.upper():
            code_snippet = "".join(lines[max(0, i - 2):min(len(lines), i + 1)]).strip()
            vulnerability = "Unvalidated Input"
            message = f"Use of ACCEPT statement (unvalidated input) at line {i}. Consider validating input length."
            fix, fix_example = get_fix_recommendation(vulnerability, message)
            exploitability_score = 5  # User input involved
            finding = {
                "file": file_path,
                "vulnerability": vulnerability,
                "message": message,
                "severity": "Medium",
                "line": i,
                "uid": generate_uid(file_path, vulnerability, i, code_snippet),
                "code_snippet": code_snippet,
                "fix": fix,
                "fix_example": fix_example,
                "cvss_score": 0.0,
                "exploitability_score": exploitability_score
            }
            findings.append(finding)

    # Check for XSS and Format String vulnerabilities
    xss_issues = check_for_xss(code)
    for issue in xss_issues:
        code_snippet = "N/A"
        vulnerability = "XSS" if "XSS" in issue else "Format String Vulnerability"
        fix, fix_example = get_fix_recommendation(vulnerability, issue)
        exploitability_score = 5 if "user-controlled" in issue else 3
        finding = {
            "file": file_path,
            "vulnerability": vulnerability,
            "message": issue,
            "severity": "Medium",
            "line": 0,
            "uid": generate_uid(file_path, vulnerability, 0, code_snippet),
            "code_snippet": code_snippet,
            "fix": fix,
            "fix_example": fix_example,
            "cvss_score": 0.0,
            "exploitability_score": exploitability_score
        }
        findings.append(finding)

    # Check for SQL Injection vulnerabilities
    sql_issues = check_for_sql_injection(code)
    for issue in sql_issues:
        code_snippet = "N/A"
        vulnerability = "SQL Injection"
        fix, fix_example = get_fix_recommendation(vulnerability, issue)
        exploitability_score = 7  # High impact
        finding = {
            "file": file_path,
            "vulnerability": vulnerability,
            "message": issue,
            "severity": "High",
            "line": 0,
            "uid": generate_uid(file_path, vulnerability, 0, code_snippet),
            "code_snippet": code_snippet,
            "fix": fix,
            "fix_example": fix_example,
            "cvss_score": 0.0,
            "exploitability_score": exploitability_score
        }
        findings.append(finding)

    # Check for Command Injection vulnerabilities
    command_issues = check_for_command_injection(code)
    for issue in command_issues:
        code_snippet = "N/A"
        vulnerability = "Command Injection" if "Command Injection" in issue else "Insecure Dependency"
        severity_match = re.search(r"Severity: (\w+)", issue)
        severity = severity_match.group(1) if severity_match else "Medium"
        fix, fix_example = get_fix_recommendation(vulnerability, issue)
        exploitability_score = 7 if "Severity: High" in issue else 5 if "Severity: Medium" in issue else 3
        finding = {
            "file": file_path,
            "vulnerability": vulnerability,
            "message": issue,
            "severity": severity,
            "line": 0,
            "uid": generate_uid(file_path, vulnerability, 0, code_snippet),
            "code_snippet": code_snippet,
            "fix": fix,
            "fix_example": fix_example,
            "cvss_score": 0.0,
            "exploitability_score": exploitability_score
        }
        findings.append(finding)

    # Check for Insecure Cryptographic Storage vulnerabilities
    cryptographic_issues = check_for_insecure_cryptographic_storage(code)
    for issue in cryptographic_issues:
        code_snippet = "N/A"
        vulnerability = "Insecure Cryptographic Storage"
        fix, fix_example = get_fix_recommendation(vulnerability, issue)
        exploitability_score = 4
        finding = {
            "file": file_path,
            "vulnerability": vulnerability,
            "message": issue,
            "severity": "Medium",
            "line": 0,
            "uid": generate_uid(file_path, vulnerability, 0, code_snippet),
            "code_snippet": code_snippet,
            "fix": fix,
            "fix_example": fix_example,
            "cvss_score": 0.0,
            "exploitability_score": exploitability_score
        }
        findings.append(finding)

    # Check for CSRF vulnerabilities
    csrf_issues = check_for_csrf(code)
    for issue in csrf_issues:
        code_snippet = "N/A"
        vulnerability = "CSRF"
        fix, fix_example = get_fix_recommendation(vulnerability, issue)
        exploitability_score = 4
        finding = {
            "file": file_path,
            "vulnerability": vulnerability,
            "message": issue,
            "severity": "Medium",
            "line": 0,
            "uid": generate_uid(file_path, vulnerability, 0, code_snippet),
            "code_snippet": code_snippet,
            "fix": fix,
            "fix_example": fix_example,
            "cvss_score": 0.0,
            "exploitability_score": exploitability_score
        }
        findings.append(finding)

    # Check for File Handling vulnerabilities
    file_issues = check_for_file_handling_vulnerabilities(code)
    for issue in file_issues:
        code_snippet = "N/A"
        vulnerability = "File Traversal" if "File Traversal" in issue else "Resource Exhaustion"
        severity_match = re.search(r"Severity: (\w+)", issue)
        severity = severity_match.group(1) if severity_match else (
            "Medium" if vulnerability == "File Traversal" else "Low")
        fix, fix_example = get_fix_recommendation(vulnerability, issue)
        exploitability_score = 7 if "Severity: High" in issue else 5 if "Severity: Medium" in issue else 3
        finding = {
            "file": file_path,
            "vulnerability": vulnerability,
            "message": issue,
            "severity": severity,
            "line": 0,
            "uid": generate_uid(file_path, vulnerability, 0, code_snippet),
            "code_snippet": code_snippet,
            "fix": fix,
            "fix_example": fix_example,
            "cvss_score": 0.0,
            "exploitability_score": exploitability_score
        }
        findings.append(finding)

    # Check for Hardcoded Sensitive Data
    hardcoded_issues = check_for_hardcoded_sensitive_data(code)
    for issue in hardcoded_issues:
        code_snippet = "N/A"
        vulnerability = "Hardcoded Sensitive Data"
        fix, fix_example = get_fix_recommendation(vulnerability, issue)
        exploitability_score = 6
        finding = {
            "file": file_path,
            "vulnerability": vulnerability,
            "message": issue,
            "severity": "High",
            "line": 0,
            "uid": generate_uid(file_path, vulnerability, 0, code_snippet),
            "code_snippet": code_snippet,
            "fix": fix,
            "fix_example": fix_example,
            "cvss_score": 0.0,
            "exploitability_score": exploitability_score
        }
        findings.append(finding)

    # Check for Arithmetic Overflows
    arithmetic_issues = check_for_arithmetic_overflows(code)
    for issue in arithmetic_issues:
        code_snippet = "N/A"
        vulnerability = "Arithmetic Overflow" if "Overflow" in issue else "Divide-by-Zero"
        severity = "Medium" if vulnerability == "Arithmetic Overflow" else "High"
        fix, fix_example = get_fix_recommendation(vulnerability, issue)
        exploitability_score = 5 if vulnerability == "Arithmetic Overflow" else 7
        finding = {
            "file": file_path,
            "vulnerability": vulnerability,
            "message": issue,
            "severity": severity,
            "line": 0,
            "uid": generate_uid(file_path, vulnerability, 0, code_snippet),
            "code_snippet": code_snippet,
            "fix": fix,
            "fix_example": fix_example,
            "cvss_score": 0.0,
            "exploitability_score": exploitability_score
        }
        findings.append(finding)

    # Check for Buffer Overflows in STRING/UNSTRING
    buffer_issues = check_for_buffer_overflows(code)
    for issue in buffer_issues:
        code_snippet = "N/A"
        vulnerability = "Buffer Overflow"
        fix, fix_example = get_fix_recommendation(vulnerability, issue)
        exploitability_score = 6
        finding = {
            "file": file_path,
            "vulnerability": vulnerability,
            "message": issue,
            "severity": "High",
            "line": 0,
            "uid": generate_uid(file_path, vulnerability, 0, code_snippet),
            "code_snippet": code_snippet,
            "fix": fix,
            "fix_example": fix_example,
            "cvss_score": 0.0,
            "exploitability_score": exploitability_score
        }
        findings.append(finding)

    # Check for Insecure Data Transmission
    transmission_issues = check_for_insecure_data_transmission(code)
    for issue in transmission_issues:
        code_snippet = "N/A"
        vulnerability = "Insecure Data Transmission"
        fix, fix_example = get_fix_recommendation(vulnerability, issue)
        exploitability_score = 6
        finding = {
            "file": file_path,
            "vulnerability": vulnerability,
            "message": issue,
            "severity": "High",
            "line": 0,
            "uid": generate_uid(file_path, vulnerability, 0, code_snippet),
            "code_snippet": code_snippet,
            "fix": fix,
            "fix_example": fix_example,
            "cvss_score": 0.0,
            "exploitability_score": exploitability_score
        }
        findings.append(finding)

    # Check for Improper Error Handling
    error_handling_issues = check_for_improper_error_handling(code)
    for issue in error_handling_issues:
        code_snippet = "N/A"
        vulnerability = "Improper Error Handling" if "ON ERROR" not in issue else "Information Disclosure"
        severity = "Medium" if vulnerability == "Information Disclosure" else "Low"
        fix, fix_example = get_fix_recommendation(vulnerability, issue)
        exploitability_score = 3 if vulnerability == "Information Disclosure" else 2
        finding = {
            "file": file_path,
            "vulnerability": vulnerability,
            "message": issue,
            "severity": severity,
            "line": 0,
            "uid": generate_uid(file_path, vulnerability, 0, code_snippet),
            "code_snippet": code_snippet,
            "fix": fix,
            "fix_example": fix_example,
            "cvss_score": 0.0,
            "exploitability_score": exploitability_score
        }
        findings.append(finding)

    # Check for Insecure Session Management
    session_issues = check_for_insecure_session_management(code)
    for issue in session_issues:
        code_snippet = "N/A"
        vulnerability = "Insecure Session Management"
        fix, fix_example = get_fix_recommendation(vulnerability, issue)
        exploitability_score = 6
        finding = {
            "file": file_path,
            "vulnerability": vulnerability,
            "message": issue,
            "severity": "High",
            "line": 0,
            "uid": generate_uid(file_path, vulnerability, 0, code_snippet),
            "code_snippet": code_snippet,
            "fix": fix,
            "fix_example": fix_example,
            "cvss_score": 0.0,
            "exploitability_score": exploitability_score
        }
        findings.append(finding)

    # Check for Custom Rules
    custom_issues = check_custom_rules(code, custom_rules)
    for issue in custom_issues:
        code_snippet = "N/A"
        vulnerability = "Custom Rule Violation"
        severity_match = re.search(r"Severity: (\w+)", issue)
        severity = severity_match.group(1) if severity_match else "Medium"
        fix, fix_example = get_fix_recommendation(vulnerability, issue)
        exploitability_score = 4  # Moderate impact for custom rules
        finding = {
            "file": file_path,
            "vulnerability": vulnerability,
            "message": issue,
            "severity": severity,
            "line": 0,
            "uid": generate_uid(file_path, vulnerability, 0, code_snippet),
            "code_snippet": code_snippet,
            "fix": fix,
            "fix_example": fix_example,
            "cvss_score": 0.0,
            "exploitability_score": exploitability_score
        }
        findings.append(finding)

    return findings


def scan_vulnerabilities(path, quiet=False, custom_rules=None):
    """Check COBOL files for common vulnerabilities with parallel and incremental scanning."""
    findings = []
    file_hashes = load_file_hashes()
    files_to_scan = []

    # Collect files to scan and check for changes
    if os.path.isdir(path):
        for root, _, files in os.walk(path):
            for file in files:
                if file.endswith(".cbl"):
                    file_path = os.path.join(root, file)
                    current_hash = compute_file_hash(file_path)
                    if file_path not in file_hashes or file_hashes[file_path] != current_hash:
                        files_to_scan.append((file_path, custom_rules))
                        file_hashes[file_path] = current_hash
    elif os.path.isfile(path):
        if path.endswith(".cbl"):
            current_hash = compute_file_hash(path)
            if path not in file_hashes or file_hashes[path] != current_hash:
                files_to_scan.append((path, custom_rules))
                file_hashes[path] = current_hash
        else:
            if not quiet:
                console.print(f"[bold red][Error] {path} is not a .cbl file.[/bold red]")
    else:
        if not quiet:
            console.print(f"[bold red][Error] {path} is not a valid file or directory.[/bold red]")

    # Save updated hashes
    save_file_hashes(file_hashes)

    # Parallel scanning
    with Pool() as pool:
        results = pool.starmap(analyze_file, files_to_scan)
    for result in results:
        findings.extend(result)

    return findings


def export_results(results, output, format, quiet=False):
    """Export the scan results to the specified format (JSON/SARIF/HTML)."""
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
                        "exploitability_score": result.get("exploitability_score", 0),
                        "fix": result.get("fix", "No fix available"),
                        "fix_example": result.get("fix_example", "")
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

    elif format == "html":
        # Count vulnerabilities by severity
        severity_counts = {"High": 0, "Medium": 0, "Low": 0}
        for result in results:
            severity = result["severity"].capitalize()
            if severity in severity_counts:
                severity_counts[severity] += 1

        html_content = f"""
        <html>
        <head>
            <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
                .high {{ color: red; }}
                .medium {{ color: orange; }}
                .low {{ color: green; }}
            </style>
        </head>
        <body>
            <h1>CobRA Scan Report</h1>
            <h2>Vulnerability Summary</h2>
            <canvas id="vulnChart" width="400" height="200"></canvas>
            <script>
                const ctx = document.getElementById('vulnChart').getContext('2d');
                new Chart(ctx, {{
                    type: 'bar',
                    data: {{
                        labels: ['High', 'Medium', 'Low'],
                        datasets: [{{
                            label: 'Vulnerabilities by Severity',
                            data: [{severity_counts['High']}, {severity_counts['Medium']}, {severity_counts['Low']}],
                            backgroundColor: ['red', 'orange', 'green']
                        }}]
                    }},
                    options: {{
                        scales: {{
                            y: {{ beginAtZero: true }}
                        }}
                    }}
                }});
            </script>
            <h2>Findings</h2>
            <table>
                <tr>
                    <th>File</th>
                    <th>Vulnerability</th>
                    <th>Severity</th>
                    <th>Line</th>
                    <th>Message</th>
                    <th>Fix</th>
                    <th>Fix Example</th>
                    <th>Exploitability Score</th>
                </tr>
        """

        for result in results:
            severity = result["severity"].lower()
            severity_class = severity
            html_content += f"""
                <tr>
                    <td>{result['file']}</td>
                    <td>{result['vulnerability']}</td>
                    <td class="{severity_class}">{result['severity']}</td>
                    <td>{result['line']}</td>
                    <td>{result['message']}</td>
                    <td>{result['fix']}</td>
                    <td><pre>{result['fix_example']}</pre></td>
                    <td>{result['exploitability_score']}</td>
                </tr>
            """

        html_content += """
            </table>
        </body>
        </html>
        """

        try:
            with open(output, "w") as html_file:
                html_file.write(html_content)
            if not quiet:
                console.print(f"[bold blue][Info] Results exported to {output} in HTML format.[/bold blue]")
        except IOError as e:
            console.print(f"[bold red][Error] Failed to write HTML file: {str(e)}[/bold red]")


if __name__ == "__main__":
    cli()