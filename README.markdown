# CobRA: COBOL Risk Analyzer

![CobRA Logo](https://github.com/Sdsman16/CobRA/raw/main/logo.png)

CobRA is a Python-based static analysis tool designed to identify vulnerabilities and security risks in COBOL source code. It scans `.cbl` files for issues such as buffer overflows, unvalidated inputs, hardcoded values, weak authentication, and web-related vulnerabilities (e.g., XSS, SQL injection), leveraging the National Vulnerability Database (NVD) API to match code patterns against known CVEs. CobRA provides detailed fix recommendations and can be integrated into CI/CD pipelines to enforce security policies by breaking builds when vulnerabilities are detected. It’s ideal for developers and security professionals working with legacy COBOL systems in financial and enterprise environments.

## Features

- **CVE Detection**: Identifies COBOL constructs that may trigger known vulnerabilities (e.g., CVE-2019-14486, CVE-2023-32265) using NVD API data.
- **Vulnerability Scanning**: Detects a wide range of COBOL-specific and web-related vulnerabilities:
  - **Unvalidated Input**: Identifies `ACCEPT` statements without input validation.
  - **File Handling Issues**: Detects dynamic file names in `SELECT` statements for potential file traversal (with enhanced detection for user input and path traversal patterns) and unclosed files (resource exhaustion).
  - **Hardcoded Sensitive Data**: Finds hardcoded credentials, keys, or sensitive data like SSNs in `WORKING-STORAGE SECTION`.
  - **Arithmetic Overflows**: Checks for missing `ON SIZE ERROR` clauses in arithmetic operations and potential divide-by-zero in `DIVIDE` statements.
  - **Insecure Data Transmission**: Identifies network interactions without SSL/HTTPS.
  - **Improper Error Handling**: Detects missing `ON ERROR` or `AT END` clauses and error blocks that might disclose information.
  - **Insecure Session Management**: Finds web-enabled COBOL code lacking secure session tokens.
  - **Web Vulnerabilities**: Includes XSS, SQL injection, command injection, insecure cryptographic storage, and CSRF in web-enabled COBOL applications.
- **Fix Recommendations**: Provides actionable remediation steps for each detected issue, tailored to COBOL development.
- **Severity Filtering**: Filter findings by severity (`--severity=<high|medium|low>`) or show severity and lower (`--severity-and-lower=<high|medium|low>`). Filtering applies to both console output and exported results.
- **Delta Comparison**: Compare current scan results with previous results (`--delta=<path>`) to identify net new vulnerabilities and fail the build if any are found.
- **CI/CD Integration**: Breaks the build in CI/CD pipelines if vulnerabilities or net new vulnerabilities are detected, ensuring security issues are addressed early.
- **Colorized Output**: Uses `rich` for enhanced console output with color-coded severity levels (e.g., `[red]HIGH[/red]`, `[yellow]MEDIUM[/yellow]`).
- **Flexible Output**: Generates results in JSON or SARIF formats with detailed findings, including line numbers, severity, CVSS scores, code snippets, and fixes.
- **Ignore List**: Allows suppression of specific findings via unique IDs (UIDs) stored in `ignore.json`.
- **Verbose Logging**: Provides detailed debug logs for troubleshooting, saved to `cobra.log`.
- **Extensible**: Easily extendable with new rules and CVE patterns via `rules.py` and `cve_checker.py`.

## Installation

### Prerequisites

- **Python**: Version 3.8 or higher (tested with Python 3.13).
- **Operating System**: Windows, Linux, or macOS (tested on Windows and Ubuntu).

### Steps

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/Sdsman16/CobRA.git
   cd CobRA
   ```

2. **Uninstall Global `cobra` Package** (if installed):
   To avoid conflicts with the global `cobra` package, run:
   ```bash
   pip uninstall cobra -y
   ```
   Manually remove any remnants (Windows):
   ```bash
   del C:\Users\sdson\AppData\Local\Programs\Python\Python313\Scripts\cobra.exe
   rmdir /s /q C:\Users\sdson\AppData\Local\Programs\Python\Python313\Lib\site-packages\cobra
   ```
   Verify:
   ```bash
   pip list | findstr cobra
   ```
   The output should show no `cobra` package.

3. **Install CobRA Package**:
   Install CobRA and its dependencies, which will make the `cobra` command available:
   ```bash
   pip install -e .
   ```

4. **Clear Python Cache** (if needed):
   ```bash
   del /s /q C:\Users\sdson\PycharmProjects\CobRA\__pycache__
   del /s /q C:\Users\sdson\PycharmProjects\CobRA\cobra\__pycache__
   ```

5. **Update CVE Database**:
   Populate `cve_cache.json` with the latest CVE data:
   ```bash
   cobra update-cve-db
   ```
   Check `cobra.log` for:
   ```
   CVE database updated successfully. X CVEs cached.
   ```

## Usage

CobRA supports scanning individual `.cbl` files or directories for CVEs and vulnerabilities, providing detailed findings with fix recommendations. Results include unique IDs (UIDs) for suppression and can fail CI/CD builds if vulnerabilities or net new vulnerabilities are detected.

### Commands

- **Scan Files or Directories**:
  Scan a COBOL file or directory for CVEs and vulnerabilities:
  ```bash
  cobra scan path/to/file.cbl --output=results.json --format=json
  ```
  ```bash
  cobra scan path/to/directory --verbose --output=results.sarif --format=sarif
  ```
  Filter by severity (e.g., show only high-severity issues):
  ```bash
  cobra scan path/to/directory --severity=high --output=results.json --format=json
  ```
  Show severity and lower (e.g., medium and low-severity issues):
  ```bash
  cobra scan path/to/directory --severity-and-lower=medium --output=results.json --format=json
  ```
  Compare with previous results to identify net new vulnerabilities:
  ```bash
  cobra scan path/to/directory --delta=previous_results.json --output=results.json --format=json
  ```

- **Update CVE Database**:
  Refresh the local CVE cache from the NVD API:
  ```bash
  cobra update-cve-db
  ```

- **Ignore a Finding**:
  Add a finding’s UID to the ignore list:
  ```bash
  cobra ignore abc123 --file path/to/file.cbl --vulnerability CVE-2019-14486 --line 10 --code-snippet "MOVE ..."
  ```

- **List Ignored Findings**:
  View or prune ignored findings:
  ```bash
  cobra ignore-list
  ```
  ```bash
  cobra ignore-list --prune
  ```

### Options for `scan`

- `--output=<filename>`: Save results to a file (JSON or SARIF).
- `--format=<json|sarif>`: Output format (default: console).
- `--line-tolerance=<int>`: Line number tolerance for matching ignored findings (default: 10).
- `--quiet`: Suppress non-critical console output.
- `--verbose`: Show detailed debug logs.
- `--no-update`: Skip automatic CVE database update.
- `--severity=<high|medium|low>`: Show only findings of the specified severity. In CI/CD, breaks the build if any matching vulnerabilities are found (unless `--delta` is used).
- `--severity-and-lower=<high|medium|low>`: Show findings of the specified severity and lower (e.g., `--severity-and-lower=medium` shows medium and low). In CI/CD, breaks the build if any matching vulnerabilities are found (unless `--delta` is used).
- `--delta=<path>`: Path to previous scan results for delta comparison. Breaks the build if net new vulnerabilities are found.

### CI/CD Integration

CobRA can be integrated into CI/CD pipelines to scan COBOL files as a stage and break the build if vulnerabilities or net new vulnerabilities are detected. This ensures security issues are addressed before deployment.

#### Example: GitHub Actions Workflow with Delta Comparison

```yaml
name: CI/CD Pipeline with CobRA Scan

on:
  push:
    branches:
      - main
  pull_request:
    branches:
      - main

jobs:
  build-and-scan:
    runs-on: ubuntu-latest

    steps:
    - name: Checkout code
      uses: actions/checkout@v3

    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.8'

    - name: Install CobRA
      run: |
        pip install -e .
        cobra update-cve-db

    - name: Run CobRA Vulnerability Scan with Delta
      run: |
        # Assumes previous_results.json is available (e.g., from a previous build)
        cobra scan "./path/to/cobol/files" --severity=high --delta=previous_results.json --output=results.json --format=json
        # Update previous_results.json for the next run
        cp results.json previous_results.json
```

- If net new vulnerabilities are found compared to `previous_results.json`, the `cobra scan` command exits with a non-zero status code, failing the build.
- If `--delta` is not used, the build breaks if any vulnerabilities matching the severity filter are found.
- Adjust the `--severity` or `--severity-and-lower` options to control which findings are considered in the delta comparison.

### Example Output

#### Without Severity Filter or Delta
```
[Debug] Starting scan_directory
cobra found 46 issues grouped by file:

C:\Users\sdson\Downloads\buffer_overflow.cbl
  [red]HIGH[/red] (line 3): Keyword match for CVE-2019-14486: GnuCOBOL 2.2 buffer overflow in cb_evaluate_expr in cobc/field.c via crafted COBOL source code. (UID: bab64cc5..., CVSS: 7.5)
    [bold green]Fix:[/bold green] Implement bounds checking on array accesses and use safe COBOL constructs like INSPECT to validate data lengths.
  [yellow]MEDIUM[/yellow] (line 19): Use of ACCEPT statement (unvalidated input). Consider validating input length. (UID: 55640145..., CVSS: 0.0)
    [bold green]Fix:[/bold green] Validate and sanitize user input before using ACCEPT; consider using a validation routine or restricting input length.
  [red]HIGH[/red] (line 50): Potential Hardcoded Sensitive Data: Possible credential or sensitive data. (UID: 789abcde..., CVSS: 0.0)
    [bold green]Fix:[/bold green] Remove hardcoded sensitive data; use environment variables or a secure vault to store credentials and keys.
  [red]HIGH[/red] (line 60): Potential File Traversal: Dynamic file name from user input in SELECT statement (Severity: High). (UID: 1234efgh..., CVSS: 0.0)
    [bold green]Fix:[/bold green] User input detected in file name; strictly validate and sanitize input to prevent path traversal (e.g., reject '../' sequences).
[Info] Found 23 CVE-related issues after severity filtering.
[Info] Found 23 vulnerability issues before severity filtering.
[Info] Total findings before filtering: 46
[Info] Total findings after severity filtering: 46
[Error] Found 46 vulnerabilities. Breaking the build.
```

#### With `--severity=high` and `--delta=previous_results.json`
```
[Debug] Starting scan_directory
cobra found 23 issues grouped by file:

C:\Users\sdson\Downloads\buffer_overflow.cbl
  [red]HIGH[/red] (line 3): Keyword match for CVE-2019-14486: GnuCOBOL 2.2 buffer overflow in cb_evaluate_expr in cobc/field.c via crafted COBOL source code. (UID: bab64cc5..., CVSS: 7.5)
    [bold green]Fix:[/bold green] Implement bounds checking on array accesses and use safe COBOL constructs like INSPECT to validate data lengths.
  [red]HIGH[/red] (line 9): Keyword match for CVE-2019-14486: GnuCOBOL 2.2 buffer overflow in cb_evaluate_expr in cobc/field.c via crafted COBOL source code. (UID: 5883df6f..., CVSS: 7.5)
    [bold green]Fix:[/bold green] Implement bounds checking on array accesses and use safe COBOL constructs like INSPECT to validate data lengths.
  [red]HIGH[/red] (line 60): Potential File Traversal: Dynamic file name from user input in SELECT statement (Severity: High). (UID: 1234efgh..., CVSS: 0.0)
    [bold green]Fix:[/bold green] User input detected in file name; strictly validate and sanitize input to prevent path traversal (e.g., reject '../' sequences).
  [red]HIGH[/red] (line 70): Potential Divide-by-Zero: Missing divisor check in DIVIDE statement. (UID: 4567ijkl..., CVSS: 0.0)
    [bold green]Fix:[/bold green] Add a check for zero divisor before DIVIDE statements to prevent crashes.
[Info] Found 23 CVE-related issues after severity filtering.
[Info] Found 3 vulnerability issues before severity filtering.
[Info] Total findings before filtering: 26
[Info] Total findings after severity filtering: 23
[Info] Found 2 net new vulnerabilities compared to previous scan.
  [red]HIGH[/red] (line 60): Potential File Traversal: Dynamic file name from user input in SELECT statement (Severity: High). (UID: 1234efgh..., CVSS: 0.0)
    [bold green]Fix:[/bold green] User input detected in file name; strictly validate and sanitize input to prevent path traversal (e.g., reject '../' sequences).
  [red]HIGH[/red] (line 70): Potential Divide-by-Zero: Missing divisor check in DIVIDE statement. (UID: 4567ijkl..., CVSS: 0.0)
    [bold green]Fix:[/bold green] Add a check for zero divisor before DIVIDE statements to prevent crashes.
[Error] Found 2 net new vulnerabilities. Breaking the build.
```

#### With `--severity-and-lower=medium` and `--delta=previous_results.json`
```
[Debug] Starting scan_directory
cobra found 21 issues grouped by file:

C:\Users\sdson\Downloads\buffer_overflow.cbl
  [yellow]MEDIUM[/yellow] (line 19): Use of ACCEPT statement (unvalidated input). Consider validating input length. (UID: 55640145..., CVSS: 0.0)
    [bold green]Fix:[/bold green] Validate and sanitize user input before using ACCEPT; consider using a validation routine or restricting input length.
  [yellow]MEDIUM[/yellow] (line 22): Use of ACCEPT statement (unvalidated input). Consider validating input length. (UID: fd6123aa..., CVSS: 0.0)
    [bold green]Fix:[/bold green] Validate and sanitize user input before using ACCEPT; consider using a validation routine or restricting input length.
  [yellow]MEDIUM[/yellow] (line 65): Potential File Traversal: File name contains traversal pattern in SELECT statement at line 65. (UID: 5678qrst..., CVSS: 0.0)
    [bold green]Fix:[/bold green] Validate file names in SELECT statements and avoid using user input directly in file paths.
  [yellow]MEDIUM[/yellow] (line 80): Potential Arithmetic Overflow: Missing ON SIZE ERROR in arithmetic operation. (UID: 9012mnop..., CVSS: 0.0)
    [bold green]Fix:[/bold green] Add ON SIZE ERROR clause to arithmetic operations to handle overflows gracefully.
[Info] Found 18 CVE-related issues after severity filtering.
[Info] Found 3 vulnerability issues before severity filtering.
[Info] Total findings before filtering: 26
[Info] Total findings after severity filtering: 21
[Info] Found 1 net new vulnerability compared to previous scan.
  [yellow]MEDIUM[/yellow] (line 65): Potential File Traversal: File name contains traversal pattern in SELECT statement at line 65. (UID: 5678qrst..., CVSS: 0.0)
    [bold green]Fix:[/bold green] Validate file names in SELECT statements and avoid using user input directly in file paths.
[Error] Found 1 net new vulnerability. Breaking the build.
```

#### No New Vulnerabilities with `--delta=previous_results.json`
```
[Debug] Starting scan_directory
cobra found 23 issues grouped by file:

C:\Users\sdson\Downloads\buffer_overflow.cbl
  [red]HIGH[/red] (line 3): Keyword match for CVE-2019-14486: GnuCOBOL 2.2 buffer overflow in cb_evaluate_expr in cobc/field.c via crafted COBOL source code. (UID: bab64cc5..., CVSS: 7.5)
    [bold green]Fix:[/bold green] Implement bounds checking on array accesses and use safe COBOL constructs like INSPECT to validate data lengths.
  [red]HIGH[/red] (line 9): Keyword match for CVE-2019-14486: GnuCOBOL 2.2 buffer overflow in cb_evaluate_expr in cobc/field.c via crafted COBOL source code. (UID: 5883df6f..., CVSS: 7.5)
    [bold green]Fix:[/bold green] Implement bounds checking on array accesses and use safe COBOL constructs like INSPECT to validate data lengths.
[Info] Found 23 CVE-related issues after severity filtering.
[Info] Found 3 vulnerability issues before severity filtering.
[Info] Total findings before filtering: 26
[Info] Total findings after severity filtering: 23
[Info] No net new vulnerabilities found compared to previous scan.
[Success] Results have been saved to: results.json
```

#### No Vulnerabilities Found
```
[Debug] Starting scan_directory
cobra found no vulnerabilities!
[Info] Found 0 CVE-related issues after severity filtering.
[Info] Found 0 vulnerability issues before severity filtering.
[Info] Total findings before filtering: 0
[Info] Total findings after severity filtering: 0
[Success] Results have been saved to: results.json
```

### Example JSON Output (with `--severity=high`)

```json
[
    {
        "file": "buffer_overflow.cbl",
        "vulnerability": "CVE-2019-14486",
        "message": "Keyword match for CVE-2019-14486: GnuCOBOL 2.2 buffer overflow in cb_evaluate_expr in cobc/field.c via crafted COBOL source code.",
        "severity": "High",
        "line": 3,
        "uid": "bab64cc5-...",
        "code_snippet": "MOVE ...",
        "cvss_score": 7.5,
        "fix": "Implement bounds checking on array accesses and use safe COBOL constructs like INSPECT to validate data lengths."
    },
    {
        "file": "buffer_overflow.cbl",
        "vulnerability": "Hardcoded Sensitive Data",
        "message": "Potential Hardcoded Sensitive Data: Possible credential or sensitive data.",
        "severity": "High",
        "line": 0,
        "uid": "789abcde-...",
        "code_snippet": "N/A",
        "cvss_score": 0.0,
        "fix": "Remove hardcoded sensitive data; use environment variables or a secure vault to store credentials and keys."
    },
    {
        "file": "buffer_overflow.cbl",
        "vulnerability": "File Traversal",
        "message": "Potential File Traversal: Dynamic file name from user input in SELECT statement (Severity: High).",
        "severity": "High",
        "line": 0,
        "uid": "1234efgh-...",
        "code_snippet": "N/A",
        "cvss_score": 0.0,
        "fix": "User input detected in file name; strictly validate and sanitize input to prevent path traversal (e.g., reject '../' sequences)."
    }
]
```

## Troubleshooting

- **Global Package Conflict**:
  If CobRA doesn’t run as expected:
  - Verify: `pip list | findstr cobra` should show `cobol-risk-analyzer`.
  - Re-run uninstall steps for the global `cobra` package and reinstall CobRA:
    ```bash
    pip uninstall cobra -y
    pip install -e .
    ```

- **Command Not Found**:
  If `cobra` command is not recognized:
  - Ensure CobRA is installed: `pip install -e .`
  - Verify the Python Scripts directory is in your PATH (Windows):
    ```bash
    echo %PATH%
    ```
    Add if needed:
    ```bash
    set PATH=%PATH%;C:\Users\sdson\AppData\Local\Programs\Python\Python313\Scripts
    ```

- **Empty CVE Database**:
  If no CVEs are detected:
  - Run: `cobra update-cve-db`.
  - Check `cve_cache.json` for CVEs (e.g., `CVE-2019-14486`).
  - Inspect `cobra.log` for API errors.

- **File Extension Issues**:
  Ensure COBOL files end in `.cbl`:
  ```bash
  dir path\to\files\*.cbl
  ```
  Rename if needed:
  ```bash
  ren path\to\files\*.txt *.cbl
  ```

- **Low Findings Count**:
  If fewer findings than expected (e.g., CVE count drops from 43 to 28):
  - **Check Ignore List**: Open `ignore.json` to see if UIDs of missing CVEs are listed. Run `cobra ignore-list --prune` to remove outdated ignores.
  - **Verify CVE Database**: Compare the current `cve_cache.json` with a previous version. Check CVSS scores of relevant CVEs (e.g., `CVE-2019-14486`). If scores dropped below 7.0, they may no longer be classified as "High" under `--severity=high`.
  - **Update CVE Database**: Run `cobra update-cve-db` to refresh `cve_cache.json`. Check `cobra.log` for errors like "Failed to fetch CVE data."
  - **Debug with Verbose**: Run the scan with `--verbose` to see detailed logs of CVE matching and filtering:
    ```bash
    cobra scan path/to/directory --severity=high --verbose --output=results.json --format=json
    ```
  - **Check Test File**: Ensure the COBOL file (e.g., `buffer_overflow.cbl`) hasn’t changed, as modified keywords can reduce CVE matches.

- **CI/CD Build Not Breaking**:
  If the build doesn’t break despite vulnerabilities:
  - Ensure `--severity` or `--severity-and-lower` matches your criteria.
  - If using `--delta`, ensure the previous results file exists and is accessible.
  - Verify the `cobra scan` command exits with a non-zero status code by checking the pipeline logs.

- **Delta Comparison Issues**:
  If the `--delta` option doesn’t work as expected:
  - Ensure the previous results file (e.g., `previous_results.json`) is in JSON format and contains valid scan results.
  - Check `cobra.log` for errors related to loading the delta file.
  - Verify the UIDs in the current and previous results to ensure they match for unchanged vulnerabilities.

- **Logs**:
  Check `cobra.log` for debugging:
  - `Fetching CVE data from NVD API...`
  - `Found CVE ... at ...`

## Contributing

Contributions are welcome! To contribute:
1. Fork the repository.
2. Create a branch: `git checkout -b feature/your-feature`.
3. Commit changes: `git commit -m "Add your feature"`.
4. Push: `git push origin feature/your-feature`.
5. Open a pull request.

Please include tests and update documentation as needed.

## License

CobRA is licensed under the MIT License. See [LICENSE](LICENSE) for details.

## Contact

For issues or questions, open an issue on the [GitHub repository](https://github.com/Sdsman16/CobRA).