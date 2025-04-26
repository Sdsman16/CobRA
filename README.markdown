# CobRA: COBOL Risk Analyzer

![CobRA Logo](https://github.com/Sdsman16/CobRA/raw/main/logo.png)

CobRA is a Python-based static analysis tool designed to identify vulnerabilities and security risks in COBOL source code. It scans `.cbl` files for issues such as buffer overflows, unvalidated inputs, hardcoded values, weak authentication, and web-related vulnerabilities (e.g., XSS, SQL injection), leveraging the National Vulnerability Database (NVD) API and OSV.dev to match code patterns against known vulnerabilities. CobRA provides detailed fix recommendations with COBOL code examples, supports custom rules, and can be integrated into CI/CD pipelines to enforce security policies by breaking builds when vulnerabilities are detected. It’s ideal for developers and security professionals working with legacy COBOL systems in financial and enterprise environments.

## Features

- **CVE Detection**: Identifies COBOL constructs that may trigger known vulnerabilities (e.g., CVE-2019-14486, CVE-2023-32265) using NVD API and OSV.dev data.
- **Vulnerability Scanning**: Detects a wide range of COBOL-specific and web-related vulnerabilities:
  - **Unvalidated Input**: Identifies `ACCEPT` statements without input validation.
  - **File Handling Issues**: Detects dynamic file names in `SELECT` statements for potential file traversal (with enhanced detection for user input and path traversal patterns) and unclosed files (resource exhaustion).
  - **Hardcoded Sensitive Data**: Finds hardcoded credentials, keys, or sensitive data like SSNs in `WORKING-STORAGE SECTION`.
  - **Arithmetic Overflows**: Checks for missing `ON SIZE ERROR` clauses in arithmetic operations and potential divide-by-zero in `DIVIDE` statements.
  - **Buffer Overflows in String Operations**: Detects missing `ON OVERFLOW` clauses in `STRING` and `UNSTRING` statements.
  - **Insecure Data Transmission**: Identifies network interactions without SSL/HTTPS.
  - **Improper Error Handling**: Detects missing `ON ERROR` or `AT END` clauses and error blocks that might disclose information.
  - **Insecure Session Management**: Finds web-enabled COBOL code lacking secure session tokens.
  - **Web Vulnerabilities**: Includes XSS, format string vulnerabilities in `DISPLAY` statements, SQL injection, command injection (with enhanced detection for user input and injection patterns), insecure dependency usage in `CALL` statements, insecure cryptographic storage, and CSRF in web-enabled COBOL applications.
- **Custom Rules**: Supports user-defined vulnerability patterns via a JSON rules file.
- **Exploitability Scoring**: Assigns an exploitability score to each finding based on user input and patterns to help prioritize remediation.
- **Reachability Analysis**: Reduces false positives by ensuring user-controlled variables are actually reachable in vulnerable code paths.
- **Fix Recommendations**: Provides actionable remediation steps with COBOL code examples for each detected issue.
- **Automated Fixes**: Offers a `fix` command to automatically apply simple fixes (e.g., adding `ON SIZE ERROR` clauses).
- **Severity Filtering**: Filter findings by severity (`--severity=<high|medium|low>`) or show severity and lower (`--severity-and-lower=<high|medium|low>`).
- **Delta Comparison**: Compare current scan results with previous results (`--delta=<path>`) to identify net new vulnerabilities.
- **CI/CD Integration**: Breaks the build in CI/CD pipelines if vulnerabilities or net new vulnerabilities are detected.
- **Colorized Output**: Uses `rich` for enhanced console output with color-coded severity levels.
- **Flexible Output**: Generates results in JSON, SARIF, or HTML formats with detailed findings, including charts in HTML reports.
- **Ignore List**: Allows suppression of specific findings via unique IDs (UIDs) stored in `ignore.json`.
- **Verbose Logging**: Provides detailed debug logs for troubleshooting, saved to `cobra.log`.
- **Performance Optimizations**: Supports parallel scanning for large codebases and incremental scanning to skip unchanged files.
- **Extensible**: Easily extendable with new rules and vulnerability patterns via `rules.py` and `cve_checker.py`.

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

2. **Uninstall Global `cobra` Package** (if applicable):
   If you have a globally installed `cobra` package that conflicts, uninstall it:
   ```bash
   pip uninstall cobra
   ```

3. **Install Dependencies**:
   Install the required Python packages listed in `requirements.txt`:
   ```bash
   pip install -r requirements.txt
   ```

   **Note**: Ensure you have the following dependencies:
   - `click` for CLI functionality.
   - `rich` for colorized console output.
   - `requests` for CVE fetching.

4. **Verify Installation**:
   Run the following to ensure CobRA is set up:
   ```bash
   python -m cobra.cli --help
   ```

## Usage

### Basic Scan

Scan a directory or file for vulnerabilities and save results in JSON format:
```bash
cobra scan "path/to/cobol/files" --output=results.json --format=json
```

### Advanced Options

- **Filter by Severity**:
  Show only high-severity findings:
  ```bash
  cobra scan "path/to/cobol/files" --severity=high --output=results.json --format=json
  ```

  Show medium and lower severity findings:
  ```bash
  cobra scan "path/to/cobol/files" --severity-and-lower=medium --output=results.json --format=json
  ```

- **Delta Comparison**:
  Compare with a previous scan to identify new vulnerabilities:
  ```bash
  cobra scan "path/to/cobol/files" --delta=previous_results.json --output=results.json --format=json
  ```

- **Verbose Output**:
  Enable detailed debug logs:
  ```bash
  cobra scan "path/to/cobol/files" --verbose --output=results.json --format=json
  ```

- **Custom Rules**:
  Define custom vulnerability patterns in a `rules.json` file:
  ```json
  {
      "rules": [
          {
              "name": "Custom MOVE Check",
              "pattern": "MOVE\\s+TO\\s+\\w+\\s+WITHOUT\\s+VALIDATION",
              "severity": "High",
              "message": "MOVE statement without validation"
          }
      ]
  }
  ```
  Scan with custom rules:
  ```bash
  cobra scan "path/to/cobol/files" --custom-rules=rules.json --output=results.json --format=json
  ```

- **Custom Vulnerability Database**:
  Provide a custom vulnerability database in JSON format:
  ```json
  [
      {
          "id": "CUSTOM-001",
          "keywords": ["cobol", "custom"],
          "summary": "Custom vulnerability in COBOL code.",
          "cvss_score": 5.0
      }
  ]
  ```
  Scan with the custom database:
  ```bash
  cobra scan "path/to/cobol/files" --custom-db=custom_vulns.json --output=results.json --format=json
  ```

- **HTML Output**:
  Generate an HTML report with a severity chart:
  ```bash
  cobra scan "path/to/cobol/files" --output=report.html --format=html
  ```
  The HTML report includes a bar chart of vulnerabilities by severity and a detailed table of findings.

- **Automated Fixes**:
  Automatically apply fixes to simple issues (e.g., adding `ON SIZE ERROR` clauses):
  ```bash
  cobra fix "path/to/file.cbl"
  ```
  This generates a `file.cbl.fixed` with the applied fixes.

- **Update CVE Database**:
  Manually update the CVE cache:
  ```bash
  cobra update-cve-db
  ```

- **Ignore Findings**:
  Add a finding to the ignore list using its UID:
  ```bash
  cobra ignore "UID12345" --file="path/to/file.cbl" --vulnerability="CVE-2019-14486" --line=10 --code-snippet="ACCEPT INPUT"
  ```

- **List Ignored Findings**:
  View all ignored findings:
  ```bash
  cobra ignore-list
  ```

## Example Output

### JSON Output
```json
[
    {
        "file": "path/to/file.cbl",
        "vulnerability": "Unvalidated Input",
        "message": "Use of ACCEPT statement (unvalidated input) at line 19. Consider validating input length.",
        "severity": "Medium",
        "line": 19,
        "uid": "55640145-abcd-1234-efgh-567890abcdef",
        "code_snippet": "ACCEPT USER-INPUT",
        "fix": "Validate and sanitize user input before using ACCEPT; consider using a validation routine or restricting input length.",
        "fix_example": "PROCEDURE DIVISION.\n    ACCEPT USER-INPUT\n    IF USER-INPUT NOT MATCHES \"[A-Z0-9]+\" THEN\n        DISPLAY \"Invalid input\"\n        STOP RUN\n    END-IF",
        "cvss_score": 0.0,
        "exploitability_score": 5
    },
    {
        "file": "path/to/file.cbl",
        "vulnerability": "Format String Vulnerability",
        "message": "Potential Format String Vulnerability: DISPLAY with user-controlled variable at line 25",
        "severity": "Medium",
        "line": 0,
        "uid": "78901234-abcd-1234-efgh-567890abcdef",
        "code_snippet": "N/A",
        "fix": "Sanitize user input in DISPLAY statements to prevent format string vulnerabilities.",
        "fix_example": "PROCEDURE DIVISION.\n    ACCEPT USER-INPUT\n    INSPECT USER-INPUT REPLACING ALL \"%\" BY \" \"\n    DISPLAY USER-INPUT",
        "cvss_score": 0.0,
        "exploitability_score": 5
    }
]
```

### HTML Output
The HTML report includes:
- A bar chart showing the distribution of vulnerabilities by severity (High, Medium, Low).
- A table with columns for File, Vulnerability, Severity, Line, Message, Fix, Fix Example, and Exploitability Score.
- Color-coded severity levels for easy identification.

## Troubleshooting

- **CVE Count Dropped**:
  If the number of detected CVEs drops unexpectedly (e.g., from 43 to 26):
  1. Check the ignore list:
     ```bash
     cobra ignore-list
     ```
     Prune outdated ignores if necessary:
     ```bash
     cobra ignore-list --prune
     ```
  2. Update the CVE database:
     ```bash
     cobra update-cve-db
     ```
     Check `cobra.log` for errors like "Failed to fetch CVE data."
  3. Run with verbose output to debug CVE matching:
     ```bash
     cobra scan "path/to/files" --verbose --output=results.json --format=json
     ```
  4. Compare `cve_cache.json` with a previous version to identify changes in CVSS scores or descriptions.
  5. Verify the OSV.dev integration is fetching additional vulnerabilities by checking `cobra.log` for OSV fetch logs.

- **No Vulnerabilities Found**:
  - Ensure the path contains `.cbl` files.
  - Run with `--verbose` to see if files are being scanned.
  - Check `cobra.log` for errors during scanning.

- **Performance Issues**:
  - CobRA uses parallel scanning for large codebases. Ensure your system has sufficient resources.
  - Incremental scanning skips unchanged files. If performance is still slow, check `file_hashes.json` for corruption.

- **Custom Rules Not Working**:
  - Verify the `rules.json` format matches the expected structure.
  - Check `cobra.log` for errors loading the rules file.

## Contributing

Contributions are welcome! To contribute:

1. Fork the repository.
2. Create a feature branch:
   ```bash
   git checkout -b feature/your-feature
   ```
3. Make changes and commit:
   ```bash
   git commit -m "Add your feature"
   ```
4. Push to your fork:
   ```bash
   git push origin feature/your-feature
   ```
5. Open a pull request with a detailed description of your changes.

## License

CobRA is licensed under the MIT License. See the `LICENSE` file for details.

## Contact

For questions or support, open an issue on GitHub or contact the maintainer at [your-email@example.com].