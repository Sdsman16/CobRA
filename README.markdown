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

2. **Uninstall Global `cobra` Package**