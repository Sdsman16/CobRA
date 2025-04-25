# CobRA - COBOL Risk Analyzer

**CobRA** (COBOL Risk Analyzer) is a static analysis tool designed to identify security vulnerabilities and Common Vulnerabilities and Exposures (CVEs) in COBOL source code. It scans `.cbl` files for issues such as unvalidated input (e.g., `ACCEPT` statements), buffer overflows, and known CVEs associated with COBOL compilers like GnuCOBOL and Micro Focus COBOL. CobRA generates detailed reports in JSON or SARIF format, supports ignoring specific findings with stable unique identifiers (UIDs), and handles code movement with a configurable line tolerance.

## Features

- **Vulnerability Detection**: Identifies COBOL-specific issues like unvalidated `ACCEPT` statements and other common vulnerabilities (e.g., XSS, SQL Injection).
- **CVE Scanning**: Matches code patterns against a local CVE database for known COBOL-related vulnerabilities.
- **Stable UIDs**: Generates consistent UIDs for findings, enabling reliable ignoring even if code moves (within a ±10 line tolerance by default).
- **Flexible Output**: Exports results in JSON or SARIF format for integration with CI/CD pipelines or security tools.
- **Ignore System**: Allows suppression of specific findings via UIDs, with persistence across scans and code changes.
- **Deduplication**: Removes duplicate findings based on file, message, and line number.
- **Customizable CLI**: Supports `--quiet` for minimal output, `--verbose` for detailed debugging, and configurable line tolerance.

## Installation

### Prerequisites

- **Python**: Version 3.8 or higher.
- **Dependencies**: Install required Python packages using `pip`.

### Setup

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/your-org/cobra.git
   cd cobra
   ```

2. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```
   The `requirements.txt` should include:
   ```
   click
   rich
   ```

3. **Initialize the CVE Database**:
   Populate the local CVE cache:
   ```bash
   cobra update-cve-db
   ```

4. **Verify Installation**:
   Check that CobRA is installed:
   ```bash
   cobra --help
   ```

## Usage

CobRA provides a command-line interface (CLI) with the following commands:

### Scan COBOL Files

Scan a COBOL file or directory for vulnerabilities and CVEs:

```bash
cobra scan <path> [--output <file>] [--format json|sarif] [--line-tolerance <int>] [--quiet] [--verbose]
```

- `<path>`: Path to a `.cbl` file or directory containing COBOL files.
- `--output <file>`: Save results to the specified file (e.g., `results.json`).
- `--format json|sarif`: Output format (default: JSON if `--output` is specified).
- `--line-tolerance <int>`: Line number tolerance for matching ignored findings (default: 10).
- `--quiet`: Suppress non-critical console output.
- `--verbose`: Show detailed debug logs, including JSON findings.

**Example**:
```bash
cobra scan C:\Users\sdson\Downloads\buffer_overflow.cbl --output results1.json --format json
```

**Output**:
```
[Debug] Starting scan_directory
cobra found 43 issues:
HIGH - C:\Users\sdson\Downloads\buffer_overflow.cbl (line 3): Keyword match for CVE-2019-14468: ... (UID: b9eb4ca0...)
...
[Info] Found 43 CVE-related issues.
[Debug] Starting scan_vulnerabilities
Unvalidated Input vulnerability found in buffer_overflow.cbl: ACCEPT statement at line 19
...
[Info] Found 3 vulnerability issues.
[Info] Total findings after ignoring: 46
[Warning] results1.json already exists and will be overwritten.
[Info] Results exported to results1.json in JSON format.
[Success] Results have been saved to: C:\Users\sdson\PycharmProjects\CobRA\results1.json
```

### Update CVE Database

Refresh the local CVE cache:

```bash
cobra update-cve-db
```

### Ignore Findings

Suppress a specific finding by its UID:

```bash
cobra ignore <uid> --file <path> --vulnerability <id> --line <number> --code-snippet <snippet>
```

- `<uid>`: Unique identifier of the finding (e.g., `f3f84402...`).
- `--file <path>`: Path to the affected file.
- `--vulnerability <id>`: Vulnerability type (e.g., `CVE-2019-16395`).
- `--line <number>`: Line number of the finding.
- `--code-snippet <snippet>`: Code snippet associated with the finding.

**Example**:
```bash
cobra ignore f3f84402... --file "C:\Users\sdson\Downloads\buffer_overflow.cbl" --vulnerability "CVE-2019-16395" --line 32 --code-snippet "* Insecure: this can lead to an overflow..."
```

### List Ignored Findings

View or prune ignored findings:

```bash
cobra ignore-list [--prune]
```

- `--prune`: Remove unmatched ignored findings (requires a scan to identify outdated ignores).

**Example**:
```bash
cobra ignore-list
```

## Output Format

### JSON

When `--format json` is specified, results are saved as a list of findings:

```json
[
    {
        "file": "C:\\Users\\sdson\\Downloads\\buffer_overflow.cbl",
        "vulnerability": "CVE-2019-16395",
        "message": "Keyword match for CVE-2019-16395: GnuCOBOL 2.2 has a stack-based buffer overflow...",
        "severity": "high",
        "line": 32,
        "uid": "f3f8440263e5194f7cc7e4ce000277db4d906f512c9409d50539413dcac1862c",
        "code_snippet": "* Insecure: this can lead to an overflow..."
    },
    ...
]
```

### SARIF

When `--format sarif` is specified, results are saved in SARIF 2.1.0 format, compatible with tools like GitHub Code Scanning.

## Configuration

- **Ignore File**: Ignored findings are stored in `ignore.json` in the project root. Example:
  ```json
  {
      "ignored_findings": {
          "f3f84402...": {
              "file": "C:\\Users\\sdson\\Downloads\\buffer_overflow.cbl",
              "vulnerability": "CVE-2019-16395",
              "line": 32,
              "code_snippet": "* Insecure: this can lead to an overflow..."
          }
      }
  }
  ```

- **Line Tolerance**: Configure via `--line-tolerance` to allow ignored findings to persist across code movement (default: ±10 lines).

## Logging

CobRA logs debug information to `cobra.log` in the project root, including:
- Scan start/end times.
- `run_rules` output structure.
- Total issues found.

## Development

### Project Structure

```
cobra/
├── cobra/
│   ├── __init__.py
│   ├── cli.py          # CLI interface
│   ├── scanner.py      # Core scanning logic
│   ├── utils.py        # Utility functions (e.g., UID generation)
│   ├── cve_checker.py  # CVE database management
│   ├── vuln_checker.py # Vulnerability checks (e.g., XSS, SQL Injection)
│   ├── rules.py        # Rules for CVE and vulnerability detection
├── ignore.json         # Ignored findings
├── cobra.log           # Debug logs
├── requirements.txt    # Dependencies
├── README.md           # This file
```

### Contributing

1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/xyz`).
3. Commit changes (`git commit -m "Add feature XYZ"`).
4. Push to the branch (`git push origin feature/xyz`).
5. Open a pull request.

### Adding New Rules

To add new vulnerability or CVE rules:
1. Update `rules.py` with new patterns in `run_rules`.
2. Test with sample COBOL files.
3. Update the CVE database if necessary (`cobra update-cve-db`).

## Troubleshooting

- **Empty CVE Database**:
  - Run `cobra update-cve-db` to populate the cache.
  - Check `cobra.log` for errors.

- **JSON Findings in CLI**:
  - Avoid `--verbose` unless debugging is needed.
  - Ensure `cli.py` is updated to the latest version.

- **Incorrect Vulnerability IDs**:
  - Verify `run_rules` returns `id` or `vulnerability` keys.
  - Check `cobra.log` for `run_rules` output structure.

- **Ignored Findings Not Persisting**:
  - Confirm `--line-tolerance` is sufficient for code movement.
  - Check `ignore.json` for correct UID entries.

For issues, open a ticket on the [GitHub repository](https://github.com/your-org/cobra/issues) with:
- Console output.
- `cobra.log` contents.
- Sample COBOL file (if possible).

## License

CobRA is licensed under the MIT License. See [LICENSE](LICENSE) for details.

## Acknowledgments

- Built with [Click](https://click.palletsprojects.com/) for CLI and [Rich](https://rich.readthedocs.io/) for console formatting.
- Inspired by the need for robust COBOL security analysis in legacy systems.

---

*Maintained by [Your Organization]*  
*Last updated: April 2025*