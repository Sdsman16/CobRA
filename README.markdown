# CobRA: COBOL Risk Analyzer

CobRA is a Python-based static analysis tool designed to identify vulnerabilities and security risks in COBOL source code. It scans `.cbl` files for issues such as buffer overflows, unvalidated inputs, hardcoded values, weak authentication, and web-related vulnerabilities (e.g., XSS, SQL injection), leveraging the National Vulnerability Database (NVD) API to match code patterns against known CVEs. CobRA is ideal for developers and security professionals working with legacy COBOL systems in financial and enterprise environments.

## Features

- **CVE Detection**: Identifies COBOL constructs that may trigger known vulnerabilities (e.g., CVE-2019-14468, CVE-2023-4501) using NVD API data.
- **Vulnerability Scanning**: Detects COBOL-specific issues (e.g., unvalidated `ACCEPT`, dynamic `CALL`) and web vulnerabilities (e.g., XSS, SQL injection, CSRF).
- **Flexible Output**: Generates results in JSON or SARIF formats with detailed findings, including line numbers, severity, CVSS scores, and code snippets.
- **Ignore List**: Allows suppression of specific findings via unique IDs (UIDs) stored in `ignore.json`.
- **Verbose Logging**: Provides detailed debug logs for troubleshooting, saved to `cobra.log`.
- **Extensible**: Easily extendable with new rules and CVE patterns via `rules.py` and `cve_checker.py`.

## Installation

### Prerequisites

- **Python**: Version 3.8 or higher (tested with Python 3.13).
- **Dependencies**: `click`, `rich`, `requests`.
- **Operating System**: Windows, Linux, or macOS (tested on Windows).

### Steps

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/Sdsman16/CobRA.git
   cd CobRA
   ```

2. **Install Dependencies**:
   ```bash
   pip install click rich requests
   ```

3. **Uninstall Global `cobra` Package** (if installed):
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

4. **Clear Python Cache**:
   ```bash
   del /s /q C:\Users\sdson\PycharmProjects\CobRA\__pycache__
   del /s /q C:\Users\sdson\PycharmProjects\CobRA\cobra\__pycache__
   ```

5. **Update CVE Database**:
   Populate `cve_cache.json` with the latest CVE data:
   ```bash
   python -m cobra.cli update-cve-db
   ```
   Check `cobra.log` for:
   ```
   CVE database updated successfully. X CVEs cached.
   ```

## Usage

CobRA supports scanning individual `.cbl` files or directories for CVEs and vulnerabilities. Results include detailed findings with unique IDs (UIDs) for suppression.

### Commands

- **Scan Files or Directories**:
  Scan a COBOL file or directory for CVEs and vulnerabilities:
  ```bash
  python -m cobra.cli scan "path/to/file.cbl" --output=results.json --format=json
  ```
  ```bash
  python -m cobra.cli scan "path/to/directory" --verbose --output=results.sarif --format=sarif
  ```

- **Update CVE Database**:
  Refresh the local CVE cache from the NVD API:
  ```bash
  python -m cobra.cli update-cve-db
  ```

- **Ignore a Finding**:
  Add a finding’s UID to the ignore list:
  ```bash
  python -m cobra.cli ignore "abc123" --file="path/to/file.cbl" --vulnerability="CVE-2019-14468" --line=10 --code-snippet="MOVE ..."
  ```

- **List Ignored Findings**:
  View or prune ignored findings:
  ```bash
  python -m cobra.cli ignore-list
  ```
  ```bash
  python -m cobra.cli ignore-list --prune
  ```

### Options for `scan`

- `--output=<filename>`: Save results to a file (JSON or SARIF).
- `--format=<json|sarif>`: Output format (default: console).
- `--line-tolerance=<int>`: Line number tolerance for matching ignored findings (default: 10).
- `--quiet`: Suppress non-critical console output.
- `--verbose`: Show detailed debug logs.
- `--no-update`: Skip automatic CVE database update.

### Example Output

```
[Debug] Starting scan_directory
cobra found 28 issues:
HIGH - buffer_overflow.cbl (line 3): Keyword match for CVE-2019-14468: ... (UID: 7a907042..., CVSS: 7.5)
MEDIUM - buffer_overflow.cbl (line 19): Use of ACCEPT statement (unvalidated input). ... (UID: 55640145..., CVSS: 0.0)
[Info] Found 25 CVE-related issues.
[Info] Found 3 vulnerability issues.
[Info] Total findings after ignoring: 28
[Success] Results have been saved to: results.json
```

## Troubleshooting

- **Global Package Conflict**:
  If CobRA runs via `cobra.exe` instead of local files:
  - Verify: `python -c "import cobra; print(cobra.__file__)"` should point to `C:\Users\sdson\PycharmProjects\CobRA\cobra\__init__.py`.
  - Re-run uninstall steps above.

- **Empty CVE Database**:
  If no CVEs are detected:
  - Run: `python -m cobra.cli update-cve-db`.
  - Check `cve_cache.json` for CVEs (e.g., `CVE-2019-14468`).
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
  If fewer findings than expected:
  - Ensure `cve_cache.json` is updated.
  - Use `--verbose` to debug rules and matches.
  - Check `cobra.log` for errors like `Failed to fetch CVE data`.

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