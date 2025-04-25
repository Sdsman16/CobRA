import re
import logging

# Configure logging
logging.basicConfig(level=logging.DEBUG, filename="cobra.log", format="%(asctime)s - %(levelname)s - %(message)s")


def run_rules(code, filename, cves):
    """
    Apply rules to detect CVEs and vulnerabilities in COBOL code.

    Args:
        code (str): COBOL source code.
        filename (str): Path to the COBOL file.
        cves (list): List of CVE dictionaries with id, keywords, summary, and optional cvss_score.

    Returns:
        list: List of findings with file, line, message, severity, vulnerability, and optional cvss_score.
    """
    findings = []
    lines = code.splitlines()

    # Log cves structure for debugging
    logging.debug(f"cves structure: {cves[:2]}")

    # COBOL-specific vulnerability patterns
    vuln_patterns = [
        {
            "vulnerability": "Unvalidated Input",
            "pattern": r"ACCEPT\s+[A-Z0-9-]+",
            "message": "Use of ACCEPT statement (unvalidated input). Consider validating input length.",
            "severity": "Medium"
        },
        {
            "vulnerability": "Hardcoded Value",
            "pattern": r"MOVE\s+['\"][^'\"]+['\"]\s+TO\s+[A-Z0-9-]+",
            "message": "Hardcoded value assigned (possible sensitive data). Use external configuration.",
            "severity": "High"
        },
        {
            "vulnerability": "Insecure File Operation",
            "pattern": r"OPEN\s+(INPUT|OUTPUT|I-O)\s+[A-Z0-9-]+",
            "message": "Insecure file OPEN without validation. Validate file paths and permissions.",
            "severity": "Medium"
        },
        {
            "vulnerability": "Dynamic Call",
            "pattern": r"CALL\s+['\"][A-Z0-9-]+['\"]",
            "message": "Dynamic CALL with unvalidated input. Sanitize inputs to prevent code injection.",
            "severity": "High"
        },
        {
            "vulnerability": "Hardcoded Credentials",
            "pattern": r"(USER-ID|PASSWORD)\s*=\s*['\"][^'\"]+['\"]",
            "message": "Hardcoded credentials detected. Store credentials securely outside the codebase.",
            "severity": "High"
        }
    ]

    # Scan for COBOL vulnerabilities
    for pattern in vuln_patterns:
        for i, line in enumerate(lines, 1):
            if re.search(pattern["pattern"], line, re.IGNORECASE):
                findings.append({
                    "file": filename,
                    "line": i,
                    "message": pattern["message"],
                    "severity": pattern["severity"],
                    "vulnerability": pattern["vulnerability"]
                })
                logging.debug(f"Found {pattern['vulnerability']} at {filename}:{i}")

    # CVE-specific patterns
    cve_patterns = [
        {
            "id": "CVE-2019-14468",
            "pattern": r"(PROGRAM-ID\.|WORKING-STORAGE\s+SECTION\.|MOVE\s+[A-Z0-9-]+\s+TO\s+[A-Z0-9-]+|ACCEPT\s+[A-Z0-9-]+|PROCEDURE\s+DIVISION\.|PERFORM\s+[A-Z0-9-]+|DATA\s+DIVISION\.)",
            "message": "Keyword match for CVE-2019-14468: GnuCOBOL 2.2 buffer overflow in cb_push_op in cobc/field.c via crafted COBOL source code.",
            "severity": "High"
        },
        {
            "id": "CVE-2019-14486",
            "pattern": r"(PROGRAM-ID\.|WORKING-STORAGE\s+SECTION\.|MOVE\s+[A-Z0-9-]+\s+TO\s+[A-Z0-9-]+|PROCEDURE\s+DIVISION\.|PERFORM\s+[A-Z0-9-]+|DATA\s+DIVISION\.)",
            "message": "Keyword match for CVE-2019-14486: GnuCOBOL 2.2 buffer overflow in cb_evaluate_expr in cobc/field.c via crafted COBOL source code.",
            "severity": "High"
        },
        {
            "id": "CVE-2019-14528",
            "pattern": r"(PROGRAM-ID\.|WORKING-STORAGE\s+SECTION\.|MOVE\s+[A-Z0-9-]+\s+TO\s+[A-Z0-9-]+|PROCEDURE\s+DIVISION\.|PERFORM\s+[A-Z0-9-]+|DATA\s+DIVISION\.)",
            "message": "Keyword match for CVE-2019-14528: GnuCOBOL 2.2 heap-based buffer overflow in read_literal in cobc/scanner.l via crafted COBOL source code.",
            "severity": "High"
        },
        {
            "id": "CVE-2019-14541",
            "pattern": r"(PROGRAM-ID\.|WORKING-STORAGE\s+SECTION\.|MOVE\s+[A-Z0-9-]+\s+TO\s+[A-Z0-9-]+|PROCEDURE\s+DIVISION\.|PERFORM\s+[A-Z0-9-]+|DATA\s+DIVISION\.)",
            "message": "Keyword match for CVE-2019-14541: GnuCOBOL 2.2 stack-based buffer overflow in cb_encode_program_id in cobc/typeck.c via crafted COBOL source code.",
            "severity": "High"
        },
        {
            "id": "CVE-2019-16395",
            "pattern": r"(PROGRAM-ID\.|WORKING-STORAGE\s+SECTION\.|MOVE\s+[A-Z0-9-]+\s+TO\s+[A-Z0-9-]+|ACCEPT\s+[A-Z0-9-]+|PROCEDURE\s+DIVISION\.|PERFORM\s+[A-Z0-9-]+|DATA\s+DIVISION\.)",
            "message": "Keyword match for CVE-2019-16395: GnuCOBOL 2.2 stack-based buffer overflow in cb_name() in cobc/tree.c via crafted COBOL source code.",
            "severity": "High"
        },
        {
            "id": "CVE-2023-4501",
            "pattern": r"(ACCEPT\s+[A-Z0-9-]+|USER-ID|PASSWORD)",
            "message": "Keyword match for CVE-2023-4501: Ineffective authentication in OpenText (Micro Focus) Visual COBOL.",
            "severity": "High"
        },
        {
            "id": "CVE-2012-0918",
            "pattern": r"(PROGRAM-ID\.|PROCEDURE\s+DIVISION\.)",
            "message": "Keyword match for CVE-2012-0918: Unspecified vulnerability in Hitachi COBOL2002 Net Developer.",
            "severity": "High"
        },
        {
            "id": "CVE-2012-4274",
            "pattern": r"(PROGRAM-ID\.|PROCEDURE\s+DIVISION\.)",
            "message": "Keyword match for CVE-2012-4274: Unspecified vulnerability in Hitachi Cobol GUI Option.",
            "severity": "High"
        },
        {
            "id": "CVE-2023-32265",
            "pattern": r"(PROGRAM-ID\.|PROCEDURE\s+DIVISION\.)",
            "message": "Keyword match for CVE-2023-32265: Security vulnerability in Enterprise Server Common Web Administration (ESCWA).",
            "severity": "High"
        },
        {
            "id": "CVE-2001-0208",
            "pattern": r"(PROGRAM-ID\.|WORKING-STORAGE\s+SECTION\.)",
            "message": "Keyword match for CVE-2001-0208: MicroFocus Cobol 4.1 insecure permissions.",
            "severity": "High"
        }
    ]

    # Scan for CVEs using specific patterns
    for pattern in cve_patterns:
        if any(cve["id"] == pattern["id"] for cve in cves):
            for i, line in enumerate(lines, 1):
                if re.search(pattern["pattern"], line, re.IGNORECASE):
                    cve_data = next((c for c in cves if c["id"] == pattern["id"]), {})
                    findings.append({
                        "file": filename,
                        "line": i,
                        "message": pattern["message"],
                        "severity": pattern["severity"],
                        "vulnerability": pattern["id"],
                        "cvss_score": cve_data.get("cvss_score", 0.0)
                    })
                    logging.debug(f"Found CVE {pattern['id']} at {filename}:{i}")

    # Fallback: Scan for CVEs using keywords
    seen_findings = set()  # Track findings to avoid duplicates
    for cve in cves:
        for keyword in cve.get("keywords", []):
            for i, line in enumerate(lines, 1):
                if re.search(r'\b' + re.escape(keyword) + r'\b', line, re.IGNORECASE):
                    finding_key = (filename, cve["id"], i)
                    if finding_key not in seen_findings:
                        findings.append({
                            "file": filename,
                            "line": i,
                            "message": f"Keyword match for {cve['id']}: {cve['summary']}",
                            "severity": "High",
                            "vulnerability": cve["id"],
                            "cvss_score": cve.get("cvss_score", 0.0)
                        })
                        seen_findings.add(finding_key)
                        logging.debug(f"Found CVE {cve['id']} via keyword '{keyword}' at {filename}:{i}")

    logging.debug(f"run_rules found {len(findings)} issues in {filename}")
    return findings