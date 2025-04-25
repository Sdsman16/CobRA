import re

def run_rules(code, filename, cves):
    findings = []

    for i, line in enumerate(code.splitlines(), 1):
        if re.search(r'ACCEPT\s+[A-Z0-9-]+', line, re.IGNORECASE):
            findings.append({
                "file": filename,
                "line": i,
                "message": "Use of ACCEPT statement (unvalidated input)",
                "severity": "medium"
            })

        if re.search(r'MOVE\s+"[^"]+"\s+TO\s+([A-Z0-9-]+)', line, re.IGNORECASE):
            findings.append({
                "file": filename,
                "line": i,
                "message": "Hardcoded value assigned (possible sensitive data)",
                "severity": "high"
            })

        # CVE Matching (keywords from CVE database)
        for cve in cves:
            for keyword in cve["keywords"]:
                if keyword.lower() in line.lower():
                    findings.append({
                        "file": filename,
                        "line": i,
                        "message": f"Keyword match for {cve['id']}: {cve['summary']}",
                        "severity": "high"
                    })

    return findings
