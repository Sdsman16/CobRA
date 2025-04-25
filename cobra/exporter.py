import json
import datetime

def export_results(findings, output_path, fmt):
    if fmt == "json":
        with open(output_path, "w") as f:
            json.dump(findings, f, indent=2)
    elif fmt == "sarif":
        sarif_output = generate_sarif(findings)
        with open(output_path, "w") as f:
            json.dump(sarif_output, f, indent=2)

def generate_sarif(findings):
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "CobRA",
                    "informationUri": "https://github.com/your/repo",
                    "rules": []
                }
            },
            "results": [
                {
                    "ruleId": f["type"],
                    "message": {"text": f["message"]},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": f["file"]},
                            "region": {"startLine": f.get("line", 1)}
                        }
                    }],
                    "level": severity_to_level(f["severity"])
                }
                for f in findings
            ]
        }]
    }

def severity_to_level(sev):
    return {
        "LOW": "note",
        "MEDIUM": "warning",
        "HIGH": "error"
    }.get(sev.upper(), "warning")
