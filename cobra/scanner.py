import os
from cobra.rules import run_rules
from cobra.utils import is_cobol_file
from rich.console import Console

console = Console()


def scan_directory(path, cves):
    results = []

    # If the path is a directory, walk through all files
    if os.path.isdir(path):
        for root, _, files in os.walk(path):
            for file in files:
                if is_cobol_file(file):
                    full_path = os.path.join(root, file)
                    try:
                        with open(full_path, "r", errors="ignore") as f:
                            code = f.read()
                        findings = run_rules(code, full_path, cves)
                        results.extend(findings)
                    except Exception as e:
                        console.print(f"[red]Error reading file {full_path}: {e}[/red]")

    # If the path is a file, scan that single file directly
    elif os.path.isfile(path):
        if is_cobol_file(path):  # Ensure it's a valid COBOL file
            try:
                with open(path, "r", errors="ignore") as f:
                    code = f.read()
                findings = run_rules(code, path, cves)
                results.extend(findings)
            except Exception as e:
                console.print(f"[red]Error reading file {path}: {e}[/red]")
        else:
            console.print(f"[red]Error: {path} is not a valid COBOL file![/red]")

    else:
        console.print(f"[red]Error: {path} is neither a valid file nor a directory![/red]")
        return

    # Output results
    if not results:
        console.print("[green]cobra found no vulnerabilities![/green]")
    else:
        console.print(f"[bold red]cobra found {len(results)} issues:[/bold red]")
        for finding in results:
            console.print(
                f"[red]{finding['severity'].upper()}[/red] - {finding['file']} (line {finding['line']}): {finding['message']}"
            )
