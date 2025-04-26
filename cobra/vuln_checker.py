import re


def check_for_xss(code):
    """Check for potential XSS vulnerabilities in COBOL code."""
    issues = []
    if "DISPLAY" in code.upper():
        # Simplified check: DISPLAY statements with variables might be used in web output
        lines = code.split("\n")
        for i, line in enumerate(lines, 1):
            if "DISPLAY" in line.upper() and "X'" not in line.upper():
                issues.append(f"Potential XSS: Unsanitized DISPLAY statement at line {i}")
    return issues


def check_for_sql_injection(code):
    """Check for potential SQL injection vulnerabilities in COBOL code."""
    issues = []
    if "EXEC SQL" in code.upper():
        lines = code.split("\n")
        for i, line in enumerate(lines, 1):
            if "EXEC SQL" in line.upper() and ":" in line:
                # Check for host variables that might contain user input
                issues.append(f"Potential SQL Injection: Dynamic SQL with host variable at line {i}")
    return issues


def check_for_command_injection(code):
    """Check for potential command injection vulnerabilities in COBOL code."""
    issues = []
    lines = code.split("\n")
    for i, line in enumerate(lines, 1):
        if "CALL" in line.upper() and '"' not in line and "'" not in line:
            # Dynamic CALL with a variable program name
            issues.append(f"Potential Command Injection: Dynamic CALL statement at line {i}")
    return issues


def check_for_insecure_cryptographic_storage(code):
    """Check for insecure cryptographic storage in COBOL code."""
    issues = []
    lines = code.split("\n")
    for i, line in enumerate(lines, 1):
        if "MOVE" in line.upper() and ("KEY" in line.upper() or "PASSWORD" in line.upper()):
            issues.append(f"Potential Insecure Cryptographic Storage: Hardcoded key or password at line {i}")
    return issues


def check_for_csrf(code):
    """Check for potential CSRF vulnerabilities in COBOL code."""
    issues = []
    if "EXEC CICS" in code.upper() and "WEB" in code.upper():
        lines = code.split("\n")
        for i, line in enumerate(lines, 1):
            if "EXEC CICS WEB" in line.upper() and "TOKEN" not in line.upper():
                issues.append(f"Potential CSRF: Missing CSRF token in CICS web interaction at line {i}")
    return issues


def check_for_file_handling_vulnerabilities(code):
    """Check for file handling vulnerabilities in COBOL code."""
    issues = []
    lines = code.split("\n")

    # Track open files to detect missing CLOSE statements
    open_files = set()
    file_vars = {}

    for i, line in enumerate(lines, 1):
        line_upper = line.upper()

        # Detect dynamic file names in SELECT statements
        if "SELECT" in line_upper and "ASSIGN TO" in line_upper:
            # Extract the file variable name after ASSIGN TO
            match = re.search(r"ASSIGN\s+TO\s+(\w+)", line_upper)
            if match:
                file_var = match.group(1)
                file_vars[file_var] = i
                # Check if the file name is a variable (not a literal)
                if '"' not in line and "'" not in line:
                    issues.append(f"Potential File Traversal: Dynamic file name in SELECT statement at line {i}")

        # Track OPEN statements
        if "OPEN" in line_upper:
            for file_var in file_vars.keys():
                if file_var in line_upper:
                    open_files.add(file_var)

        # Track CLOSE statements
        if "CLOSE" in line_upper:
            for file_var in list(open_files):
                if file_var in line_upper:
                    open_files.remove(file_var)

    # Report files that were opened but not closed
    for file_var in open_files:
        line_num = file_vars.get(file_var, "unknown")
        issues.append(
            f"Potential Resource Exhaustion: File {file_var} opened but not closed (SELECT at line {line_num})")

    return issues


def check_for_hardcoded_sensitive_data(code):
    """Check for hardcoded sensitive data in COBOL code."""
    issues = []
    lines = code.split("\n")
    in_working_storage = False

    for i, line in enumerate(lines, 1):
        line_upper = line.upper()

        # Detect WORKING-STORAGE SECTION
        if "WORKING-STORAGE SECTION" in line_upper:
            in_working_storage = True
        elif in_working_storage and "SECTION" in line_upper and "WORKING-STORAGE" not in line_upper:
            in_working_storage = False

        # Check for hardcoded sensitive data
        if in_working_storage or "MOVE" in line_upper:
            if any(keyword in line_upper for keyword in ["PASSWORD", "KEY", "SECRET", "SSN", "CREDIT"]):
                issues.append(f"Potential Hardcoded Sensitive Data: Possible credential or sensitive data at line {i}")
            # Check for patterns like SSNs (e.g., 123-45-6789)
            ssn_pattern = r"\d{3}-\d{2}-\d{4}"
            if re.search(ssn_pattern, line):
                issues.append(f"Potential Hardcoded Sensitive Data: SSN pattern detected at line {i}")

    return issues


def check_for_arithmetic_overflows(code):
    """Check for potential arithmetic overflows in COBOL code."""
    issues = []
    lines = code.split("\n")

    for i, line in enumerate(lines, 1):
        line_upper = line.upper()

        # Check for arithmetic operations without bounds checking
        if any(op in line_upper for op in ["COMPUTE", "ADD", "SUBTRACT", "MULTIPLY", "DIVIDE"]):
            # Simplified check: Look for operations without ON SIZE ERROR
            if "ON SIZE ERROR" not in line_upper:
                issues.append(
                    f"Potential Arithmetic Overflow: Missing ON SIZE ERROR in arithmetic operation at line {i}")

        # Check for divide-by-zero
        if "DIVIDE" in line_upper:
            # Look for preceding lines to check for zero validation
            if i > 1 and "IF" not in lines[i - 2].upper() and "NOT = 0" not in lines[i - 2].upper():
                issues.append(f"Potential Divide-by-Zero: Missing divisor check in DIVIDE statement at line {i}")

    return issues


def check_for_insecure_data_transmission(code):
    """Check for insecure data transmission in COBOL code."""
    issues = []
    lines = code.split("\n")

    for i, line in enumerate(lines, 1):
        line_upper = line.upper()

        # Check for network-related CALLs or CICS web interactions
        if ("CALL" in line_upper and "NETWORK" in line_upper) or ("EXEC CICS WEB" in line_upper):
            if "SSL" not in line_upper and "HTTPS" not in line_upper:
                issues.append(
                    f"Potential Insecure Data Transmission: Missing SSL/HTTPS in network interaction at line {i}")

    return issues


def check_for_improper_error_handling(code):
    """Check for improper error handling in COBOL code."""
    issues = []
    lines = code.split("\n")

    for i, line in enumerate(lines, 1):
        line_upper = line.upper()

        # Check for READ, WRITE, CALL without error handling
        if any(op in line_upper for op in ["READ", "WRITE", "CALL"]):
            if "ON ERROR" not in line_upper and "AT END" not in line_upper:
                issues.append(f"Potential Improper Error Handling: Missing ON ERROR or AT END clause at line {i}")

        # Check for DISPLAY in error handling blocks
        if "ON ERROR" in line_upper and "DISPLAY" in line_upper:
            issues.append(f"Potential Information Disclosure: DISPLAY in error handling block at line {i}")

    return issues


def check_for_insecure_session_management(code):
    """Check for insecure session management in COBOL code."""
    issues = []
    lines = code.split("\n")
    in_working_storage = False

    for i, line in enumerate(lines, 1):
        line_upper = line.upper()

        # Detect WORKING-STORAGE SECTION
        if "WORKING-STORAGE SECTION" in line_upper:
            in_working_storage = True
        elif in_working_storage and "SECTION" in line_upper and "WORKING-STORAGE" not in line_upper:
            in_working_storage = False

        # Check for session-related variables
        if in_working_storage and "SESSION" in line_upper:
            issues.append(
                f"Potential Insecure Session Management: Session variable detected; ensure regeneration per session at line {i}")

        # Check for CICS/IMS web interactions without token
        if ("EXEC CICS" in line_upper or "EXEC IMS" in line_upper) and "WEB" in line_upper:
            if "TOKEN" not in line_upper:
                issues.append(
                    f"Potential Insecure Session Management: Missing session token in web interaction at line {i}")

    return issues