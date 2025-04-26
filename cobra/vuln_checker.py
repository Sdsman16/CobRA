import re


def check_for_xss(code):
    """Check for potential XSS vulnerabilities in COBOL code."""
    issues = []
    if "DISPLAY" in code.upper():
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
                issues.append(f"Potential SQL Injection: Dynamic SQL with host variable at line {i}")
    return issues


def check_for_command_injection(code):
    """Check for potential command injection vulnerabilities in COBOL code with improved detection."""
    issues = []
    lines = code.split("\n")

    # Track variables and their assignments
    variables = {}  # {var_name: (value, line_num, is_user_input)}

    # First pass: Track variable assignments and user input
    for i, line in enumerate(lines, 1):
        line_upper = line.upper().strip()

        # Track variables assigned via MOVE
        move_match = re.search(r"MOVE\s+(.+?)\s+TO\s+(\w+)", line_upper)
        if move_match:
            value = move_match.group(1).strip()
            var_name = move_match.group(2).strip()
            is_user_input = False
            # Check if the value is a literal or variable
            if '"' in value or "'" in value:
                # Literal value
                value = value.replace('"', '').replace("'", '')
            else:
                # Variable or computed value; check if it's user-controlled
                if value in variables and variables[value][2]:
                    is_user_input = True
            variables[var_name] = (value, i, is_user_input)

        # Track variables assigned via ACCEPT (user input)
        if "ACCEPT" in line_upper:
            accept_match = re.search(r"ACCEPT\s+(\w+)", line_upper)
            if accept_match:
                var_name = accept_match.group(1).strip()
                variables[var_name] = ("<user_input>", i, True)

    # Second pass: Analyze CALL statements
    for i, line in enumerate(lines, 1):
        line_upper = line.upper().strip()

        # Detect dynamic CALL statements
        if "CALL" in line_upper:
            # Extract the program name after CALL
            call_match = re.search(r"CALL\s+(\w+)", line_upper)
            if call_match:
                prog_var = call_match.group(1).strip()
                # Check if the program name is a variable (not a literal)
                if '"' not in line and "'" not in line:
                    # Check if the variable is tracked
                    if prog_var in variables:
                        var_info = variables[prog_var]
                        source = var_info[0]
                        is_user_input = var_info[2]
                        has_injection_pattern = False

                        # Check for command injection patterns in the value (if literal)
                        if not source.startswith("<"):
                            has_injection_pattern = any(
                                pattern in source.lower() for pattern in ["&", "|", ";", "&&", "||"])

                        # Determine severity and message
                        if is_user_input:
                            severity = "High" if has_injection_pattern else "Medium"
                            issues.append(
                                f"Potential Command Injection: Dynamic CALL with user-controlled program name at line {i} (Severity: {severity})")
                        else:
                            # Variable but not user-controlled; check for injection patterns
                            if has_injection_pattern:
                                issues.append(
                                    f"Potential Command Injection: Program name contains injection pattern in CALL statement at line {i} (Severity: Low)")
                            # If no user input and no patterns, don't flag (reduces false positives)
                    else:
                        # Untracked variable; conservatively flag as potential issue
                        issues.append(
                            f"Potential Command Injection: Untracked dynamic program name in CALL statement at line {i} (Severity: Medium)")

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
    """Check for file handling vulnerabilities in COBOL code with improved file traversal detection."""
    issues = []
    lines = code.split("\n")

    # Track file variables and their line numbers
    file_vars = {}  # {file_var: (line_num, is_dynamic, source)}
    open_files = set()  # Track opened files for resource exhaustion
    variables = {}  # Track variable assignments {var_name: (value, line_num, is_user_input)}

    # First pass: Track variable assignments and user input
    for i, line in enumerate(lines, 1):
        line_upper = line.upper().strip()

        # Track variables assigned via MOVE
        move_match = re.search(r"MOVE\s+(.+?)\s+TO\s+(\w+)", line_upper)
        if move_match:
            value = move_match.group(1).strip()
            var_name = move_match.group(2).strip()
            is_user_input = False
            # Check if the value is a literal or variable
            if '"' in value or "'" in value:
                # Literal value
                value = value.replace('"', '').replace("'", '')
            else:
                # Variable or computed value; check if it's user-controlled
                if value in variables and variables[value][2]:
                    is_user_input = True
            variables[var_name] = (value, i, is_user_input)

        # Track variables assigned via ACCEPT (user input)
        if "ACCEPT" in line_upper:
            accept_match = re.search(r"ACCEPT\s+(\w+)", line_upper)
            if accept_match:
                var_name = accept_match.group(1).strip()
                variables[var_name] = ("<user_input>", i, True)

    # Second pass: Analyze SELECT and file operations
    for i, line in enumerate(lines, 1):
        line_upper = line.upper().strip()

        # Detect dynamic file names in SELECT statements
        if "SELECT" in line_upper and "ASSIGN TO" in line_upper:
            match = re.search(r"ASSIGN\s+TO\s+(\w+)", line_upper)
            if match:
                file_var = match.group(1).strip()
                is_dynamic = False
                source = "unknown"
                has_traversal_pattern = False

                # Check if the file name is a variable
                if file_var in variables:
                    is_dynamic = True
                    var_info = variables[file_var]
                    source = var_info[0]
                    is_user_input = var_info[2]
                    # Check for path traversal patterns in the value (if literal)
                    if not source.startswith("<"):
                        has_traversal_pattern = any(
                            pattern in source.lower() for pattern in ["../", "..\\", "/etc/", "\\windows\\"])
                    # If user input, assume potential for traversal
                    if is_user_input:
                        file_vars[file_var] = (i, True, "user_input")
                        severity = "High" if has_traversal_pattern else "Medium"
                        issues.append(
                            f"Potential File Traversal: Dynamic file name from user input in SELECT statement at line {i} (Severity: {severity})")
                    else:
                        # Variable but not user-controlled; check for traversal patterns
                        if has_traversal_pattern:
                            file_vars[file_var] = (i, True, source)
                            issues.append(
                                f"Potential File Traversal: File name contains traversal pattern in SELECT statement at line {i}")
                        else:
                            file_vars[file_var] = (i, False, source)
                else:
                    # Not a variable we tracked; check if it's a literal with quotes
                    if '"' not in line and "'" not in line:
                        file_vars[file_var] = (i, True, "untracked_variable")
                        issues.append(
                            f"Potential File Traversal: Untracked dynamic file name in SELECT statement at line {i}")
                    else:
                        file_vars[file_var] = (i, False, "literal")

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
        line_num, is_dynamic, source = file_vars.get(file_var, (None, False, None))
        if line_num and is_dynamic:
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
            if "ON SIZE ERROR" not in line_upper:
                issues.append(
                    f"Potential Arithmetic Overflow: Missing ON SIZE ERROR in arithmetic operation at line {i}")

        # Check for divide-by-zero
        if "DIVIDE" in line_upper:
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