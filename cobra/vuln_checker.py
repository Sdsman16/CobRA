import re


def check_for_xss(cobol_code):
    """Check for potential XSS vulnerabilities in COBOL code."""
    xss_patterns = [
        re.compile(r'MOVE\s+"<script.*>.*</script>"\s*TO\s+\w+', re.IGNORECASE),
        re.compile(r'ACCEPT\s+\w+\s*FROM\s+USER', re.IGNORECASE),
        re.compile(r'MOVE\s+"<.*on\w+=[^>]+>.*</.*>"\s*TO\s+\w+', re.IGNORECASE)
    ]

    issues = []

    for pattern in xss_patterns:
        matches = pattern.findall(cobol_code)
        if matches:
            issues.append(f"Potential XSS vulnerability found with pattern: {pattern.pattern}")

    return issues


def check_for_sql_injection(cobol_code):
    """Check for SQL Injection vulnerabilities in COBOL code."""
    sql_patterns = [
        re.compile(r'MOVE\s+".*SELECT.*WHERE.*TO\s+\w+', re.IGNORECASE),  # Basic SQL query pattern
        re.compile(r'MOVE\s+".*DROP\s+TABLE.*TO\s+\w+', re.IGNORECASE),  # Potential Drop table statement
        re.compile(r'MOVE\s+".*UNION\s+SELECT.*TO\s+\w+', re.IGNORECASE),  # SQL Injection with UNION SELECT
    ]

    issues = []

    for pattern in sql_patterns:
        matches = pattern.findall(cobol_code)
        if matches:
            issues.append(f"Potential SQL Injection vulnerability found with pattern: {pattern.pattern}")

    return issues


def check_for_command_injection(cobol_code):
    """Check for Command Injection vulnerabilities in COBOL code."""
    command_patterns = [
        re.compile(r'MOVE\s+".*system\s*\(\s*[^)]*\)\s*TO\s+\w+', re.IGNORECASE),
        # system() function (command execution)
        re.compile(r'MOVE\s+".*exec\s*\(\s*[^)]*\)\s*TO\s+\w+', re.IGNORECASE),  # exec() function (command execution)
    ]

    issues = []

    for pattern in command_patterns:
        matches = pattern.findall(cobol_code)
        if matches:
            issues.append(f"Potential Command Injection vulnerability found with pattern: {pattern.pattern}")

    return issues


def check_for_insecure_cryptographic_storage(cobol_code):
    """Check for Insecure Cryptographic Storage vulnerabilities in COBOL code."""
    cryptographic_patterns = [
        re.compile(r'MOVE\s+".*BASE64\s*ENCODE\s*\(.*\)\s*TO\s+\w+', re.IGNORECASE),
        # Base64 encoding (not secure storage)
        re.compile(r'MOVE\s+".*DES\s*ENCRYPT\s*\(.*\)\s*TO\s+\w+', re.IGNORECASE),  # Using DES (a weak algorithm)
        re.compile(r'MOVE\s+".*MD5\s*HASH\s*\(.*\)\s*TO\s+\w+', re.IGNORECASE),  # MD5 hashing (considered insecure)
        re.compile(r'MOVE\s+".*SHA1\s*HASH\s*\(.*\)\s*TO\s+\w+', re.IGNORECASE),  # SHA1 hashing (considered insecure)
    ]

    issues = []

    for pattern in cryptographic_patterns:
        matches = pattern.findall(cobol_code)
        if matches:
            issues.append(
                f"Potential Insecure Cryptographic Storage vulnerability found with pattern: {pattern.pattern}")

    return issues


def check_for_csrf(cobol_code):
    """Check for Cross-Site Request Forgery (CSRF) vulnerabilities in COBOL code."""
    csrf_patterns = [
        re.compile(r'MOVE\s+".*<form\s+action\s*=\s*\"[^\"]*\".*method\s*=\s*\"post\".*>"\s*TO\s+\w+', re.IGNORECASE),
        re.compile(
            r'MOVE\s+".*<input\s+type\s*=\s*\"hidden\".*name\s*=\s*\"[^\"]*\".*value\s*=\s*\"[^\"]*\".*>"\s*TO\s+\w+',
            re.IGNORECASE),
    ]

    issues = []

    for pattern in csrf_patterns:
        matches = pattern.findall(cobol_code)
        if matches:
            issues.append(f"Potential CSRF vulnerability found with pattern: {pattern.pattern}")

    return issues