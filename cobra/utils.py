import hashlib
import os

def is_cobol_file(filename):
    """Check if the file has a COBOL extension."""
    return filename.lower().endswith(".cbl")

def generate_uid(file_path, vulnerability, line_number, code_snippet):
    """Generate a unique identifier for a finding."""
    data = f"{file_path}:{vulnerability}:{line_number}:{code_snippet}"
    return hashlib.sha256(data.encode()).hexdigest()