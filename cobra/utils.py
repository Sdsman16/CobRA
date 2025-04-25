import os
import hashlib

def is_cobol_file(filename):
    """Check if a file is a COBOL file based on its extension."""
    return filename.lower().endswith((".cbl", ".cob", ".cpy"))

def generate_uid(file_path, vulnerability, line_number, code_snippet):
    """Generate a deterministic UID based on file, vulnerability, and code snippet."""
    # Use relative path to handle directory moves
    relative_path = os.path.relpath(file_path, os.getcwd())
    # Combine attributes into a stable string
    uid_string = f"{relative_path}:{vulnerability}:{line_number}:{code_snippet}"
    # Generate SHA-256 hash
    return hashlib.sha256(uid_string.encode()).hexdigest()