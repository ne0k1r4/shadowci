"""
File permissions scanner — detects world-writable files, executable
secrets, overly permissive scripts, and SUID/SGID bits.
"""
import os
import stat
from typing import List
from ..models import Finding

SKIP_DIRS = {'.git', 'node_modules', '__pycache__', '.venv', 'venv', 'dist', 'build'}

SENSITIVE_NAMES = {
    '.env', '.envrc', 'id_rsa', 'id_ed25519', 'id_dsa', 'id_ecdsa',
    'secrets.json', 'credentials.json', 'terraform.tfstate',
    'terraform.tfstate.backup', '.netrc', '.htpasswd',
}

SENSITIVE_PATTERNS = ['.env.', '.pem', '.key', '.p12', '.pfx', '.jks', '.keystore']


def _is_sensitive(filename: str) -> bool:
    name = os.path.basename(filename).lower()
    if name in SENSITIVE_NAMES:
        return True
    return any(pat in name for pat in SENSITIVE_PATTERNS)


def scan_permissions(path: str) -> List[Finding]:
    findings = []

    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

        for filename in files:
            filepath = os.path.join(root, filename)
            rel      = os.path.relpath(filepath, path)

            try:
                st   = os.stat(filepath)
                mode = st.st_mode
            except (OSError, PermissionError):
                continue

            # World-writable files
            if mode & stat.S_IWOTH:
                sev = "HIGH" if _is_sensitive(filename) else "MEDIUM"
                findings.append(Finding(
                    severity=sev,
                    message=f"World-writable file: {filename}",
                    file=rel, scanner="permissions",
                    detail=f"Permission {oct(mode)[-3:]} allows any user to modify this file.",
                    remediation=f"Run: chmod o-w {rel}",
                ))

            # Sensitive file with too-open permissions (not 600 or 400)
            if _is_sensitive(filename):
                perm_bits = mode & 0o777
                if perm_bits & 0o044:  # readable by group or other
                    findings.append(Finding(
                        severity="HIGH",
                        message=f"Sensitive file has overly permissive mode: {filename}",
                        file=rel, scanner="permissions",
                        detail=f"Mode {oct(perm_bits)} — group/others can read this sensitive file.",
                        remediation=f"Run: chmod 600 {rel}",
                    ))

            # Executable .env or secret files
            if _is_sensitive(filename) and (mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)):
                findings.append(Finding(
                    severity="MEDIUM",
                    message=f"Sensitive file has executable bit set: {filename}",
                    file=rel, scanner="permissions",
                    detail=f"Credential/config files should not be executable.",
                    remediation=f"Run: chmod a-x {rel}",
                ))

            # SUID or SGID bits
            if mode & (stat.S_ISUID | stat.S_ISGID):
                bit = "SUID" if mode & stat.S_ISUID else "SGID"
                findings.append(Finding(
                    severity="HIGH",
                    message=f"{bit} bit set on file: {filename}",
                    file=rel, scanner="permissions",
                    detail=f"{bit} allows the file to run with elevated privileges.",
                    remediation=f"Run: chmod u-s {rel}  # (or g-s for SGID). Rarely needed in repos.",
                ))

        # World-writable directories
        for dirname in dirs:
            dirpath = os.path.join(root, dirname)
            rel_dir = os.path.relpath(dirpath, path)
            try:
                st   = os.stat(dirpath)
                mode = st.st_mode
                if mode & stat.S_IWOTH:
                    findings.append(Finding(
                        severity="MEDIUM",
                        message=f"World-writable directory: {dirname}/",
                        file=rel_dir, scanner="permissions",
                        detail=f"Any user can create or delete files in this directory.",
                        remediation=f"Run: chmod o-w {rel_dir}",
                    ))
            except (OSError, PermissionError):
                continue

    return findings
