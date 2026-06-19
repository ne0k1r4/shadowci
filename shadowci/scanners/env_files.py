import os
import re
from typing import List
from ..models import Finding

ENV_FILENAMES = {'.env', '.env.local', '.env.production', '.env.staging',
                 '.env.development', '.env.test', '.env.backup', '.env.bak',
                 '.env.example', '.env.sample', '.envrc'}
SKIP_DIRS = {'.git', 'node_modules', '__pycache__', '.venv', 'venv', 'dist', 'build'}
SENSITIVE_KEY_RE = re.compile(r'(?i)(password|passwd|secret|token|key|credential|auth|api_key)')


def _is_env_file(filename: str) -> bool:
    name = filename.lower()
    return name in ENV_FILENAMES or name.endswith('.env') or name.startswith('.env.')


def _severity_for_env(filename: str) -> str:
    name = filename.lower()
    return "LOW" if any(x in name for x in ('example', 'sample', 'template')) else "CRITICAL"


def scan_env_files(path: str) -> List[Finding]:
    findings = []
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for filename in files:
            if not _is_env_file(filename):
                continue
            filepath = os.path.join(root, filename)
            rel = os.path.relpath(filepath, path)
            sev = _severity_for_env(filename)
            findings.append(Finding(
                severity=sev,
                message=f"Environment file exposed: {filename}",
                file=rel, scanner="env",
                detail="Env files contain DB passwords, JWT secrets, API keys, OAuth credentials.",
                remediation=f"Add '{filename}' to .gitignore immediately. Use a secrets manager for production values.",
            ))
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    for lineno, line in enumerate(f, 1):
                        stripped = line.strip()
                        if not stripped or stripped.startswith('#'):
                            continue
                        m = re.match(r'^([A-Z_][A-Z0-9_]*)\s*=\s*(.+)$', stripped)
                        if m:
                            key, value = m.group(1), m.group(2).strip('"\'')
                            if SENSITIVE_KEY_RE.search(key) and value and \
                               value not in ('', 'your_value_here', 'changeme', 'CHANGEME', 'xxx', 'TODO', '<your_key>'):
                                findings.append(Finding(
                                    severity="CRITICAL",
                                    message=f"Sensitive value found in env file: {key}",
                                    file=rel, scanner="env", line=lineno,
                                    detail=f"Key '{key}' contains a real credential value.",
                                    remediation="Move to a secrets manager (Vault, AWS SSM, Doppler). Rotate the credential immediately.",
                                ))
            except (OSError, PermissionError):
                continue
    return findings
