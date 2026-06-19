"""
.gitignore scanner — detects dangerous files that exist in the repo
but are NOT covered by .gitignore rules.
"""
import os
import fnmatch
from typing import List, Set
from ..models import Finding

# Files that MUST be gitignored if they exist
MUST_IGNORE = [
    (".env",                   "CRITICAL", "Credentials file .env is not gitignored — it will be committed"),
    (".env.local",             "CRITICAL", ".env.local is not gitignored"),
    (".env.production",        "CRITICAL", ".env.production is not gitignored"),
    (".env.staging",           "HIGH",     ".env.staging is not gitignored"),
    (".envrc",                 "HIGH",     ".envrc is not gitignored"),
    ("*.pem",                  "CRITICAL", "PEM certificate/key files are not gitignored"),
    ("*.key",                  "HIGH",     "Private key files (*.key) are not gitignored"),
    ("*.p12",                  "CRITICAL", "PKCS#12 keystore files are not gitignored"),
    ("id_rsa",                 "CRITICAL", "SSH private key id_rsa is not gitignored"),
    ("id_ed25519",             "CRITICAL", "SSH private key id_ed25519 is not gitignored"),
    ("*.tfvars",               "HIGH",     "Terraform variable files (*.tfvars) may contain secrets and are not gitignored"),
    ("terraform.tfstate",      "CRITICAL", "Terraform state file exposes infrastructure secrets — not gitignored"),
    ("terraform.tfstate.backup","HIGH",    "Terraform state backup is not gitignored"),
    ("*.log",                  "LOW",      "Log files are not gitignored — may contain sensitive runtime data"),
    ("*.sqlite",               "MEDIUM",   "SQLite database files are not gitignored"),
    ("*.sqlite3",              "MEDIUM",   "SQLite3 database files are not gitignored"),
    ("secrets.json",           "CRITICAL", "secrets.json is not gitignored"),
    ("credentials.json",       "CRITICAL", "credentials.json is not gitignored"),
    ("service-account*.json",  "CRITICAL", "Google service account key file is not gitignored"),
    (".DS_Store",              "LOW",      ".DS_Store macOS metadata is not gitignored"),
    ("node_modules/",          "LOW",      "node_modules/ is not gitignored — bloats repo"),
    ("__pycache__/",           "LOW",      "__pycache__/ is not gitignored"),
    (".venv/",                 "LOW",      ".venv/ virtualenv directory is not gitignored"),
    ("venv/",                  "LOW",      "venv/ virtualenv directory is not gitignored"),
    ("dist/",                  "LOW",      "dist/ build output is not gitignored"),
]


def _load_gitignore_patterns(repo_path: str) -> Set[str]:
    """Read all .gitignore files and return raw patterns."""
    patterns = set()
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d != '.git']
        if '.gitignore' in files:
            gi_path = os.path.join(root, '.gitignore')
            try:
                with open(gi_path, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            patterns.add(line)
            except (OSError, PermissionError):
                pass
    return patterns


def _is_ignored(filename: str, patterns: Set[str]) -> bool:
    """Check if a filename/pattern matches any gitignore rule."""
    basename = os.path.basename(filename)
    for pat in patterns:
        # Direct match
        if pat == filename or pat == basename:
            return True
        # Glob match
        if fnmatch.fnmatch(basename, pat):
            return True
        if fnmatch.fnmatch(filename, pat):
            return True
        # Directory patterns
        if pat.endswith('/') and (basename + '/') == pat:
            return True
        # Wildcard like *.env
        if fnmatch.fnmatch(basename, pat.lstrip('/')):
            return True
    return False


def _find_existing_files(repo_path: str, pattern: str) -> List[str]:
    """Find files in repo matching a pattern."""
    matches = []
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in {'.git', 'node_modules', '__pycache__'}]
        all_entries = files + [d + '/' for d in dirs]
        for entry in all_entries:
            if fnmatch.fnmatch(entry, pattern) or fnmatch.fnmatch(entry.rstrip('/'), pattern.rstrip('/')):
                rel = os.path.relpath(os.path.join(root, entry), repo_path)
                matches.append(rel)
    return matches


def scan_gitignore(path: str) -> List[Finding]:
    findings = []

    # Check if .gitignore even exists
    gitignore_exists = os.path.exists(os.path.join(path, '.gitignore'))
    if not gitignore_exists:
        findings.append(Finding(
            severity="HIGH",
            message="No .gitignore file found in repository root",
            file=".gitignore",
            scanner="gitignore",
            detail="Without .gitignore, secrets, keys, and build artifacts may be committed accidentally.",
        ))
        patterns = set()
    else:
        patterns = _load_gitignore_patterns(path)

    for file_pattern, severity, message in MUST_IGNORE:
        existing = _find_existing_files(path, file_pattern)
        for rel_path in existing:
            # Check if it's covered by gitignore
            basename = os.path.basename(rel_path)
            if not _is_ignored(basename, patterns) and not _is_ignored(rel_path, patterns) \
               and not _is_ignored(file_pattern, patterns):
                findings.append(Finding(
                    severity=severity,
                    message=message,
                    file=rel_path,
                    scanner="gitignore",
                    detail=f"File '{rel_path}' exists in repository but has no matching .gitignore rule. "
                           f"Add '{file_pattern}' to .gitignore immediately.",
                ))

    return findings
