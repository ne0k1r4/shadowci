"""
shadowci/scanners/supply_chain.py — Supply Chain Security Scanner
Detects typosquatting, suspicious install scripts, dependency confusion,
and other supply chain attack vectors.
"""

import os
import re
import json
from typing import List
from ..models import Finding

SKIP_DIRS = {'.git', 'node_modules', '__pycache__', '.venv', 'venv'}

# Known typosquatted packages (name -> legitimate package)
TYPOSQUATS = {
    # Python
    "requets":       "requests",
    "reqeusts":      "requests",
    "request":       "requests",
    "urllib4":       "urllib3",
    "colourama":     "colorama",
    "coloramma":     "colorama",
    "djago":         "django",
    "djangoo":       "django",
    "flassk":        "flask",
    "pytohn":        "python",
    "numpyy":        "numpy",
    "pandaas":       "pandas",
    "scippy":        "scipy",
    "setuptool":     "setuptools",
    "setup-tools":   "setuptools",
    "pyyamll":       "pyyaml",
    "cryptograpy":   "cryptography",
    "pillow-imaging":"pillow",
    "python-jwt":    "PyJWT",
    "jwt-python":    "PyJWT",
    "boto":          "boto3",       # old version, often typosquatted
    "amazons3":      "boto3",
    "openssl-python":"pyopenssl",
    # JavaScript
    "cross-env2":    "cross-env",
    "lодаsh":        "lodash",
    "loadash":       "loadash",
    "reakt":         "react",
    "expresss":      "express",
    "expresjs":      "express",
    "mongooes":      "mongoose",
    "babelcli":      "babel-cli",
    "axois":         "axios",
    "chalk2":        "chalk",
    "npmtest":       "npm",
    "nodeenv2":      "nodeenv",
    "webpakc":       "webpack",
    "typescirpt":    "typescript",
    "eslint-config-airbn": "eslint-config-airbnb",
}

# Suspicious patterns in install scripts (setup.py, package.json scripts)
SUSPICIOUS_INSTALL_PATTERNS = [
    (re.compile(r'(?i)(?:curl|wget)\s+.*\|\s*(?:ba)?sh'),
     "CRITICAL", "Install script downloads and executes remote code",
     "Never pipe downloads to shell. Verify checksums before executing."),

    (re.compile(r'(?i)(?:curl|wget|requests\.get|urllib)\s+.*(?:http|https)://(?!pypi|npmjs|github\.com/|raw\.githubusercontent\.com/)'),
     "HIGH", "Install script makes HTTP request to untrusted host",
     "Audit all network calls in setup.py/install scripts."),

    (re.compile(r'\bbase64\.b64decode\s*\('),
     "HIGH", "Install script uses base64 decode — possible obfuscated payload",
     "Investigate all base64-encoded content in install scripts."),

    (re.compile(r'(?i)subprocess\.(run|call|Popen)\s*\(.*shell\s*=\s*True'),
     "HIGH", "Install script uses shell=True subprocess — command injection risk",
     "Use shell=False with argument lists."),

    (re.compile(r'(?i)os\.system\s*\('),
     "MEDIUM", "Install script uses os.system() — command injection risk",
     "Use subprocess.run() with shell=False instead."),

    (re.compile(r'(?i)open\s*\([\'"][/~]'),
     "MEDIUM", "Install script accesses files outside current directory",
     "Audit file access in install scripts. Malware often reads SSH keys or .env files."),

    (re.compile(r'(?i)socket\.connect\s*\('),
     "HIGH", "Install script creates network socket connection",
     "Legitimate install scripts should not make raw socket connections."),

    (re.compile(r'(?i)__import__\s*\('),
     "MEDIUM", "Install script uses __import__() — dynamic import obfuscation",
     "Investigate dynamic imports in install scripts."),

    (re.compile(r'(?i)(?:HOME|USERPROFILE|APPDATA).*(?:\.ssh|\.aws|\.config)'),
     "CRITICAL", "Install script accesses sensitive user directories (.ssh, .aws, .config)",
     "This is a supply chain attack indicator. Do not install this package."),

    (re.compile(r'(?i)(?:\.ssh/id_rsa|\.ssh/id_ed25519|authorized_keys)'),
     "CRITICAL", "Install script references SSH key files",
     "This is a supply chain attack indicator. Do not install this package."),
]


def _check_requirements_txt(filepath: str, path: str) -> List[Finding]:
    """Check requirements.txt for typosquatted packages."""
    findings = []
    rel = os.path.relpath(filepath, path)
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for lineno, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                # Extract package name
                pkg = re.split(r'[>=<!;\[]', line)[0].strip().lower()
                if pkg in TYPOSQUATS:
                    findings.append(Finding(
                        severity="HIGH",
                        message=f"Possible typosquatted package: '{pkg}' (did you mean '{TYPOSQUATS[pkg]}'?)",
                        file=rel, scanner="supply_chain", line=lineno,
                        detail=f"'{pkg}' closely resembles the legitimate package '{TYPOSQUATS[pkg]}'.",
                        remediation=f"Replace '{pkg}' with '{TYPOSQUATS[pkg]}'. Verify package at pypi.org.",
                    ))
    except (OSError, PermissionError):
        pass
    return findings


def _check_package_json(filepath: str, path: str) -> List[Finding]:
    """Check package.json for typosquatted packages and suspicious scripts."""
    findings = []
    rel = os.path.relpath(filepath, path)
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            data = json.load(f)

        # Check all dependency sections
        for section in ('dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies'):
            for pkg in data.get(section, {}):
                pkg_lower = pkg.lower()
                if pkg_lower in TYPOSQUATS:
                    findings.append(Finding(
                        severity="HIGH",
                        message=f"Possible typosquatted npm package: '{pkg}' (did you mean '{TYPOSQUATS[pkg_lower]}'?)",
                        file=rel, scanner="supply_chain", line=0,
                        detail=f"'{pkg}' closely resembles '{TYPOSQUATS[pkg_lower]}'.",
                        remediation=f"Verify this is the intended package at npmjs.com.",
                    ))

        # Check lifecycle scripts for suspicious patterns
        scripts = data.get('scripts', {})
        for script_name in ('preinstall', 'install', 'postinstall', 'prepare'):
            script = scripts.get(script_name, '')
            if not script:
                continue
            for pattern, severity, message, remediation in SUSPICIOUS_INSTALL_PATTERNS:
                if pattern.search(script):
                    findings.append(Finding(
                        severity=severity,
                        message=f"Suspicious pattern in package.json '{script_name}' script: {message}",
                        file=rel, scanner="supply_chain", line=0,
                        detail=f"Script content: {script[:100]}",
                        remediation=remediation,
                    ))
                    break

    except (OSError, PermissionError, json.JSONDecodeError):
        pass
    return findings


def _check_setup_py(filepath: str, path: str) -> List[Finding]:
    """Check setup.py for suspicious install-time code execution."""
    findings = []
    rel = os.path.relpath(filepath, path)
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for lineno, line in enumerate(f, 1):
                for pattern, severity, message, remediation in SUSPICIOUS_INSTALL_PATTERNS:
                    if pattern.search(line):
                        findings.append(Finding(
                            severity=severity,
                            message=f"Suspicious pattern in setup.py: {message}",
                            file=rel, scanner="supply_chain", line=lineno,
                            detail=f"Line: {line.strip()[:100]}",
                            remediation=remediation,
                        ))
                        break
    except (OSError, PermissionError):
        pass
    return findings


def _check_pyproject_toml(filepath: str, path: str) -> List[Finding]:
    """Check pyproject.toml for suspicious build system hooks."""
    findings = []
    rel = os.path.relpath(filepath, path)
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()

        # Check for suspicious build hooks
        if re.search(r'\[tool\.hatch\.build\.hooks\]', content):
            findings.append(Finding(
                severity="MEDIUM",
                message="pyproject.toml defines custom build hooks — audit for supply chain risk",
                file=rel, scanner="supply_chain", line=0,
                detail="Custom build hooks execute code at install time.",
                remediation="Audit all build hook scripts for suspicious network/file operations.",
            ))

    except (OSError, PermissionError):
        pass
    return findings


def scan_supply_chain(path: str) -> List[Finding]:
    """Supply chain security scanner."""
    findings = []

    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

        for filename in files:
            filepath = os.path.join(root, filename)

            if filename == 'requirements.txt' or filename.startswith('requirements') and filename.endswith('.txt'):
                findings.extend(_check_requirements_txt(filepath, path))

            elif filename == 'package.json' and 'node_modules' not in filepath:
                findings.extend(_check_package_json(filepath, path))

            elif filename == 'setup.py':
                findings.extend(_check_setup_py(filepath, path))

            elif filename == 'pyproject.toml':
                findings.extend(_check_pyproject_toml(filepath, path))

    return findings
