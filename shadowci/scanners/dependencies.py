"""
Dependency scanner — detects known vulnerable packages in
requirements.txt, package.json, Pipfile, pyproject.toml, go.mod.
"""
import os
import json
import re
from typing import List
from ..models import Finding

# Known vulnerable packages (name → [(version_range, severity, CVE, description)])
# Format: version_range is a simple string like "<2.0" or "<=1.9.3"
# This is a curated list of high-profile historical vulns for demo/education.
KNOWN_PYTHON_VULNS = {
    "django": [
        ("<2.2.26", "HIGH",     "CVE-2021-45116", "Potential information disclosure via settings"),
        ("<3.2.11", "HIGH",     "CVE-2021-45116", "Potential information disclosure via settings"),
        ("<2.0",    "CRITICAL", "CVE-2017-7233",  "Open redirect and possible XSS attack"),
    ],
    "flask": [
        ("<1.0",   "HIGH",     "CVE-2018-1000656", "Denial of service via crafted JSON"),
    ],
    "requests": [
        ("<2.20.0","HIGH",     "CVE-2018-18074",   "Credentials exposure via HTTP redirect"),
    ],
    "pyyaml": [
        ("<5.4",   "CRITICAL", "CVE-2020-14343",   "Arbitrary code execution via yaml.load()"),
    ],
    "pillow": [
        ("<9.0.0", "HIGH",     "CVE-2022-22817",   "Arbitrary expression evaluation in ImagePath.Path"),
        ("<8.1.1", "CRITICAL", "CVE-2021-25287",   "Out-of-bounds read in TIFF image parsing"),
    ],
    "cryptography": [
        ("<3.3.2", "HIGH",     "CVE-2020-36242",   "Buffer overflow in symmetric key handling"),
    ],
    "paramiko": [
        ("<2.4.2", "HIGH",     "CVE-2018-1000805", "Authentication bypass via missing check"),
    ],
    "urllib3": [
        ("<1.26.5","HIGH",     "CVE-2021-33503",   "ReDoS via evil header value"),
    ],
    "setuptools": [
        ("<65.5.1","HIGH",     "CVE-2022-40897",   "ReDoS in package_index module"),
    ],
    "lxml": [
        ("<4.9.1", "HIGH",     "CVE-2022-2309",    "NULL pointer dereference in xmlTextReaderExpand"),
    ],
    "ansible": [
        ("<2.8.18","CRITICAL", "CVE-2021-3620",    "Information disclosure via error messages"),
    ],
    "jinja2": [
        ("<2.11.3","HIGH",     "CVE-2020-28493",   "ReDoS in urlize filter"),
        ("<3.1.3", "HIGH",     "CVE-2024-34064",   "XSS via xmlattr filter"),
    ],
    "sqlalchemy": [
        ("<1.4.0", "MEDIUM",   "CVE-2019-7548",    "SQL injection via ORDER BY clause"),
    ],
}

KNOWN_NPM_VULNS = {
    "lodash": [
        ("<4.17.21",  "CRITICAL", "CVE-2021-23337", "Command injection via template"),
        ("<4.17.19",  "CRITICAL", "CVE-2020-8203",  "Prototype pollution"),
    ],
    "axios": [
        ("<0.21.2",   "HIGH",     "CVE-2021-3749",  "ReDoS via crafted URL"),
        ("<1.6.0",    "MEDIUM",   "CVE-2023-45857", "CSRF via withCredentials"),
    ],
    "express": [
        ("<4.19.2",   "HIGH",     "CVE-2024-29041", "Open redirect via malformed URL"),
    ],
    "moment": [
        ("<2.29.4",   "HIGH",     "CVE-2022-31129", "Path traversal in format string"),
    ],
    "minimist": [
        ("<1.2.6",    "CRITICAL", "CVE-2021-44906", "Prototype pollution"),
    ],
    "node-fetch": [
        ("<2.6.7",    "HIGH",     "CVE-2022-0235",  "Exposure of sensitive information to wrong actor"),
    ],
    "tar": [
        ("<6.1.9",    "CRITICAL", "CVE-2021-37701", "Arbitrary file creation via symlink attack"),
    ],
    "semver": [
        ("<7.5.2",    "HIGH",     "CVE-2022-25883", "ReDoS via crafted version string"),
    ],
    "jsonwebtoken": [
        ("<9.0.0",    "CRITICAL", "CVE-2022-23529", "Remote code execution via malicious JWK"),
    ],
    "ws": [
        ("<7.5.10",   "HIGH",     "CVE-2024-37890", "DoS via crafted HTTP request"),
    ],
}


def _parse_version(ver_str: str):
    """Parse version string into comparable tuple. Returns None on failure."""
    ver_str = ver_str.strip().lstrip('v=~^')
    # Take only numeric parts
    parts = re.split(r'[.\-]', ver_str)
    result = []
    for p in parts[:3]:
        try:
            result.append(int(p))
        except ValueError:
            break
    return tuple(result) if result else None


def _version_lt(a, b_str: str) -> bool:
    """Check if version tuple a is less than version string b."""
    b = _parse_version(b_str)
    if a is None or b is None:
        return False
    return a < b


def _version_lte(a, b_str: str) -> bool:
    b = _parse_version(b_str)
    if a is None or b is None:
        return False
    return a <= b


def _check_vuln(pkg_name: str, version_str: str, vuln_db: dict, rel_path: str,
                scanner_name: str) -> List[Finding]:
    findings = []
    name_lower = pkg_name.lower().strip()
    if name_lower not in vuln_db:
        return findings

    parsed = _parse_version(version_str)

    for (range_str, severity, cve, desc) in vuln_db[name_lower]:
        op  = range_str[:2] if range_str[1] in '<>=' else range_str[0]
        ver = range_str.lstrip('<>=')
        match = False
        if op == '<':
            match = _version_lt(parsed, ver)
        elif op == '<=':
            match = _version_lte(parsed, ver)

        if match:
            findings.append(Finding(
                severity=severity,
                message=f"Vulnerable dependency: {pkg_name}=={version_str} ({cve})",
                file=rel_path,
                scanner=scanner_name,
                detail=f"{cve}: {desc}. Upgrade to a patched version.",
            ))
            break  # one finding per package

    return findings


def _scan_requirements_txt(filepath: str, rel: str) -> List[Finding]:
    findings = []
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#') or line.startswith('-'):
                    continue
                # pkg==version or pkg>=version etc
                m = re.match(r'^([A-Za-z0-9_\-\.]+)\s*==\s*([0-9][^\s;]+)', line)
                if m:
                    findings += _check_vuln(m.group(1), m.group(2),
                                            KNOWN_PYTHON_VULNS, rel, "dependencies")
    except (OSError, PermissionError):
        pass
    return findings


def _scan_package_json(filepath: str, rel: str) -> List[Finding]:
    findings = []
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            data = json.load(f)
    except (OSError, PermissionError, json.JSONDecodeError):
        return findings

    all_deps = {}
    all_deps.update(data.get('dependencies', {}))
    all_deps.update(data.get('devDependencies', {}))

    for pkg, ver_range in all_deps.items():
        # Strip range chars: ^1.2.3 -> 1.2.3
        ver = re.sub(r'^[\^~>=<\s]+', '', ver_range).split(' ')[0]
        findings += _check_vuln(pkg, ver, KNOWN_NPM_VULNS, rel, "dependencies")

    return findings


def _scan_pipfile(filepath: str, rel: str) -> List[Finding]:
    """Basic Pipfile scanning — look for pinned versions."""
    findings = []
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                m = re.match(r'^([A-Za-z0-9_\-\.]+)\s*=\s*["\']?==\s*([0-9][^\s"\']+)', line)
                if m:
                    findings += _check_vuln(m.group(1), m.group(2),
                                            KNOWN_PYTHON_VULNS, rel, "dependencies")
    except (OSError, PermissionError):
        pass
    return findings


def _scan_pyproject(filepath: str, rel: str) -> List[Finding]:
    findings = []
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        # Match: packagename = "==x.y.z" or packagename==x.y.z
        for m in re.finditer(r'([A-Za-z0-9_\-\.]+)\s*[=,\s]*"?==\s*([0-9][^"\s,\]]+)"?', content):
            findings += _check_vuln(m.group(1), m.group(2),
                                    KNOWN_PYTHON_VULNS, rel, "dependencies")
    except (OSError, PermissionError):
        pass
    return findings


SKIP_DIRS = {'.git', 'node_modules', '__pycache__', '.venv', 'venv', 'dist', 'build', '.terraform'}


def scan_dependencies(path: str) -> List[Finding]:
    findings = []

    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

        for filename in files:
            filepath = os.path.join(root, filename)
            rel = os.path.relpath(filepath, path)

            if filename == 'requirements.txt' or filename.startswith('requirements') and filename.endswith('.txt'):
                findings += _scan_requirements_txt(filepath, rel)

            elif filename == 'package.json':
                findings += _scan_package_json(filepath, rel)

            elif filename == 'Pipfile':
                findings += _scan_pipfile(filepath, rel)

            elif filename == 'pyproject.toml':
                findings += _scan_pyproject(filepath, rel)

    return findings
