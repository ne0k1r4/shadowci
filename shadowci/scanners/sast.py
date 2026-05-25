"""
shadowci/scanners/sast.py — SAST Lite Scanner
Detects hardcoded credentials, dangerous functions, injection sinks,
insecure deserialization, and other code-level security issues.
"""

import os
import re
from typing import List
from ..models import Finding

SKIP_DIRS = {'.git', 'node_modules', '__pycache__', '.venv', 'venv',
             'dist', 'build', '.tox', 'coverage', '.pytest_cache', 'scanners'}

SKIP_EXTENSIONS = {'.pyc', '.pyo', '.pyd', '.so', '.dylib', '.dll',
                   '.exe', '.bin', '.jpg', '.png', '.gif', '.ico',
                   '.pdf', '.zip', '.tar', '.gz', '.lock'}

CODE_EXTENSIONS = {
    '.py', '.js', '.ts', '.jsx', '.tsx', '.php', '.rb', '.go',
    '.java', '.cs', '.cpp', '.c', '.h', '.sh', '.bash', '.ps1',
    '.rs', '.swift', '.kt', '.scala', '.r',
}

# (name, pattern, severity, message, remediation, languages)
SAST_PATTERNS = [

    # ── Hardcoded credentials ────────────────────────────────────────────────
    ("Hardcoded Password Assignment",
     re.compile(r'(?i)(?:password|passwd|pwd)\s*=\s*[\'"][^\'"]{4,}[\'"]'),
     "CRITICAL", "Hardcoded password assignment detected",
     "Use environment variables or a secrets manager. Never hardcode passwords.",
     None),

    ("Hardcoded Secret Assignment",
     re.compile(r'(?i)(?:secret|api_secret|client_secret)\s*=\s*[\'"][^\'"]{8,}[\'"]'),
     "CRITICAL", "Hardcoded secret detected",
     "Store secrets in environment variables or a vault.",
     None),

    ("Hardcoded Token",
     re.compile(r'(?i)(?:token|auth_token|bearer_token)\s*=\s*[\'"][A-Za-z0-9_\-\.]{20,}[\'"]'),
     "HIGH", "Hardcoded authentication token detected",
     "Load tokens from environment variables: os.environ.get('TOKEN')",
     None),

    # ── Dangerous Python functions ────────────────────────────────────────────
    ("Python eval()",
     re.compile(r'\beval\s*\('),
     "CRITICAL", "Use of eval() detected — arbitrary code execution risk",
     "Never use eval() on untrusted input. Use ast.literal_eval() for safe evaluation.",
     {'.py'}),

    ("Python exec()",
     re.compile(r'(?<!["\'])\bexec\s*\((?![^)]*["\'])'),
     "HIGH", "Use of exec() detected — code injection risk",
     "Avoid exec() with user-controlled data. Use subprocess for shell commands.",
     {'.py'}),

    ("Python pickle.loads()",
     re.compile(r'\bpickle\.loads?\s*\('),
     "CRITICAL", "Use of pickle.loads() — arbitrary code execution on deserialization",
     "Never deserialize pickle data from untrusted sources. Use JSON or msgpack.",
     {'.py'}),

    ("Python marshal.loads()",
     re.compile(r'\bmarshal\.loads?\s*\('),
     "HIGH", "Use of marshal.loads() — unsafe deserialization",
     "Avoid marshal for untrusted data. Use JSON instead.",
     {'.py'}),

    ("Python subprocess shell=True",
     re.compile(r'subprocess\.[a-z_]+\s*\([^)]*shell\s*=\s*True'),
     "HIGH", "subprocess called with shell=True — command injection risk",
     "Use shell=False and pass arguments as a list: subprocess.run(['cmd', 'arg'])",
     {'.py'}),

    ("Python os.system()",
     re.compile(r'\bos\.system\s*\('),
     "MEDIUM", "Use of os.system() — command injection risk",
     "Use subprocess.run() with shell=False instead.",
     {'.py'}),

    ("Python os.popen()",
     re.compile(r'\bos\.popen\s*\('),
     "MEDIUM", "Use of os.popen() — command injection risk",
     "Use subprocess.run() with shell=False and capture_output=True instead.",
     {'.py'}),

    ("Python input() in Python 2 style",
     re.compile(r'(?<!\w)input\s*\([^)]*\)\s*#.*python\s*2', re.IGNORECASE),
     "MEDIUM", "Python 2 input() executes arbitrary code",
     "Use raw_input() in Python 2 or input() in Python 3.",
     {'.py'}),

    ("Python yaml.load() unsafe",
     re.compile(r'\byaml\.load\s*\([^)]*\)(?!\s*,\s*Loader)'),
     "HIGH", "yaml.load() without Loader= is unsafe — arbitrary code execution",
     "Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader)",
     {'.py'}),

    ("Python hashlib MD5",
     re.compile(r'\bhashlib\.md5\s*\('),
     "MEDIUM", "MD5 hash function detected — cryptographically broken",
     "Use hashlib.sha256() or hashlib.sha3_256() instead.",
     {'.py'}),

    ("Python hashlib SHA1",
     re.compile(r'\bhashlib\.sha1\s*\('),
     "MEDIUM", "SHA1 hash function detected — weak for security use",
     "Use hashlib.sha256() or higher for security-sensitive hashing.",
     {'.py'}),

    ("Python random for crypto",
     re.compile(r'\brandom\.(?:random|randint|choice|choices|sample|shuffle)\s*\('),
     "MEDIUM", "Non-cryptographic random used — may be weak for security",
     "Use secrets module for security-sensitive randomness: secrets.token_hex()",
     {'.py'}),

    # ── SQL Injection sinks ───────────────────────────────────────────────────
    ("SQL String Concatenation",
     re.compile(r'(?i)(?:execute|cursor\.execute)\s*\(\s*[\'"][^\'"]*(SELECT|INSERT|UPDATE|DELETE|DROP)[^\'"]*([\'"]\s*\+|%\s*\()'),
     "CRITICAL", "Potential SQL injection via string concatenation",
     "Use parameterized queries: cursor.execute('SELECT * FROM t WHERE id=%s', (user_id,))",
     None),

    ("SQL f-string injection",
     re.compile(r'(?i)(?:execute|cursor\.execute)\s*\(\s*f[\'"].*(?:SELECT|INSERT|UPDATE|DELETE)'),
     "CRITICAL", "SQL query built with f-string — injection risk",
     "Never use f-strings or .format() for SQL. Use parameterized queries.",
     {'.py'}),

    # ── JavaScript / Node.js ──────────────────────────────────────────────────
    ("JS eval()",
     re.compile(r'(?<!\w)eval\s*\('),
     "CRITICAL", "JavaScript eval() detected — XSS and code injection risk",
     "Avoid eval(). Use JSON.parse() for JSON, or refactor logic.",
     {'.js', '.ts', '.jsx', '.tsx'}),

    ("JS innerHTML assignment",
     re.compile(r'\.innerHTML\s*='),
     "HIGH", "Direct innerHTML assignment — XSS risk",
     "Use textContent for text, or sanitize HTML with DOMPurify.",
     {'.js', '.ts', '.jsx', '.tsx'}),

    ("JS document.write()",
     re.compile(r'document\.write\s*\('),
     "HIGH", "document.write() detected — XSS risk",
     "Use DOM manipulation methods (createElement, appendChild) instead.",
     {'.js', '.ts', '.jsx', '.tsx'}),

    ("JS dangerouslySetInnerHTML",
     re.compile(r'dangerouslySetInnerHTML'),
     "HIGH", "React dangerouslySetInnerHTML detected — XSS risk",
     "Sanitize content with DOMPurify before passing to dangerouslySetInnerHTML.",
     {'.jsx', '.tsx', '.js', '.ts'}),

    ("JS setTimeout with string",
     re.compile(r'setTimeout\s*\(\s*[\'"`]'),
     "MEDIUM", "setTimeout with string argument — code injection risk",
     "Pass a function reference instead: setTimeout(() => doSomething(), 1000)",
     {'.js', '.ts', '.jsx', '.tsx'}),

    # ── PHP ───────────────────────────────────────────────────────────────────
    ("PHP eval()",
     re.compile(r'(?<!\w)eval\s*\('),
     "CRITICAL", "PHP eval() — arbitrary code execution",
     "Remove eval(). Refactor to use proper functions.",
     {'.php'}),

    ("PHP system()/exec()/shell_exec()",
     re.compile(r'(?<!\w)(?:system|exec|shell_exec|passthru|popen)\s*\('),
     "CRITICAL", "PHP shell execution function detected — command injection risk",
     "Validate and escape all input. Use escapeshellarg() if shell execution is necessary.",
     {'.php'}),

    ("PHP SQL concatenation",
     re.compile(r'(?i)mysql_query\s*\(\s*[\'"].*\.\s*\$'),
     "CRITICAL", "PHP SQL injection via string concatenation",
     "Use PDO prepared statements with parameterized queries.",
     {'.php'}),

    # ── Path traversal ────────────────────────────────────────────────────────
    ("Path traversal via user input",
     re.compile(r'(?i)open\s*\(\s*(?:request\.|req\.|params\[|input\()'),
     "HIGH", "File open with potentially user-controlled path",
     "Validate and sanitize file paths. Use os.path.basename() and restrict to safe directories.",
     None),

    # ── Hardcoded IPs / Internal ──────────────────────────────────────────────
    ("Hardcoded internal IP",
     re.compile(r'(?i)(?:host|url|endpoint)\s*=\s*[\'"](?:192\.168\.|10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.)'),
     "MEDIUM", "Hardcoded internal IP address detected",
     "Use configuration files or environment variables for host addresses.",
     None),

    ("Debug mode enabled",
     re.compile(r'(?i)(?:DEBUG\s*=\s*True|debug\s*=\s*true|app\.run\(.*debug\s*=\s*True)'),
     "HIGH", "Debug mode enabled in code",
     "Ensure DEBUG=False in production. Use environment variables to control debug mode.",
     None),

    # ── SSRF / Request forgery ────────────────────────────────────────────────
    ("SSRF via user-controlled URL",
     re.compile(r'(?i)requests?\.[a-z]+\(\s*(?:request\.|req\.|params\[|input\()'),
     "HIGH", "HTTP request to potentially user-controlled URL — SSRF risk",
     "Validate URLs against an allowlist. Block internal IP ranges.",
     {'.py'}),
]


def scan_sast(path: str) -> List[Finding]:
    """SAST lite scanner — detect dangerous patterns in source code."""
    findings = []

    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

        for filename in files:
            ext = os.path.splitext(filename)[1].lower()
            if ext in SKIP_EXTENSIONS or ext not in CODE_EXTENSIONS:
                continue

            filepath = os.path.join(root, filename)
            rel = os.path.relpath(filepath, path)

            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    for lineno, line in enumerate(f, 1):
                        stripped = line.strip()
                        if stripped.startswith('#') or stripped.startswith('//'):
                            continue  # skip comments
                        # skip regex pattern definition lines and cipher name strings
                        if 're.compile(' in stripped or ('PATTERNS' in stripped and '=' in stripped):
                            continue
                        # skip weak crypto FP: only flag actual usage not string literals
                        if any(x in stripped for x in ['DES', '3DES', 'TripleDES', 'ECB']):
                            import re as _re
                            if not _re.search(r'\.(new|encrypt|decrypt|cipher)\s*\(|from\s+Crypto|import\s+DES', stripped, _re.I):
                                continue
                        for name, pattern, severity, message, remediation, languages in \
                                [(p[0], p[1], p[2], p[3], p[4], p[5]) for p in SAST_PATTERNS]:
                            if languages and ext not in languages:
                                continue
                            if pattern.search(line):
                                findings.append(Finding(
                                    severity=severity,
                                    message=message,
                                    file=rel,
                                    scanner="sast",
                                    line=lineno,
                                    detail=f"Pattern: {name} — {line.strip()[:80]}",
                                    remediation=remediation,
                                ))
                                break
            except (OSError, PermissionError):
                continue

    return findings
