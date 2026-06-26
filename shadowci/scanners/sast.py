"""
shadowci/scanners/sast.py — SAST Lite Scanner
Detects hardcoded credentials, dangerous functions, injection sinks,
insecure deserialization, and other code-level security issues.
"""

import os
import re
import ast
from typing import List
from ..models import Finding

SKIP_DIRS = {
    '.git', 'node_modules', '__pycache__', '.venv', 'venv',
    'dist', 'build', 'scanners', '.tox', 'coverage', '.pytest_cache'
}

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


# walks the AST so it catches renamed imports too, not just string matching
# TODO: only does python rn, js support would need a different parser
class PythonASTScanner(ast.NodeVisitor):
    def __init__(self, filepath: str, rel_path: str):
        self.filepath = filepath
        self.rel_path = rel_path
        self.findings = []

    def add_finding(self, node, name, severity, message, remediation):
        self.findings.append(Finding(
            severity=severity,
            message=message,
            file=self.rel_path,
            scanner="sast",
            line=getattr(node, 'lineno', 0),
            detail=f"AST Check: {name} detected",
            remediation=remediation
        ))

    def visit_Call(self, node):
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
            if func_name == 'eval':
                self.add_finding(
                    node, "Python eval()", "CRITICAL",
                    "Use of eval() detected — arbitrary code execution risk",
                    "Never use eval() on untrusted input. Use ast.literal_eval() for safe evaluation."
                )
            elif func_name == 'exec':
                self.add_finding(
                    node, "Python exec()", "HIGH",
                    "Use of exec() detected — code injection risk",
                    "Avoid exec() with user-controlled data. Use subprocess for shell commands."
                )
            elif func_name in ('system', 'popen'):
                self.add_finding(
                    node, f"Python os.{func_name}()", "MEDIUM",
                    f"Use of os.{func_name}() — command injection risk",
                    "Use subprocess.run() with shell=False instead."
                )
        
        elif isinstance(node.func, ast.Attribute):
            module_name = ""
            if isinstance(node.func.value, ast.Name):
                module_name = node.func.value.id
            
            func_name = node.func.attr
            
            if module_name == 'os' and func_name in ('system', 'popen'):
                self.add_finding(
                    node, f"Python os.{func_name}()", "MEDIUM",
                    f"Use of os.{func_name}() — command injection risk",
                    "Use subprocess.run() with shell=False and capture_output=True instead."
                )
            elif module_name == 'pickle' and func_name in ('load', 'loads'):
                self.add_finding(
                    node, "Python pickle.loads()", "CRITICAL",
                    "Use of pickle.loads() — arbitrary code execution on deserialization",
                    "Never deserialize pickle data from untrusted sources. Use JSON or msgpack."
                )
            elif module_name == 'marshal' and func_name in ('load', 'loads'):
                self.add_finding(
                    node, "Python marshal.loads()", "HIGH",
                    "Use of marshal.loads() — unsafe deserialization",
                    "Avoid marshal for untrusted data. Use JSON instead."
                )
            elif module_name == 'yaml' and func_name == 'load':
                has_safe_loader = False
                for kw in node.keywords:
                    if kw.arg == 'Loader':
                        if isinstance(kw.value, ast.Attribute) and getattr(kw.value.value, 'id', '') == 'yaml' and kw.value.attr == 'SafeLoader':
                            has_safe_loader = True
                        elif isinstance(kw.value, ast.Name) and kw.value.id == 'SafeLoader':
                            has_safe_loader = True
                if not has_safe_loader:
                    self.add_finding(
                        node, "Python yaml.load() unsafe", "HIGH",
                        "yaml.load() without Loader=SafeLoader is unsafe — arbitrary code execution",
                        "Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader)"
                    )
            elif module_name == 'hashlib' and func_name == 'md5':
                self.add_finding(
                    node, "Python hashlib MD5", "MEDIUM",
                    "MD5 hash function detected — cryptographically broken",
                    "Use hashlib.sha256() or hashlib.sha3_256() instead."
                )
            elif module_name == 'hashlib' and func_name == 'sha1':
                self.add_finding(
                    node, "Python hashlib SHA1", "MEDIUM",
                    "SHA1 hash function detected — weak for security use",
                    "Use hashlib.sha256() or higher for security-sensitive hashing."
                )
            elif module_name == 'subprocess' or (isinstance(node.func.value, ast.Name) and node.func.value.id == 'subprocess'):
                for kw in node.keywords:
                    if kw.arg == 'shell' and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        self.add_finding(
                            node, "Python subprocess shell=True", "HIGH",
                            "subprocess called with shell=True — command injection risk",
                            "Use shell=False and pass arguments as a list: subprocess.run(['cmd', 'arg'])"
                        )
                        break

            if func_name in ('execute', 'executemany') and node.args:
                first_arg = node.args[0]
                is_unsafe = False
                
                if isinstance(first_arg, ast.JoinedStr):
                    is_unsafe = True
                elif isinstance(first_arg, ast.BinOp):
                    if isinstance(first_arg.op, (ast.Mod, ast.Add)):
                        is_unsafe = True
                elif isinstance(first_arg, ast.Call) and isinstance(first_arg.func, ast.Attribute) and first_arg.func.attr == 'format':
                    is_unsafe = True
                
                if is_unsafe:
                    def find_sql_words(n):
                        if isinstance(n, ast.Constant) and isinstance(n.value, str):
                            val = n.value.upper()
                            return any(w in val for w in ('SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP'))
                        elif isinstance(n, ast.JoinedStr):
                            return any(find_sql_words(val) for val in n.values)
                        elif isinstance(n, ast.BinOp):
                            return find_sql_words(n.left) or find_sql_words(n.right)
                        elif isinstance(n, ast.Call):
                            return find_sql_words(n.func)
                        return False
                    
                    if find_sql_words(first_arg):
                        self.add_finding(
                            node, "SQL f-string/concatenation injection", "CRITICAL",
                            "Potential SQL injection via dynamic query construction in execute()",
                            "Never use f-strings, concatenation or % formatting for SQL queries. Use parameterized queries."
                        )

        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) and node.func.value.id == 'random':
            if node.func.attr in ('random', 'randint', 'choice', 'choices', 'sample', 'shuffle'):
                self.add_finding(
                    node, "Python random for crypto", "MEDIUM",
                    "Non-cryptographic random used — may be weak for security",
                    "Use secrets module for security-sensitive randomness: secrets.token_hex()"
                )

        self.generic_visit(node)

    def visit_Assign(self, node):
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id.lower()
                if any(x in var_name for x in ('password', 'passwd', 'pwd')) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str) and len(node.value.value) >= 4:
                    self.add_finding(
                        node, "Hardcoded Password Assignment", "CRITICAL",
                        "Hardcoded password assignment detected",
                        "Use environment variables or a secrets manager. Never hardcode passwords."
                    )
                elif any(x in var_name for x in ('secret', 'api_secret', 'client_secret')) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str) and len(node.value.value) >= 8:
                    self.add_finding(
                        node, "Hardcoded Secret Assignment", "CRITICAL",
                        "Hardcoded secret detected",
                        "Store secrets in environment variables or a vault."
                    )
                elif any(x in var_name for x in ('token', 'auth_token', 'bearer_token')) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str) and len(node.value.value) >= 20:
                    self.add_finding(
                        node, "Hardcoded Token", "HIGH",
                        "Hardcoded authentication token detected",
                        "Load tokens from environment variables: os.environ.get('TOKEN')"
                    )
        self.generic_visit(node)


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
                if ext == '.py':
                    try:
                        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                            source = f.read()
                        tree = ast.parse(source, filename=filepath)
                        scanner = PythonASTScanner(filepath, rel)
                        scanner.visit(tree)
                        findings.extend(scanner.findings)
                        continue
                    except SyntaxError:
                        pass

                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    for lineno, line in enumerate(f, 1):
                        stripped = line.strip()
                        if stripped.startswith('#') or stripped.startswith('//'):
                            continue
                        if 're.compile(' in stripped or ('PATTERNS' in stripped and '=' in stripped):
                            continue
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
