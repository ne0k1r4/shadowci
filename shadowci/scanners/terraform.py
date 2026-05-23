import os
import re
from typing import List
from ..models import Finding

SKIP_DIRS = {'.git', 'node_modules', '__pycache__', '.venv', '.terraform'}


def scan_terraform(path: str) -> List[Finding]:
    findings = []
    tf_files = []

    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for f in files:
            if f.endswith('.tf') or f.endswith('.tf.json'):
                tf_files.append(os.path.join(root, f))

    if not tf_files:
        return findings

    for tf_path in tf_files:
        rel = os.path.relpath(tf_path, path)
        findings.append(Finding(
            severity="MEDIUM",
            message=f"Terraform infrastructure definition found: {os.path.basename(tf_path)}",
            file=rel, scanner="terraform",
            detail="IaC files define cloud resources. Review for misconfigurations.",
            remediation="Run: tfsec . or checkov -d . to audit Terraform configurations.",
        ))

        try:
            with open(tf_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
        except (OSError, PermissionError):
            continue

        for lineno, line in enumerate(lines, 1):
            stripped = line.strip()

            if re.search(r'0\.0\.0\.0/0', stripped) or re.search(r'::/0', stripped):
                findings.append(Finding(
                    severity="HIGH",
                    message="Terraform resource allows traffic from any IP (0.0.0.0/0)",
                    file=rel, scanner="terraform", line=lineno,
                    detail="Open CIDR in security group ingress exposes services to the internet.",
                    remediation="Restrict cidr_blocks to known IP ranges. Never use 0.0.0.0/0 in production.",
                ))

            if re.search(r'acl\s*=\s*[\'"]public-read', stripped, re.IGNORECASE) or \
               re.search(r'acl\s*=\s*[\'"]public-read-write', stripped, re.IGNORECASE):
                findings.append(Finding(
                    severity="CRITICAL",
                    message="Terraform S3 bucket configured with public ACL",
                    file=rel, scanner="terraform", line=lineno,
                    detail="Public S3 ACL exposes all bucket objects to the internet.",
                    remediation="Set acl = \"private\" and enable aws_s3_bucket_public_access_block.",
                ))

            if re.search(r'(?i)(password|secret|token)\s*=\s*[\'"][^\'"]{4,}[\'"]', stripped):
                findings.append(Finding(
                    severity="CRITICAL",
                    message="Hardcoded credential in Terraform file",
                    file=rel, scanner="terraform", line=lineno,
                    detail="Secrets in .tf files are committed to version control.",
                    remediation="Use: var.db_password with TF_VAR_db_password env var, or AWS Secrets Manager data source.",
                ))

            if re.search(r'encrypted\s*=\s*false', stripped, re.IGNORECASE):
                findings.append(Finding(
                    severity="HIGH",
                    message="Terraform resource explicitly disables encryption",
                    file=rel, scanner="terraform", line=lineno,
                    detail="Unencrypted storage violates data protection best practices.",
                    remediation="Set encrypted = true and specify a kms_key_id.",
                ))

            if re.search(r'"Action"\s*:\s*"\*"', stripped) or re.search(r"'Action'\s*:\s*'\*'", stripped):
                findings.append(Finding(
                    severity="HIGH",
                    message="Terraform IAM policy uses wildcard Action (*)",
                    file=rel, scanner="terraform", line=lineno,
                    detail="Wildcard IAM actions violate least-privilege principles.",
                    remediation="Replace Action: '*' with specific actions like ['s3:GetObject', 's3:PutObject'].",
                ))

    return findings
