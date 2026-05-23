import os
import re
from typing import List
from ..models import Finding

# (name, pattern, severity, message, remediation)
SECRET_PATTERNS = [
    ("AWS Access Key",
     re.compile(r'AKIA[0-9A-Z]{16}'),
     "CRITICAL", "AWS Access Key ID detected",
     "Revoke key immediately at AWS IAM Console. Use IAM roles or AWS Secrets Manager instead."),

    ("AWS Secret Key",
     re.compile(r'(?i)aws_secret_access_key\s*=\s*[\'"]?([A-Za-z0-9/+=]{40})[\'"]?'),
     "CRITICAL", "AWS Secret Access Key detected",
     "Rotate via AWS IAM → Security credentials. Store in AWS Secrets Manager or environment variables."),

    ("GitHub PAT",
     re.compile(r'ghp_[A-Za-z0-9]{36}'),
     "CRITICAL", "GitHub Personal Access Token detected",
     "Revoke at github.com/settings/tokens. Use GitHub Actions secrets or OIDC instead."),

    ("GitHub Fine-grained PAT",
     re.compile(r'github_pat_[A-Za-z0-9_]{82}'),
     "CRITICAL", "GitHub Fine-grained PAT detected",
     "Revoke at github.com/settings/tokens. Use GitHub Actions secrets or OIDC instead."),

    ("GitHub OAuth Token",
     re.compile(r'gho_[A-Za-z0-9]{36}'),
     "CRITICAL", "GitHub OAuth Token detected",
     "Revoke immediately. Audit OAuth apps at github.com/settings/applications."),

    ("GitHub Actions Token",
     re.compile(r'ghs_[A-Za-z0-9]{36}'),
     "CRITICAL", "GitHub Actions Token detected",
     "This should never appear in source. Rotate secrets in repo settings."),

    ("GitLab Token",
     re.compile(r'glpat-[A-Za-z0-9_\-]{20}'),
     "CRITICAL", "GitLab Personal Access Token detected",
     "Revoke at gitlab.com/-/profile/personal_access_tokens."),

    ("Slack Webhook",
     re.compile(r'https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24,}'),
     "HIGH", "Slack Incoming Webhook URL detected",
     "Revoke at api.slack.com/apps → Your App → Incoming Webhooks."),

    ("Slack Token",
     re.compile(r'xox[baprs]-[0-9A-Za-z\-]{10,}'),
     "CRITICAL", "Slack API Token detected",
     "Revoke at api.slack.com/apps. Never hardcode Slack tokens in source."),

    ("Discord Webhook",
     re.compile(r'https://discord(?:app)?\.com/api/webhooks/[0-9]{17,19}/[A-Za-z0-9_\-]{68}'),
     "HIGH", "Discord Webhook URL detected",
     "Delete the webhook in Discord server settings → Integrations."),

    ("Discord Bot Token",
     re.compile(r'[MN][A-Za-z0-9]{23}\.[\w-]{6}\.[\w-]{27}'),
     "CRITICAL", "Discord Bot Token detected",
     "Regenerate at discord.com/developers/applications → Bot → Reset Token."),

    ("Stripe Secret Key",
     re.compile(r'sk_live_[A-Za-z0-9]{24,}'),
     "CRITICAL", "Stripe Live Secret Key detected",
     "Roll immediately at dashboard.stripe.com/apikeys. Use Stripe restricted keys with least privilege."),

    ("Stripe Publishable Key",
     re.compile(r'pk_live_[A-Za-z0-9]{24,}'),
     "MEDIUM", "Stripe Live Publishable Key detected",
     "Publishable keys are less sensitive but should not be hardcoded. Use environment variables."),

    ("SendGrid API Key",
     re.compile(r'SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}'),
     "CRITICAL", "SendGrid API Key detected",
     "Revoke at app.sendgrid.com/settings/api_keys. Create scoped keys with minimal permissions."),

    ("Twilio Account SID",
     re.compile(r'AC[a-f0-9]{32}'),
     "HIGH", "Twilio Account SID detected",
     "Rotate at console.twilio.com → Account → API Keys. Use Auth Tokens, not hardcoded SIDs."),

    ("Twilio Auth Token",
     re.compile(r'(?i)twilio.*[\'"]([a-f0-9]{32})[\'"]'),
     "CRITICAL", "Twilio Auth Token detected",
     "Rotate immediately at console.twilio.com. Use environment variables exclusively."),

    ("OpenAI API Key",
     re.compile(r'sk-[A-Za-z0-9]{48}'),
     "CRITICAL", "OpenAI API Key detected",
     "Revoke at platform.openai.com/api-keys. All usage billed to this key immediately."),

    ("Anthropic API Key",
     re.compile(r'sk-ant-[A-Za-z0-9\-_]{95}'),
     "CRITICAL", "Anthropic API Key detected",
     "Revoke at console.anthropic.com/account/keys."),

    ("GCP Service Account Key",
     re.compile(r'"type":\s*"service_account"'),
     "CRITICAL", "GCP Service Account Key JSON detected",
     "Revoke at console.cloud.google.com/iam-admin/serviceaccounts. Use Workload Identity Federation instead."),

    ("Azure Client Secret",
     re.compile(r'(?i)azure.*client.?secret\s*=\s*[\'"]([A-Za-z0-9~_\-\.]{34,})[\'"]'),
     "CRITICAL", "Azure Client Secret detected",
     "Rotate in Azure AD App registrations. Use Managed Identity instead."),

    ("Azure Storage Key",
     re.compile(r'DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}'),
     "CRITICAL", "Azure Storage Connection String with key detected",
     "Rotate at Azure Portal → Storage account → Access keys. Use SAS tokens or Managed Identity."),

    ("npm Auth Token",
     re.compile(r'//registry\.npmjs\.org/:_authToken\s*=\s*[A-Za-z0-9\-_]{36}'),
     "CRITICAL", "npm registry auth token in .npmrc detected",
     "Revoke at npmjs.com/settings/tokens. Use CI secrets for npm auth."),

    ("PyPI Token",
     re.compile(r'pypi-AgE[A-Za-z0-9_\-]{70,}'),
     "CRITICAL", "PyPI upload token detected",
     "Revoke at pypi.org/manage/account/token. Use trusted publishers (OIDC) instead."),

    ("Heroku API Key",
     re.compile(r'(?i)heroku.*[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'),
     "HIGH", "Heroku API Key detected",
     "Revoke at dashboard.heroku.com/account. Use Heroku config vars for secrets."),

    ("MongoDB URI with credentials",
     re.compile(r'mongodb(?:\+srv)?://[^:]+:[^@]+@[A-Za-z0-9\.\-]+'),
     "CRITICAL", "MongoDB connection string with credentials detected",
     "Rotate database password. Use environment variables or a secrets manager for connection strings."),

    ("PostgreSQL URI with credentials",
     re.compile(r'postgres(?:ql)?://[^:]+:[^@]+@[A-Za-z0-9\.\-]+'),
     "CRITICAL", "PostgreSQL connection string with credentials detected",
     "Rotate database password. Use environment variables for all connection strings."),

    ("MySQL URI with credentials",
     re.compile(r'mysql://[^:]+:[^@]+@[A-Za-z0-9\.\-]+'),
     "CRITICAL", "MySQL connection string with credentials detected",
     "Rotate database password immediately. Never hardcode DB URIs in source."),

    ("JWT Token",
     re.compile(r'eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+'),
     "HIGH", "JWT Token hardcoded in source",
     "JWTs expire but hardcoding them is dangerous. Generate at runtime, never embed in code."),

    ("Private Key Header",
     re.compile(r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'),
     "CRITICAL", "Private key material detected",
     "Immediately check git history (git log -S 'BEGIN PRIVATE KEY'). Revoke and regenerate the keypair."),

    ("Generic API Key",
     re.compile(r'(?i)\b(api_key|apikey|api-key)\s*[=:]\s*[\'"]?([A-Za-z0-9\-_]{20,})[\'"]?'),
     "HIGH", "Generic API key pattern detected",
     "Move to environment variable or secrets manager. Never hardcode API keys."),

    ("Hardcoded Password",
     re.compile(r'(?i)\b(password|passwd|pwd)\s*=\s*[\'"][^\'"]{6,}[\'"]'),
     "HIGH", "Hardcoded password detected",
     "Use environment variables or a secrets manager. Run: git filter-repo to purge history."),

    ("Basic Auth in URL",
     re.compile(r'https?://[^:]+:[^@]{3,}@[A-Za-z0-9\.\-]+'),
     "HIGH", "Credentials embedded in URL detected",
     "Remove credentials from URL. Use auth headers or environment variables instead."),

    ("Mailgun API Key",
     re.compile(r'key-[A-Za-z0-9]{32}'),
     "HIGH", "Mailgun API Key detected",
     "Revoke at app.mailgun.com/app/account/security. Use environment variables."),

    ("Datadog API Key",
     re.compile(r'(?i)datadog.*[\'"]([a-f0-9]{32})[\'"]'),
     "HIGH", "Datadog API Key detected",
     "Revoke at app.datadoghq.com/organization-settings/api-keys."),
]

SKIP_EXTENSIONS = {
    '.png','.jpg','.jpeg','.gif','.svg','.ico','.pdf','.zip',
    '.tar','.gz','.exe','.bin','.lock','.woff','.woff2','.ttf',
    '.eot','.pyc','.pyo','.so','.dll','.class','.jar','.war',
    '.mp4','.mp3','.avi','.mov','.webm','.webp','.bmp','.tiff',
}
SKIP_DIRS = {
    '.git','node_modules','__pycache__','.venv','venv',
    'dist','build','.terraform','.eggs','*.egg-info',
}


def scan_secrets(path: str) -> List[Finding]:
    findings = []

    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

        for filename in files:
            ext = os.path.splitext(filename)[1].lower()
            if ext in SKIP_EXTENSIONS:
                continue

            filepath = os.path.join(root, filename)
            rel      = os.path.relpath(filepath, path)

            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    for lineno, line in enumerate(f, 1):
                        for name, pattern, severity, message, remediation in SECRET_PATTERNS:
                            if pattern.search(line):
                                findings.append(Finding(
                                    severity=severity,
                                    message=message,
                                    file=rel,
                                    scanner="secrets",
                                    line=lineno,
                                    detail=f"Pattern: {name} matched on line {lineno}",
                                    remediation=remediation,
                                ))
                                break
            except (OSError, PermissionError):
                continue

    return findings
