# ✦ ShadowCI

> *「 The human whose name is written in this note shall perish. 」*

**Repository Security Intelligence Scanner — Death Note Edition**  
by `ne0k1ra`

---

ShadowCI judges your repository before it reaches production.  
It finds leaked secrets, insecure containers, risky CI pipelines, exposed environment files, and infrastructure misconfigurations.

```
shadowci scan myproject/
```

```
  ╔══════════════════════════════════════════════════════════════════╗
  ║                                                                  ║
  ║  ███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗ ██████╗██╗║
  ║  ...                                                             ║
  ║  Repository Security Intelligence Scanner   v1.1.0  ne0k1ra     ║
  ║  「 If you can see it — you can judge it. 」                    ║
  ╚══════════════════════════════════════════════════════════════════╝

  ✦ Ryuk:  "Humans are so interesting... especially when they leave secrets exposed."

  ── Target  /home/ne0k1ra/myproject
  ── Mode    full judgment scan

  ╔══════════════════╗
  ║  † CRITICAL (4)  ║
  ╚══════════════════╝

  [† CRITICAL]  AWS Access Key ID detected
               ↳ config/settings.py:42

  [† CRITICAL]  Environment file exposed: .env
               ↳ .env

  ╔══════════════════╗
  ║  ⚠ HIGH (3)      ║
  ╚══════════════════╝

  [⚠ HIGH]  Dockerfile runs container as root
            ↳ Dockerfile:18

  [⚠ HIGH]  Workflow uses dangerous pull_request_target trigger
            ↳ .github/workflows/deploy.yml

  ════════════════════════════════════════════════════════════════
  JUDGMENT — CASE FILE SUMMARY

  † CRITICAL    ████████████████  8
  ⚠ HIGH        ██████████        6
  ◈ MEDIUM      ████              4

  Verdict:  †  CONDEMNED  †
            This repository has been written in the Death Note.

  Total findings : 18
  Scan duration  : 0.041s
  ════════════════════════════════════════════════════════════════

  Case files written:
    ✦  shadowci_report.md
    ✦  shadowci_report.json

  「 The names have been written. There is no going back. 」
```

---

## Install

```bash
git clone https://github.com/ne0k1ra/shadowci
cd shadowci
pip install -e .
```

Or without installing:
```bash
pip install pyyaml
python -m shadowci.cli scan myrepo/
```

---

## Usage

```bash
shadowci scan <path>              # Full judgment scan
shadowci scan <path> -q           # Quiet — no per-scanner output
shadowci scan <path> -o reports/  # Custom report output directory
shadowci help                     # Show help page
```

---

## What Gets Judged

| Scanner | What It Finds | Severity |
|---------|---------------|----------|
| **Secrets** | AWS keys, GitHub tokens, Stripe live keys, JWT tokens, private keys, hardcoded passwords | CRITICAL / HIGH |
| **Dockerfile** | `USER root`, `:latest` tags, `curl \| sh`, `EXPOSE 22`, secrets in `ENV` | CRITICAL / HIGH / MEDIUM |
| **Workflows** | `pull_request_target`, `write-all` permissions, unpinned actions (`@main`, `@master`), `curl \| bash` in steps | HIGH / MEDIUM |
| **Env Files** | `.env`, `.env.*`, `.envrc` — plus analysis of actual credential values inside | CRITICAL |
| **Terraform** | `0.0.0.0/0` ingress rules, public S3 ACLs, hardcoded credentials, wildcard IAM `Action: *`, `encrypted = false` | CRITICAL / HIGH / MEDIUM |

---

## Output

Every scan produces two case files:

**`shadowci_report.md`** — Human-readable judgment report for security teams.  
**`shadowci_report.json`** — Machine-readable for CI pipelines, dashboards, and SIEM integration.

JSON structure:
```json
{
  "shadowci": { "version": "1.0.0", "edition": "Death Note" },
  "scan": { "verdict": "CONDEMNED", "target": "/path/to/repo" },
  "summary": { "total": 18, "critical": 8, "high": 6, "medium": 4 },
  "findings": [
    {
      "severity": "CRITICAL",
      "message": "AWS Access Key ID detected",
      "file": "config/settings.py",
      "line": 42,
      "scanner": "secrets",
      "detail": "Pattern: AWS Access Key matched on line 42"
    }
  ]
}
```

---

## CI/CD Integration

```yaml
# .github/workflows/security.yml
- name: ShadowCI Security Scan
  run: |
    pip install shadowci
    shadowci scan . -o security-reports/
  # Exits with code 1 if CRITICAL or HIGH findings are found
```

Exit codes:

| Code | Meaning |
|------|---------|
| `0` | Clean — no CRITICAL or HIGH findings |
| `1` | Condemned — CRITICAL or HIGH findings detected |

---

## Architecture

```
shadowci/
├── cli.py              ← Death Note themed terminal UI
├── engine.py           ← Coordinator — runs all scanners
├── models.py           ← Finding dataclass (severity, message, file, line, detail)
├── scanners/
│   ├── secrets.py      ← 10 regex patterns
│   ├── dockerfile.py   ← Container security
│   ├── workflows.py    ← GitHub Actions analysis (YAML parsed)
│   ├── env_files.py    ← Env file detection + credential value analysis
│   └── terraform.py    ← IaC misconfiguration detection
└── reporters/
    ├── markdown.py     ← Death Note themed .md report
    └── json_report.py  ← Structured JSON output
```

---

## The ne0k1ra Toolchain

```
kira-installer  →  hardened Arch Linux deployment
wraith-net      →  attack surface intelligence
lightscan       →  network recon engine
shadowci        →  repo & pipeline security scanner  ← you are here
grimoire        →  operator control center
```

---

> *「 I'll take a potato chip... and eat it. 」 — Light Yagami*

*ShadowCI — by ne0k1ra*
