<div align="center">

```
███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██████╗██╗
██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║   ██╔════╝██║
███████╗███████║███████║██║  ██║██║   ██║██║   ██║     ██║
╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║   ██║     ██║
███████║██║  ██║██║  ██║██████╔╝╚██████╔╝██║   ╚██████╗██║
╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝╚═╝    ╚═════╝╚═╝
```

*「 The human whose name is written in this note shall perish. 」*

[![Version](https://img.shields.io/badge/version-2.0.0-cc0000?style=for-the-badge&labelColor=0a0000)](https://github.com/ne0k1r4/shadowci)
[![Python](https://img.shields.io/badge/python-3.10+-cc0000?style=for-the-badge&logo=python&logoColor=white&labelColor=0a0000)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-cc0000?style=for-the-badge&labelColor=0a0000)](LICENSE)
[![Author](https://img.shields.io/badge/author-ne0k1r4-cc0000?style=for-the-badge&labelColor=0a0000)](https://github.com/ne0k1r4)

**Repository Security Intelligence Scanner**  
11 parallel scanners · 60+ secret patterns · SAST · Supply chain · Death Note themed

</div>

---

## Overview

ShadowCI scans code repositories for security vulnerabilities before they reach production. It runs 11 scanners in parallel across your entire codebase and produces a comprehensive risk report in Markdown, JSON, and HTML.

```bash
shadowci scan /path/to/repo
shadowci scan . --format html
shadowci scan . --only secrets sast
```

---

## 11 Scanners

| Scanner | What it detects |
|---------|----------------|
| **Secrets** | 60+ patterns — AWS, GCP, Azure, GitHub, Slack, OpenAI, Anthropic, Stripe, npm, PyPI, private keys, DB URIs |
| **SAST Lite** | eval/exec/pickle, shell=True, SQL injection, XSS sinks, MD5/ECB, hardcoded credentials, SSRF |
| **Supply Chain** | Typosquatted packages (38), suspicious install scripts, malicious lifecycle hooks, build system abuse |
| **Dockerfile** | Secrets in ENV/ARG, root USER, chmod 777, no HEALTHCHECK, curl\|bash, COPY . . |
| **GitHub Workflows** | Script injection via `${{ github.event.* }}`, unpinned actions, secrets in untrusted triggers, OIDC misconfig |
| **Env Files** | .env files committed, missing .env in .gitignore, production secrets in dev configs |
| **Terraform** | Hardcoded credentials, open security groups, unencrypted S3/RDS, missing state encryption |
| **Kubernetes** | Privileged containers, hostPID/hostNetwork, missing resource limits, root containers |
| **Dependencies** | Known CVEs in requirements.txt/package.json/Gemfile |
| **.gitignore** | Missing coverage for secrets, keys, env files, IDE configs, build artifacts |
| **File Permissions** | World-writable files, executable scripts without shebangs, SUID/SGID bits |

---

## Install

```bash
git clone https://github.com/ne0k1r4/shadowci
cd shadowci
pip install -e .
```

---

## Usage

```bash
# Scan current directory
shadowci scan .

# Scan specific path
shadowci scan /path/to/repo

# HTML report
shadowci scan . --format html

# Run specific scanners only
shadowci scan . --only secrets sast supply_chain

# Skip certain scanners
shadowci scan . --skip permissions gitignore

# JSON output for piping
shadowci scan . --format json | jq '.findings[] | select(.severity=="CRITICAL")'
```

---

## Output

```
┌─────────────────────────────────────────────────────┐
│          ☠  RYUK'S JUDGMENT — CONDEMNED  ☠          │
│                                                     │
│   CRITICAL  ████████████░░░░░░░░░░  8               │
│   HIGH      ██████░░░░░░░░░░░░░░░░  4               │
│   MEDIUM    ████░░░░░░░░░░░░░░░░░░  3               │
│   LOW       ██░░░░░░░░░░░░░░░░░░░░  2               │
└─────────────────────────────────────────────────────┘

  [CRITICAL] secrets     OpenAI API Key detected — src/config.py:14
  [CRITICAL] sast        eval() — arbitrary code execution — app/utils.py:88
  [CRITICAL] supply      Typosquatted package: 'requets' (did you mean 'requests'?)
  [HIGH]     dockerfile  Container runs as root — Dockerfile:31
  [HIGH]     workflows   Script injection via ${{ github.event.pull_request.title }}
```

Reports saved to:
```
shadowci_report.md      markdown findings table
shadowci_report.json    machine-readable full output
shadowci_report.html    dark themed interactive dashboard
```

---

## Secret Patterns (60+)

<details>
<summary>Cloud Providers</summary>

AWS (Access Key, Secret Key, Session Token) · GCP (API Key, Service Account JSON) · Azure (Connection String, Client Secret, SAS Token)

</details>

<details>
<summary>Developer Tools</summary>

GitHub (PAT, Fine-grained PAT, OAuth, Actions Token) · GitLab · npm Auth Token · PyPI Token · Terraform Cloud · HashiCorp Vault

</details>

<details>
<summary>Communication</summary>

Slack (Webhook, Bot Token) · Discord (Webhook, Bot Token) · Twilio · SendGrid · Mailgun

</details>

<details>
<summary>AI / APIs</summary>

OpenAI · Anthropic · Hugging Face · Google API Key · Cloudflare · Linear · Notion · Figma · Doppler · 1Password

</details>

<details>
<summary>Databases & Keys</summary>

PostgreSQL DSN · MySQL DSN · MongoDB URI · Redis URL · RSA Private Key · OpenSSH Private Key · PGP Private Key Block

</details>

<details>
<summary>Payment</summary>

Stripe (Secret Key, Restricted Key, Webhook) · PayPal

</details>

---

## SAST Patterns (32)

Detects dangerous code patterns across Python, JavaScript/TypeScript, PHP, and more:

**Python:** `eval()`, `exec()`, `pickle.loads()`, `marshal.loads()`, `subprocess(shell=True)`, `os.system()`, `yaml.load()` without SafeLoader, `hashlib.md5/sha1`, `random` for crypto, SQL f-string injection

**JavaScript:** `eval()`, `innerHTML =`, `document.write()`, `dangerouslySetInnerHTML`, `setTimeout` with string

**PHP:** `eval()`, `system()`, `exec()`, `shell_exec()`, SQL concatenation

**Generic:** Hardcoded passwords/secrets/tokens, DES/3DES/ECB cipher, path traversal via user input, SSRF sinks, debug mode enabled

---

## Supply Chain Detection

**Typosquatted packages (38):**  
`requets`, `djago`, `axois`, `loadash`, `colourama`, `cryptograpy`, and 32 more

**Suspicious install patterns:**
- `curl ... | bash` in setup.py or package.json postinstall
- Base64 decode in install scripts
- Socket connections at install time
- Access to `~/.ssh`, `~/.aws`, `~/.config` directories
- `shell=True` subprocess calls

---

## Verdict System

| Verdict | Condition |
|---------|-----------|
| ☠ **CONDEMNED** | 1+ CRITICAL findings |
| ⚠ **SUSPECTED** | HIGH findings, no CRITICAL |
| ◈ **WATCHING** | MEDIUM findings only |
| ✔ **ABSOLVED** | LOW/INFO only |
| ✦ **CLEAN** | No findings |

---

## Changelog

See [CHANGELOG.md](CHANGELOG.md)

---

## Disclaimer

For authorized security auditing of repositories you own or have permission to scan.

---

<div align="center">
<br>
<i>「 This world is rotten, and those who are making it rot deserve to die. 」</i>
<br><br>

[![GitHub](https://img.shields.io/badge/github.com%2Fne0k1r4-cc0000?style=flat-square&labelColor=0a0000&logo=github&logoColor=white)](https://github.com/ne0k1r4)

</div>
