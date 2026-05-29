# ShadowCI

ShadowCI is a high-performance repository security scanner designed for DevSecOps pipelines. It runs 11 vulnerability and misconfiguration scanners in parallel, generating comprehensive risk assessments in multiple formats (HTML, JSON, Markdown, and text).

## Features

- **11 Parallel Scanners**: Scans secrets, SAST, Dockerfiles, Kubernetes manifests, Terraform configs, GitHub Workflows, environment files, dependencies, world-writable file permissions, and `.gitignore` coverage.
- **AST-Based Python SAST**: Leverages Abstract Syntax Tree (AST) analysis for Python source files, significantly reducing false positives compared to standard pattern matching.
- **Multi-Format Reports**: Outputs text summaries to CLI and generates self-contained dark-themed HTML dashboards, JSON logs, and Markdown reports.
- **Enterprise-Ready**: Exits with non-zero status on critical/high findings for seamless CI/CD integration.

## Installation

```bash
git clone https://github.com/ne0k1ra/shadowci
cd shadowci
pip install -e .
```

## Usage

```bash
# Scan a directory
shadowci scan /path/to/repo

# Output in JSON format to stdout for piping
shadowci scan . --format json

# Skip specific scanners
shadowci scan . --skip permissions gitignore

# Run only specific scanners
shadowci scan . --only secrets sast

# View help and all flags
shadowci scan --help
```

## Scanners Included

| Scanner | Description |
|---------|-------------|
| `secrets` | Detects 60+ hardcoded credentials patterns (AWS, GCP, Azure, Slack, Stripe, private keys, etc.). |
| `sast` | Performs static analysis (AST-based for Python, regex for other languages) for injection, dangerous sinks, and weak crypto. |
| `supply_chain` | Checks for typosquatted dependencies and suspicious install-time code execution hooks. |
| `dockerfile` | Validates Dockerfiles against security best practices (no root USER, no unpinned tags, etc.). |
| `workflows` | Scans GitHub Actions workflows for script injections and unpinned steps. |
| `env` | Detects committed `.env` files and exposed configuration secrets. |
| `terraform` | Audits Terraform configs for public S3 buckets, open security groups, and missing encryption. |
| `kubernetes` | Scans manifests for privileged containers, hostPID/hostNetwork exposure, and missing resource limits. |
| `deps` | Checks dependencies for known CVEs. |
| `gitignore` | Audits `.gitignore` rules for missing configurations (secrets, keyfiles, build artifacts). |
| `permissions` | Scans for world-writable file permissions and SUID/SGID hazards. |

## License

This project is licensed under the MIT License.
