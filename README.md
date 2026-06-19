# shadowci

A simple, fast security scanner for git repositories. It runs multiple checks in parallel (secrets, AST-based SAST, Dockerfile, Terraform, etc.) and generates reports in HTML, JSON, or Markdown.

## Installation

```bash
git clone https://github.com/ne0k1ra/shadowci
cd shadowci
pip install -e .
```

## Quick Start

```bash
# Scan a folder
shadowci scan .

# Run only specific scanners
shadowci scan . --only secrets sast

# Skip some checks
shadowci scan . --skip permissions gitignore

# Output raw JSON to stdout (handy for jq)
shadowci scan . --format json
```

## What it checks

- **secrets**: Looks for API keys, AWS credentials, private keys, etc. (60+ patterns).
- **sast**: Static analysis. Uses Python AST for python files (to minimize false positives) and regex fallback for JS/PHP/etc.
- **supply_chain**: Scans package.json and requirements.txt for typosquats and suspicious install scripts.
- **dockerfile**: Checks for USER root, unpinned base images, and secrets in ENV/ARG.
- **workflows**: Detects script injection in GitHub Actions.
- **env**: Finds committed `.env` files.
- **terraform & kubernetes**: Audits configs for open ports, privileged containers, and missing encryption.
- **deps**: Checks dependency manifests for known vulnerabilities.
- **gitignore & permissions**: Audits gitignore coverage and checks for world-writable files.

## License
MIT
