import os
import re
from typing import List
from ..models import Finding

DOCKERFILE_NAMES = {"Dockerfile", "dockerfile"}
SKIP_DIRS = {'.git', 'node_modules', '__pycache__'}


def _find_dockerfiles(path: str) -> List[str]:
    results = []
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for f in files:
            if f in DOCKERFILE_NAMES or f.startswith("Dockerfile.") or f.endswith(".dockerfile"):
                results.append(os.path.join(root, f))
    return results


def scan_dockerfile(path: str) -> List[Finding]:
    findings = []
    for df_path in _find_dockerfiles(path):
        rel = os.path.relpath(df_path, path)
        try:
            with open(df_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
        except (OSError, PermissionError):
            continue

        for lineno, line in enumerate(lines, 1):
            stripped = line.strip()

            if re.match(r'^USER\s+root\s*$', stripped, re.IGNORECASE):
                findings.append(Finding(
                    severity="HIGH",
                    message="Dockerfile runs container as root",
                    file=rel, scanner="dockerfile", line=lineno,
                    detail="Running as root enables container breakout attacks.",
                    remediation="Add a non-root user: RUN useradd -m appuser && USER appuser",
                ))

            m = re.match(r'^FROM\s+([^\s]+)', stripped, re.IGNORECASE)
            if m:
                image = m.group(1)
                if image.endswith(':latest') or (':' not in image and '@' not in image):
                    findings.append(Finding(
                        severity="MEDIUM",
                        message=f"Dockerfile uses unpinned image tag: {image}",
                        file=rel, scanner="dockerfile", line=lineno,
                        detail="Using :latest produces unpredictable, unreproducible builds.",
                        remediation=f"Pin to a digest: FROM {image.split(':')[0]}@sha256:<hash>",
                    ))

            if re.search(r'curl\s+.+\|\s*(ba)?sh', stripped, re.IGNORECASE) or \
               re.search(r'wget\s+.+\|\s*(ba)?sh', stripped, re.IGNORECASE):
                findings.append(Finding(
                    severity="CRITICAL",
                    message="Dockerfile executes remote script via pipe to shell",
                    file=rel, scanner="dockerfile", line=lineno,
                    detail="curl/wget | sh is a supply-chain attack vector.",
                    remediation="Download the script, verify its checksum, then execute it separately.",
                ))

            if re.match(r'^EXPOSE\s+22(\s|$)', stripped, re.IGNORECASE):
                findings.append(Finding(
                    severity="HIGH",
                    message="Dockerfile exposes SSH port (22)",
                    file=rel, scanner="dockerfile", line=lineno,
                    detail="Exposing port 22 increases attack surface unnecessarily.",
                    remediation="Remove EXPOSE 22. Use kubectl exec or docker exec for shell access instead.",
                ))

            if re.match(r'^ADD\s+https?://', stripped, re.IGNORECASE):
                findings.append(Finding(
                    severity="MEDIUM",
                    message="Dockerfile uses ADD with remote URL",
                    file=rel, scanner="dockerfile", line=lineno,
                    detail="ADD with remote URL has no checksum verification.",
                    remediation="Use: RUN curl -L <url> -o file && echo '<sha256>  file' | sha256sum -c",
                ))

            if re.match(r'^(ENV|ARG)\s+.*(PASSWORD|SECRET|KEY|TOKEN)\s*=\s*\S+', stripped, re.IGNORECASE):
                findings.append(Finding(
                    severity="HIGH",
                    message="Possible secret in Dockerfile ENV/ARG instruction",
                    file=rel, scanner="dockerfile", line=lineno,
                    detail="Secrets baked into ENV/ARG are visible in image layers and docker inspect.",
                    remediation="Use Docker BuildKit secrets: RUN --mount=type=secret,id=mykey ...",
                ))

    return findings
