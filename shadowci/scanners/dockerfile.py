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
    # classic mistakes: running as root, latest tag, curl piped to bash
    # TODO: check for --no-cache-dir on pip installs
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

            # ── New checks ────────────────────────────────────────────────────

            # No HEALTHCHECK defined (check at file level after loop)
            if re.match(r'^RUN\s+chmod\s+(777|0777|a\+rwx)', stripped, re.IGNORECASE):
                findings.append(Finding(
                    severity="HIGH",
                    message="Dockerfile sets world-writable permissions (chmod 777)",
                    file=rel, scanner="dockerfile", line=lineno,
                    detail="chmod 777 allows any process to modify files — privilege escalation risk.",
                    remediation="Use minimal permissions. chmod 755 for executables, 644 for files.",
                ))

            if re.match(r'^RUN\s+.*apt-get\s+install.*--no-install-recommends', stripped, re.IGNORECASE) is None and \
               re.match(r'^RUN\s+.*apt-get\s+install', stripped, re.IGNORECASE):
                findings.append(Finding(
                    severity="LOW",
                    message="apt-get install missing --no-install-recommends",
                    file=rel, scanner="dockerfile", line=lineno,
                    detail="Without --no-install-recommends, extra packages bloat the image and increase attack surface.",
                    remediation="Use: apt-get install -y --no-install-recommends <packages>",
                ))

            if re.match(r'^COPY\s+\.\s+\.', stripped, re.IGNORECASE) or \
               re.match(r'^ADD\s+\.\s+\.', stripped, re.IGNORECASE):
                findings.append(Finding(
                    severity="MEDIUM",
                    message="Dockerfile copies entire build context into image",
                    file=rel, scanner="dockerfile", line=lineno,
                    detail="Copying '.' may include .env, .git, secrets, and other sensitive files.",
                    remediation="Use a .dockerignore file. Copy only what's needed: COPY src/ /app/src/",
                ))

            if re.match(r'^RUN\s+.*pip\s+install(?!\s+--no-cache-dir)', stripped, re.IGNORECASE) and \
               '--no-cache-dir' not in stripped:
                findings.append(Finding(
                    severity="LOW",
                    message="pip install missing --no-cache-dir",
                    file=rel, scanner="dockerfile", line=lineno,
                    detail="Without --no-cache-dir, pip stores cache in the image layer, increasing size.",
                    remediation="Use: pip install --no-cache-dir <packages>",
                ))

            if re.match(r'^RUN\s+.*sudo\b', stripped, re.IGNORECASE):
                findings.append(Finding(
                    severity="MEDIUM",
                    message="Dockerfile uses sudo in RUN instruction",
                    file=rel, scanner="dockerfile", line=lineno,
                    detail="Using sudo in Dockerfiles is a sign of incorrect user management.",
                    remediation="Run as root during build with USER root, then switch back to appuser.",
                ))

            if re.match(r'^RUN\s+.*wget\s+.*-O\s+-\s*\|\s*sh', stripped, re.IGNORECASE) or \
               re.match(r'^RUN\s+.*curl\s+.*-o\s+-\s*\|\s*sh', stripped, re.IGNORECASE):
                findings.append(Finding(
                    severity="CRITICAL",
                    message="Dockerfile pipes downloaded content directly to shell",
                    file=rel, scanner="dockerfile", line=lineno,
                    detail="Piping downloads to shell is a supply chain attack vector.",
                    remediation="Download to file, verify checksum, then execute separately.",
                ))

        # File-level checks
        full_content = "".join(lines).upper()
        if "HEALTHCHECK" not in full_content:
            findings.append(Finding(
                severity="LOW",
                message="Dockerfile missing HEALTHCHECK instruction",
                file=rel, scanner="dockerfile", line=0,
                detail="Without HEALTHCHECK, Docker can't detect unhealthy containers automatically.",
                remediation="Add: HEALTHCHECK --interval=30s CMD curl -f http://localhost/ || exit 1",
            ))

        if "USER " not in full_content or full_content.count("USER ROOT") > 0:
            if "USER ROOT" in full_content and full_content.rfind("USER ROOT") > full_content.rfind("USER "):
                findings.append(Finding(
                    severity="HIGH",
                    message="Dockerfile final USER is root",
                    file=rel, scanner="dockerfile", line=0,
                    detail="Container runs as root — enables container breakout.",
                    remediation="Add non-root user before final CMD/ENTRYPOINT.",
                ))

    return findings
