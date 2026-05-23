import os
import re
import glob
from typing import List
from ..models import Finding

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

SKIP_DIRS = {'.git', 'node_modules', '__pycache__'}


def _find_workflows(path: str) -> List[str]:
    workflows_dir = os.path.join(path, '.github', 'workflows')
    if not os.path.isdir(workflows_dir):
        return []
    return glob.glob(os.path.join(workflows_dir, '*.yml')) + \
           glob.glob(os.path.join(workflows_dir, '*.yaml'))


def _check_permissions(permissions, rel, findings, wf_name):
    if permissions is None:
        return
    if isinstance(permissions, str) and permissions == 'write-all':
        findings.append(Finding(
            severity="HIGH",
            message=f"Workflow '{wf_name}' uses write-all permissions",
            file=rel, scanner="workflows",
            detail="write-all grants excessive write access to all GitHub API scopes.",
            remediation="Use minimal permissions: permissions: contents: read. List only what's needed.",
        ))
    elif isinstance(permissions, dict):
        for scope, level in permissions.items():
            if level == 'write' and scope in ('contents', 'actions', 'deployments', 'packages'):
                findings.append(Finding(
                    severity="MEDIUM",
                    message=f"Workflow '{wf_name}' has write permission on scope '{scope}'",
                    file=rel, scanner="workflows",
                    detail=f"Scope '{scope}: write' may be broader than necessary.",
                    remediation=f"Verify '{scope}: write' is required. Prefer read-only where possible.",
                ))


def scan_github_workflows(path: str) -> List[Finding]:
    findings = []
    workflow_files = _find_workflows(path)
    if not workflow_files:
        return findings

    if not YAML_AVAILABLE:
        findings.append(Finding(
            severity="INFO",
            message="PyYAML not installed — workflow YAML parsing skipped",
            file=".github/workflows/", scanner="workflows",
            remediation="Run: pip install pyyaml",
        ))
        return findings

    for wf_path in workflow_files:
        rel = os.path.relpath(wf_path, path)
        try:
            with open(wf_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            data = yaml.safe_load(content)
        except (OSError, PermissionError, yaml.YAMLError):
            continue

        if not isinstance(data, dict):
            continue

        wf_name = data.get('name', os.path.basename(wf_path))
        on = data.get('on', data.get(True, {}))

        if isinstance(on, dict):
            if 'pull_request_target' in on:
                findings.append(Finding(
                    severity="HIGH",
                    message=f"Workflow '{wf_name}' uses dangerous pull_request_target trigger",
                    file=rel, scanner="workflows",
                    detail="pull_request_target runs with base repo secrets even for fork PRs — attackers can exfiltrate secrets.",
                    remediation="Replace with pull_request trigger. If pull_request_target is required, never checkout untrusted code in the same job.",
                ))

            if 'workflow_run' in on:
                findings.append(Finding(
                    severity="MEDIUM",
                    message=f"Workflow '{wf_name}' uses workflow_run trigger",
                    file=rel, scanner="workflows",
                    detail="workflow_run can trigger privileged workflows from untrusted inputs.",
                    remediation="Verify the triggering workflow is from a trusted branch/actor before executing privileged steps.",
                ))

        _check_permissions(data.get('permissions'), rel, findings, wf_name)

        jobs = data.get('jobs', {})
        if not isinstance(jobs, dict):
            continue

        for job_id, job in jobs.items():
            if not isinstance(job, dict):
                continue
            _check_permissions(job.get('permissions'), rel, findings, f"{wf_name}/{job_id}")

            for step in (job.get('steps', []) or []):
                if not isinstance(step, dict):
                    continue

                run_cmd = step.get('run', '')
                if isinstance(run_cmd, str):
                    if re.search(r'curl\s+.+\|\s*(ba)?sh', run_cmd, re.IGNORECASE) or \
                       re.search(r'wget\s+.+\|\s*(ba)?sh', run_cmd, re.IGNORECASE):
                        findings.append(Finding(
                            severity="HIGH",
                            message=f"Workflow '{wf_name}' step executes remote script via pipe to shell",
                            file=rel, scanner="workflows",
                            detail="Piping remote scripts to shell in CI is a supply-chain risk.",
                            remediation="Download the script, pin its SHA256, verify before executing.",
                        ))

                uses = step.get('uses', '')
                if isinstance(uses, str) and '@' in uses:
                    ref = uses.split('@')[-1]
                    if ref in ('main', 'master', 'latest', 'HEAD'):
                        findings.append(Finding(
                            severity="MEDIUM",
                            message=f"Workflow '{wf_name}' uses unpinned action: {uses}",
                            file=rel, scanner="workflows",
                            detail="Mutable branch refs can be compromised by supply-chain attacks.",
                            remediation=f"Pin to a full commit SHA: uses: {uses.split('@')[0]}@<sha256>  # {ref}",
                        ))

    return findings
