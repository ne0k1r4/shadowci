"""
Kubernetes scanner — detects misconfigurations in K8s manifests.
Covers Deployments, Pods, Services, RBAC, Ingress, NetworkPolicies.
"""
import os
import glob
from typing import List
from ..models import Finding

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

SKIP_DIRS = {'.git', 'node_modules', '__pycache__', '.venv', 'venv'}

K8S_KINDS = {
    'Pod', 'Deployment', 'DaemonSet', 'StatefulSet', 'ReplicaSet',
    'Job', 'CronJob', 'Service', 'Ingress', 'NetworkPolicy',
    'ClusterRole', 'ClusterRoleBinding', 'Role', 'RoleBinding',
    'ServiceAccount', 'ConfigMap', 'Secret', 'PersistentVolumeClaim',
}


def _find_k8s_manifests(path: str) -> List[str]:
    results = []
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for f in files:
            if f.endswith('.yaml') or f.endswith('.yml'):
                results.append(os.path.join(root, f))
    return results


def _check_container_security(container: dict, rel: str, ctx: str, findings: List[Finding]):
    name = container.get('name', 'unnamed')

    # securityContext checks
    sc = container.get('securityContext', {})

    if sc.get('privileged') is True:
        findings.append(Finding(
            severity="CRITICAL",
            message=f"Container '{name}' runs in privileged mode",
            file=rel, scanner="kubernetes",
            detail=f"Context: {ctx}. Privileged containers have full host access.",
            remediation="Set securityContext.privileged: false. Use specific capabilities instead.",
        ))

    if sc.get('runAsRoot') is True or sc.get('runAsUser') == 0:
        findings.append(Finding(
            severity="HIGH",
            message=f"Container '{name}' is configured to run as root (UID 0)",
            file=rel, scanner="kubernetes",
            detail=f"Context: {ctx}",
            remediation="Set securityContext.runAsNonRoot: true and runAsUser to a non-zero UID.",
        ))

    if sc.get('runAsNonRoot') is False:
        findings.append(Finding(
            severity="HIGH",
            message=f"Container '{name}' explicitly allows running as root",
            file=rel, scanner="kubernetes",
            detail=f"Context: {ctx}. runAsNonRoot: false overrides pod-level security.",
            remediation="Remove runAsNonRoot: false or set it to true.",
        ))

    if sc.get('allowPrivilegeEscalation') is True:
        findings.append(Finding(
            severity="HIGH",
            message=f"Container '{name}' allows privilege escalation",
            file=rel, scanner="kubernetes",
            detail=f"Context: {ctx}. allowPrivilegeEscalation: true is dangerous.",
            remediation="Set securityContext.allowPrivilegeEscalation: false.",
        ))

    if sc.get('readOnlyRootFilesystem') is False:
        findings.append(Finding(
            severity="MEDIUM",
            message=f"Container '{name}' has writable root filesystem",
            file=rel, scanner="kubernetes",
            detail=f"Context: {ctx}. Writable root filesystem enables attackers to modify binaries.",
            remediation="Set securityContext.readOnlyRootFilesystem: true. Use volumeMounts for writable paths.",
        ))

    caps = sc.get('capabilities', {})
    dangerous_caps = {'NET_ADMIN', 'SYS_ADMIN', 'SYS_PTRACE', 'SYS_MODULE',
                      'DAC_OVERRIDE', 'NET_RAW', 'SYS_TIME', 'AUDIT_WRITE'}
    added_caps = set(caps.get('add', []))
    bad_caps = added_caps & dangerous_caps
    if 'ALL' in added_caps:
        findings.append(Finding(
            severity="CRITICAL",
            message=f"Container '{name}' adds ALL capabilities",
            file=rel, scanner="kubernetes",
            detail=f"Context: {ctx}. capabilities.add: [ALL] grants full root-equivalent access.",
            remediation="Drop ALL capabilities and add only what is strictly needed.",
        ))
    elif bad_caps:
        findings.append(Finding(
            severity="HIGH",
            message=f"Container '{name}' adds dangerous capabilities: {', '.join(sorted(bad_caps))}",
            file=rel, scanner="kubernetes",
            detail=f"Context: {ctx}. These capabilities enable host-level access.",
            remediation=f"Remove capabilities: {', '.join(sorted(bad_caps))}. Apply principle of least privilege.",
        ))

    # Resource limits
    resources = container.get('resources', {})
    if not resources.get('limits'):
        findings.append(Finding(
            severity="MEDIUM",
            message=f"Container '{name}' has no resource limits defined",
            file=rel, scanner="kubernetes",
            detail=f"Context: {ctx}. No CPU/memory limits can cause resource exhaustion (DoS).",
            remediation="Add resources.limits.cpu and resources.limits.memory.",
        ))

    # Env var secrets
    for env in container.get('env', []):
        env_name = env.get('name', '')
        value    = env.get('value', '')
        import re
        if re.search(r'(?i)(password|secret|token|key|credential)', env_name) and value:
            findings.append(Finding(
                severity="HIGH",
                message=f"Container '{name}' has sensitive env var '{env_name}' hardcoded",
                file=rel, scanner="kubernetes",
                detail=f"Context: {ctx}. Hardcoded secrets in env are visible in kubectl describe.",
                remediation="Use secretKeyRef to pull from a Kubernetes Secret instead of hardcoding.",
            ))

    # Image tag
    image = container.get('image', '')
    if image and (':latest' in image or (':' not in image and '@' not in image)):
        findings.append(Finding(
            severity="MEDIUM",
            message=f"Container '{name}' uses unpinned image: {image}",
            file=rel, scanner="kubernetes",
            detail=f"Context: {ctx}. :latest tags lead to unpredictable deployments.",
            remediation="Pin to a specific digest: image: nginx@sha256:abc123...",
        ))

    # hostPath volume mounts — dangerous
    # (checked at pod level below)


def _check_pod_spec(spec: dict, rel: str, ctx: str, findings: List[Finding]):
    # Pod-level security context
    psc = spec.get('securityContext', {})

    if psc.get('hostPID') is True or spec.get('hostPID') is True:
        findings.append(Finding(
            severity="CRITICAL",
            message="Pod shares host PID namespace",
            file=rel, scanner="kubernetes",
            detail=f"Context: {ctx}. hostPID: true lets the container see and signal all host processes.",
            remediation="Remove hostPID: true from pod spec.",
        ))

    if psc.get('hostNetwork') is True or spec.get('hostNetwork') is True:
        findings.append(Finding(
            severity="HIGH",
            message="Pod uses host network namespace",
            file=rel, scanner="kubernetes",
            detail=f"Context: {ctx}. hostNetwork bypasses network isolation.",
            remediation="Remove hostNetwork: true unless absolutely required.",
        ))

    if spec.get('hostIPC') is True:
        findings.append(Finding(
            severity="HIGH",
            message="Pod shares host IPC namespace",
            file=rel, scanner="kubernetes",
            detail=f"Context: {ctx}. Shared IPC namespace can leak inter-process communication.",
            remediation="Remove hostIPC: true from pod spec.",
        ))

    # Volumes — hostPath
    for vol in spec.get('volumes', []):
        hp = vol.get('hostPath', {})
        if hp:
            hp_path = hp.get('path', '/')
            sev = "CRITICAL" if any(p in hp_path for p in ['/', '/etc', '/var/run', '/proc', '/sys']) else "HIGH"
            findings.append(Finding(
                severity=sev,
                message=f"Pod mounts sensitive host path: {hp_path}",
                file=rel, scanner="kubernetes",
                detail=f"Context: {ctx}. hostPath mounts expose the underlying node filesystem.",
                remediation="Use PersistentVolumeClaims or ConfigMaps instead of hostPath mounts.",
            ))

    # Containers
    for c in spec.get('containers', []) + spec.get('initContainers', []):
        _check_container_security(c, rel, ctx, findings)

    # Service account token automount
    if spec.get('automountServiceAccountToken') is True:
        findings.append(Finding(
            severity="MEDIUM",
            message="Pod auto-mounts service account token",
            file=rel, scanner="kubernetes",
            detail=f"Context: {ctx}. Mounted SA tokens can be used for API server attacks if compromised.",
            remediation="Set automountServiceAccountToken: false unless the app needs K8s API access.",
        ))


def _check_rbac(doc: dict, rel: str, findings: List[Finding]):
    kind  = doc.get('kind', '')
    name  = doc.get('metadata', {}).get('name', 'unnamed')
    rules = doc.get('rules', [])

    for rule in rules:
        verbs       = rule.get('verbs', [])
        resources   = rule.get('resources', [])
        api_groups  = rule.get('apiGroups', [])

        # Wildcard verbs or resources
        if '*' in verbs and '*' in resources:
            findings.append(Finding(
                severity="CRITICAL",
                message=f"RBAC {kind} '{name}' grants wildcard verbs on wildcard resources",
                file=rel, scanner="kubernetes",
                detail="This grants full cluster admin equivalent access.",
                remediation="Replace wildcards with minimal required verbs and specific resources.",
            ))
        elif '*' in verbs:
            res_str = ', '.join(resources[:3])
            findings.append(Finding(
                severity="HIGH",
                message=f"RBAC {kind} '{name}' grants wildcard verbs on: {res_str}",
                file=rel, scanner="kubernetes",
                detail="Wildcard verbs include create, delete, patch — excessive privilege.",
                remediation="Specify only the verbs actually needed (get, list, watch).",
            ))

        # Dangerous resource access
        dangerous = {'secrets', 'pods/exec', 'pods/attach', 'nodes', 'clusterroles', 'rolebindings'}
        matched = set(resources) & dangerous
        if matched and any(v in verbs for v in ['create', 'update', 'patch', 'delete', '*']):
            findings.append(Finding(
                severity="HIGH",
                message=f"RBAC {kind} '{name}' has write access to sensitive resources: {', '.join(sorted(matched))}",
                file=rel, scanner="kubernetes",
                detail="Write access to secrets/exec/nodes can lead to full cluster compromise.",
                remediation="Restrict verbs to read-only (get, list, watch) for sensitive resources.",
            ))


def _check_service(doc: dict, rel: str, findings: List[Finding]):
    name    = doc.get('metadata', {}).get('name', 'unnamed')
    svc_type = doc.get('spec', {}).get('type', 'ClusterIP')

    if svc_type == 'NodePort':
        findings.append(Finding(
            severity="MEDIUM",
            message=f"Service '{name}' uses NodePort — exposed on every cluster node",
            file=rel, scanner="kubernetes",
            detail="NodePort services are reachable on all node IPs from outside the cluster.",
            remediation="Use ClusterIP + Ingress or LoadBalancer with restricted source IP ranges.",
        ))

    if svc_type == 'LoadBalancer':
        findings.append(Finding(
            severity="INFO",
            message=f"Service '{name}' is a LoadBalancer (publicly accessible)",
            file=rel, scanner="kubernetes",
            detail="Ensure source IP restrictions are configured if this service is external-facing.",
            remediation="Add spec.loadBalancerSourceRanges to restrict access to known IPs.",
        ))


def _check_ingress(doc: dict, rel: str, findings: List[Finding]):
    name = doc.get('metadata', {}).get('name', 'unnamed')
    spec = doc.get('spec', {})
    anns = doc.get('metadata', {}).get('annotations', {})

    # TLS check
    if not spec.get('tls'):
        findings.append(Finding(
            severity="HIGH",
            message=f"Ingress '{name}' has no TLS configured",
            file=rel, scanner="kubernetes",
            detail="Unencrypted HTTP traffic exposes users to MITM attacks.",
            remediation="Add spec.tls with a valid certificate (use cert-manager for automation).",
        ))

    # Force SSL redirect
    redirect = anns.get('nginx.ingress.kubernetes.io/ssl-redirect',
               anns.get('kubernetes.io/ingress.allow-http', 'true'))
    if str(redirect).lower() == 'true' and 'allow-http' in str(anns):
        findings.append(Finding(
            severity="MEDIUM",
            message=f"Ingress '{name}' allows plain HTTP",
            file=rel, scanner="kubernetes",
            detail="HTTP traffic is not redirected to HTTPS.",
            remediation="Set nginx.ingress.kubernetes.io/ssl-redirect: 'true'",
        ))


def scan_kubernetes(path: str) -> List[Finding]:
    if not YAML_AVAILABLE:
        return []

    findings = []
    manifest_files = _find_k8s_manifests(path)

    for mf_path in manifest_files:
        rel = os.path.relpath(mf_path, path)
        try:
            with open(mf_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except (OSError, PermissionError):
            continue

        try:
            docs = list(yaml.safe_load_all(content))
        except yaml.YAMLError:
            continue

        for doc in docs:
            if not isinstance(doc, dict):
                continue

            kind = doc.get('kind', '')
            if kind not in K8S_KINDS:
                continue

            name = doc.get('metadata', {}).get('name', 'unnamed')
            ctx  = f"{kind}/{name}"

            if kind in ('Pod',):
                _check_pod_spec(doc.get('spec', {}), rel, ctx, findings)

            elif kind in ('Deployment', 'DaemonSet', 'StatefulSet', 'ReplicaSet'):
                pod_spec = doc.get('spec', {}).get('template', {}).get('spec', {})
                _check_pod_spec(pod_spec, rel, ctx, findings)

            elif kind == 'CronJob':
                pod_spec = (doc.get('spec', {})
                               .get('jobTemplate', {})
                               .get('spec', {})
                               .get('template', {})
                               .get('spec', {}))
                _check_pod_spec(pod_spec, rel, ctx, findings)

            elif kind in ('ClusterRole', 'Role'):
                _check_rbac(doc, rel, findings)

            elif kind == 'Service':
                _check_service(doc, rel, findings)

            elif kind == 'Ingress':
                _check_ingress(doc, rel, findings)

            # Kubernetes Secret in plaintext YAML
            elif kind == 'Secret':
                data = doc.get('data', {})
                string_data = doc.get('stringData', {})
                secret_name = doc.get('metadata', {}).get('name', 'unnamed')
                if string_data:
                    findings.append(Finding(
                        severity="HIGH",
                        message=f"Kubernetes Secret '{secret_name}' uses stringData (plaintext in YAML)",
                        file=rel, scanner="kubernetes",
                        detail="stringData values are stored unencoded in YAML and may be committed to git.",
                        remediation="Use sealed-secrets, Vault Agent, or external-secrets-operator instead of committing K8s Secret manifests.",
                    ))
                if data:
                    findings.append(Finding(
                        severity="MEDIUM",
                        message=f"Kubernetes Secret '{secret_name}' manifest committed to repository",
                        file=rel, scanner="kubernetes",
                        detail="Even base64-encoded secrets in git are effectively plaintext.",
                        remediation="Use sealed-secrets or external-secrets-operator. Never commit Secret manifests.",
                    ))

    return findings
