import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional, Callable
from .models import Finding, deduplicate
from .scanners.secrets        import scan_secrets
from .scanners.dockerfile     import scan_dockerfile
from .scanners.workflows      import scan_github_workflows
from .scanners.env_files      import scan_env_files
from .scanners.terraform      import scan_terraform
from .scanners.gitignore_check import scan_gitignore
from .scanners.dependencies   import scan_dependencies
from .scanners.kubernetes     import scan_kubernetes
from .scanners.permissions    import scan_permissions

ALL_SCANNERS = [
    ("secrets",    "Secrets",             scan_secrets),
    ("dockerfile", "Dockerfile",          scan_dockerfile),
    ("workflows",  "GitHub Workflows",    scan_github_workflows),
    ("env",        "Env Files",           scan_env_files),
    ("terraform",  "Terraform",           scan_terraform),
    ("gitignore",  ".gitignore Coverage", scan_gitignore),
    ("deps",       "Dependencies",        scan_dependencies),
    ("kubernetes", "Kubernetes",          scan_kubernetes),
    ("permissions","File Permissions",    scan_permissions),
]


def run_scan(
    path: str,
    verbose:          bool = False,
    only:             Optional[List[str]] = None,
    min_severity:     Optional[str] = None,
    on_scanner_start: Optional[Callable[[str, str], None]] = None,
    on_scanner_done:  Optional[Callable[[str, str, int, float], None]] = None,
    parallel:         bool = True,
) -> List[Finding]:
    path = os.path.abspath(path)
    if not os.path.exists(path):
        raise FileNotFoundError(f"Target path does not exist: {path}")

    from .models import SEVERITY_ORDER
    min_order = SEVERITY_ORDER.get(min_severity, 99) if min_severity else 99

    active = [(sid, name, fn) for sid, name, fn in ALL_SCANNERS
              if only is None or sid in only]

    all_findings: List[Finding] = []

    if parallel and len(active) > 1:
        # Run scanners in parallel — significant speedup on large repos
        futures = {}
        with ThreadPoolExecutor(max_workers=min(len(active), 6)) as pool:
            for sid, name, fn in active:
                if on_scanner_start:
                    on_scanner_start(sid, name)
                elif verbose:
                    print(f"  [*] {name}...")
                t0 = time.time()
                future = pool.submit(fn, path)
                futures[future] = (sid, name, t0)

            for future in as_completed(futures):
                sid, name, t0 = futures[future]
                elapsed = time.time() - t0
                try:
                    results = future.result()
                except Exception as e:
                    results = []
                    if verbose:
                        print(f"  [!] Scanner '{name}' failed: {e}")
                if on_scanner_done:
                    on_scanner_done(sid, name, len(results), elapsed)
                all_findings.extend(results)
    else:
        for sid, name, fn in active:
            if on_scanner_start:
                on_scanner_start(sid, name)
            elif verbose:
                print(f"  [*] {name}...")
            t0 = time.time()
            try:
                results = fn(path)
            except Exception as e:
                results = []
            elapsed = time.time() - t0
            if on_scanner_done:
                on_scanner_done(sid, name, len(results), elapsed)
            all_findings.extend(results)

    all_findings = deduplicate(all_findings)
    if min_severity:
        all_findings = [f for f in all_findings
                        if SEVERITY_ORDER.get(f.severity, 99) <= min_order]

    all_findings.sort()
    return all_findings
