#!/usr/bin/env python3
"""
ShadowCI — Repository Security Intelligence Scanner
Death Note Edition v1.2.0  |  by ne0k1ra
"""
import sys, os, argparse, time, random, threading, itertools, json
from typing import List, Optional

# ── Death Note Palette ────────────────────────────────────────────────────────
CRIMSON     = "\033[38;5;196m"
BLOOD_RED   = "\033[38;5;160m"
BONE_WHITE  = "\033[38;5;231m"
ASH_GREY    = "\033[38;5;245m"
DARK_GREY   = "\033[38;5;238m"
PALE_GOLD   = "\033[38;5;220m"
DIM_GOLD    = "\033[38;5;178m"
RUST_ORANGE = "\033[38;5;166m"
GHOST_BLUE  = "\033[38;5;153m"
TEAL        = "\033[38;5;73m"
SAGE        = "\033[38;5;108m"
DIM         = "\033[2m"
BOLD        = "\033[1m"
ITALIC      = "\033[3m"
RESET       = "\033[0m"

SEVERITY_COLORS = {
    "CRITICAL": CRIMSON,
    "HIGH":     RUST_ORANGE,
    "MEDIUM":   PALE_GOLD,
    "LOW":      TEAL,
    "INFO":     GHOST_BLUE,
}
SEVERITY_GLYPHS = {
    "CRITICAL": "†",
    "HIGH":     "⚠",
    "MEDIUM":   "◈",
    "LOW":      "◇",
    "INFO":     "○",
}
SCANNER_ICONS = {
    "secrets":     "🔑",
    "dockerfile":  "🐳",
    "workflows":   "⚙ ",
    "env":         "📄",
    "terraform":   "☁ ",
    "gitignore":   "🙈",
    "deps":        "📦",
    "kubernetes":  "☸ ",
    "permissions": "🔒",
}

RYUK_QUOTES = [
    "Humans are so interesting... especially when they leave their secrets exposed.",
    "I wonder... how many keys were left in the open today?",
    "I didn't drop this scanner here for any particular reason.",
    "Humans are greedy. They always want more access than they need.",
    "It's not stealing if the credentials were already in plain sight.",
    "I just thought this world needed a little... security audit.",
    "Don't blame me. I'm just watching. The vulnerabilities were already there.",
    "I'm bored. Let's see what you've left behind.",
    "Neither of us can escape this scan once it begins.",
    "Interesting. Even gods leave their keys in plain text.",
    "I've lived for millennia. I've never seen a repo without at least one secret.",
]
L_THOUGHTS = [
    "I am... 97.3% certain this repository has been compromised.",
    "Interesting. The evidence was already overwhelming before I looked.",
    "A detective never assumes. The scanner confirms.",
    "The probability of clean code approaches zero.",
    "These findings are... precisely what I expected.",
    "I had a feeling. I always have a feeling.",
    "Justice is not blind. Neither is the scanner.",
    "To catch a criminal, you must think like one. I always do.",
    "I'll give you 5% odds this repository is clean. Maybe less.",
]

BANNER = f"""
{DARK_GREY}  ╔══════════════════════════════════════════════════════════════════╗{RESET}
{DARK_GREY}  ║{RESET}                                                                  {DARK_GREY}║{RESET}
{DARK_GREY}  ║{RESET}  {CRIMSON}{BOLD}███████╗{RESET}{CRIMSON}██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗ ██████╗██╗{RESET}  {DARK_GREY}║{RESET}
{DARK_GREY}  ║{RESET}  {CRIMSON}{BOLD}██╔════╝{RESET}{CRIMSON}██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║██╔════╝██║{RESET}  {DARK_GREY}║{RESET}
{DARK_GREY}  ║{RESET}  {BLOOD_RED}{BOLD}███████╗{RESET}{BLOOD_RED}███████║███████║██║  ██║██║   ██║██║ █╗ ██║██║     ██║{RESET}  {DARK_GREY}║{RESET}
{DARK_GREY}  ║{RESET}  {BONE_WHITE}╚════██║{RESET}{BONE_WHITE}██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║██║     ██║{RESET}  {DARK_GREY}║{RESET}
{DARK_GREY}  ║{RESET}  {BONE_WHITE}{BOLD}███████║{RESET}{BONE_WHITE}██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝╚██████╗██║{RESET}  {DARK_GREY}║{RESET}
{DARK_GREY}  ║{RESET}  {ASH_GREY}╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝  ╚═════╝╚═╝{RESET}  {DARK_GREY}║{RESET}
{DARK_GREY}  ║{RESET}                                                                  {DARK_GREY}║{RESET}
{DARK_GREY}  ║{RESET}  {PALE_GOLD}Repository Security Intelligence Scanner{RESET}   {ASH_GREY}v2.0.0  ne0k1ra{RESET}   {DARK_GREY}║{RESET}
{DARK_GREY}  ║{RESET}  {DIM}{ITALIC}「 If you can see it — you can judge it. 」{RESET}                    {DARK_GREY}║{RESET}
{DARK_GREY}  ╚══════════════════════════════════════════════════════════════════╝{RESET}"""


def _div(char="─", width=66, color=DARK_GREY):
    return f"  {color}{char * width}{RESET}"


def _wrap(text: str, width=60) -> List[str]:
    words = text.split()
    lines = []
    cur = []
    for w in words:
        if len(' '.join(cur + [w])) > width:
            lines.append(' '.join(cur))
            cur = [w]
        else:
            cur.append(w)
    if cur:
        lines.append(' '.join(cur))
    return lines


# ── Spinner ───────────────────────────────────────────────────────────────────
class Spinner:
    def __init__(self, label: str, icon: str = "◈"):
        self.label = label
        self.icon = icon
        self._stop = threading.Event()
        self._thread = None

    def _spin(self):
        for f in itertools.cycle(["◐", "◓", "◑", "◒"]):
            if self._stop.is_set():
                break
            sys.stdout.write(f"\r  {PALE_GOLD}{self.icon}{RESET}  {ASH_GREY}{self.label:<30}{RESET}  {DIM_GOLD}{f}{RESET}  ")
            sys.stdout.flush()
            time.sleep(0.1)

    def start(self):
        self._thread = threading.Thread(target=self._spin, daemon=True)
        self._thread.start()

    def stop(self, n: int, elapsed: float):
        self._stop.set()
        if self._thread:
            self._thread.join()
        badge = f"{CRIMSON}{BOLD}[{n} found]{RESET}" if n > 0 else f"{TEAL}[clean]{RESET}"
        sys.stdout.write(f"\r  {PALE_GOLD}{self.icon}{RESET}  {BONE_WHITE}{self.label:<30}{RESET}  {badge}  {DIM}{elapsed:.2f}s{RESET}\n")
        sys.stdout.flush()


# ── Print helpers ─────────────────────────────────────────────────────────────
def print_finding(f, fix_hints=False, compact=False):
    col   = SEVERITY_COLORS.get(f.severity, BONE_WHITE)
    glyph = SEVERITY_GLYPHS.get(f.severity, "·")
    loc   = f.file + (f":{f.line}" if f.line else "")
    tag   = f"{col}{BOLD}[{glyph} {f.severity}]{RESET}"

    print(f"  {tag}  {BONE_WHITE}{f.message}{RESET}")
    print(f"           {ASH_GREY}↳ {DIM}{loc}{RESET}")

    if not compact:
        if f.detail:
            for ln in _wrap(f.detail):
                print(f"           {DIM}{DARK_GREY}  {ln}{RESET}")
        if fix_hints and f.remediation:
            print(f"           {SAGE}  ✦ Fix: {f.remediation[:100]}{'…' if len(f.remediation)>100 else ''}{RESET}")
    print()


def _risk_bar(score: int) -> str:
    filled = score // 5
    empty = 20 - filled
    col = CRIMSON if score >= 80 else RUST_ORANGE if score >= 50 else PALE_GOLD if score >= 25 else TEAL
    return f"{col}{'█'*filled}{RESET}{DIM}{'░'*empty}{RESET}  {col}{BOLD}{score}/100{RESET}"


def print_summary(findings, elapsed: float, target: str, timings: dict):
    from .models import SEVERITY_ORDER, calculate_risk_score
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    total = len(findings)
    risk  = calculate_risk_score(findings)
    has_c = counts.get("CRITICAL", 0) > 0
    has_h = counts.get("HIGH", 0) > 0

    print(f"\n{_div('═', 66, DARK_GREY)}")
    print(f"\n  {PALE_GOLD}{BOLD}JUDGMENT — CASE FILE SUMMARY{RESET}\n")

    for sev in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]:
        c = counts.get(sev, 0)
        if not c: continue
        col   = SEVERITY_COLORS.get(sev, BONE_WHITE)
        glyph = SEVERITY_GLYPHS.get(sev, "·")
        bar   = f"{col}{'█'*min(c*2,28)}{RESET}{DIM}{'░'*(28-min(c*2,28))}{RESET}"
        print(f"  {col}{glyph} {sev:<10}{RESET}  {bar}  {BOLD}{c}{RESET}")

    print(f"\n  {ASH_GREY}Risk Score    {RESET}  {_risk_bar(risk)}")

    # Scanner timing table
    if timings:
        print(f"\n  {DIM}{DARK_GREY}Scanner performance:{RESET}")
        for sid, (n, t) in sorted(timings.items(), key=lambda x: -x[1][1]):
            icon = SCANNER_ICONS.get(sid, "·")
            col  = CRIMSON if n > 0 else TEAL
            print(f"    {DIM}{icon}{RESET}  {ASH_GREY}{sid:<14}{RESET}  "
                  f"{col}{n:>3} finding{'s' if n!=1 else ' '}{RESET}  {DIM}{t:.3f}s{RESET}")

    print(f"\n{_div('─', 66, DARK_GREY)}\n")

    if has_c:
        verdict = f"{CRIMSON}{BOLD}†  CONDEMNED  †{RESET}"
        note    = f"{DIM}{ITALIC}This repository has been written in the Death Note.{RESET}"
    elif has_h:
        verdict = f"{RUST_ORANGE}{BOLD}⚠  JUDGMENT PENDING  ⚠{RESET}"
        note    = f"{DIM}{ITALIC}High-severity sins demand immediate remediation.{RESET}"
    elif counts.get("MEDIUM", 0):
        verdict = f"{PALE_GOLD}{BOLD}◈  UNDER SCRUTINY  ◈{RESET}"
        note    = f"{DIM}{ITALIC}Review medium findings before the next deployment.{RESET}"
    else:
        verdict = f"{TEAL}{BOLD}◇  ABSOLVED  ◇{RESET}"
        note    = f"{DIM}{ITALIC}No significant sins. Even Ryuk is impressed.{RESET}"

    print(f"  Verdict       {verdict}")
    print(f"                {note}")
    print(f"\n  {ASH_GREY}Total findings  {BONE_WHITE}{BOLD}{total}{RESET}")
    print(f"  {ASH_GREY}Scan duration   {BONE_WHITE}{BOLD}{elapsed:.3f}s{RESET}")
    print(f"  {ASH_GREY}Target          {BONE_WHITE}{DIM}{target}{RESET}")
    print(f"\n{_div('═', 66, DARK_GREY)}\n")


# ── Commands ──────────────────────────────────────────────────────────────────
def cmd_scan(args):
    from .engine import run_scan, ALL_SCANNERS
    from .reporters.markdown    import generate_markdown_report
    from .reporters.json_report import generate_json_report
    from .reporters.html_report import generate_html_report

    target = args.path
    if not os.path.exists(target):
        print(f"\n  {CRIMSON}{BOLD}[† FATAL]{RESET}  Path not found: {target}\n")
        sys.exit(1)

    valid_ids = {sid for sid, _, _ in ALL_SCANNERS}

    # Handle --only (supports space-separated via nargs='*' and comma-separated)
    only_ids = None
    if getattr(args, 'only', None):
        only_ids = []
        for item in args.only:
            only_ids.extend([x.strip() for x in item.split(',') if x.strip()])
        
        bad = [x for x in only_ids if x not in valid_ids]
        if bad:
            print(f"\n  {CRIMSON}[ERROR]{RESET}  Unknown scanner(s): {', '.join(bad)}")
            print(f"  Valid: {', '.join(sorted(valid_ids))}\n")
            sys.exit(1)

    # Handle --skip (supports space-separated via nargs='*' and comma-separated)
    skip_ids = None
    if getattr(args, 'skip', None):
        skip_ids = []
        for item in args.skip:
            skip_ids.extend([x.strip() for x in item.split(',') if x.strip()])
        
        bad = [x for x in skip_ids if x not in valid_ids]
        if bad:
            print(f"\n  {CRIMSON}[ERROR]{RESET}  Unknown scanner(s) to skip: {', '.join(bad)}")
            print(f"  Valid: {', '.join(sorted(valid_ids))}\n")
            sys.exit(1)

    # Resolve active scanner IDs
    active_ids = list(valid_ids)
    if only_ids is not None:
        active_ids = [x for x in only_ids if x in valid_ids]
    if skip_ids is not None:
        active_ids = [x for x in active_ids if x not in skip_ids]

    min_sev = getattr(args, 'severity', None)
    if min_sev:
        min_sev = min_sev.upper()
    fix_hints = getattr(args, 'fix_hints', False)
    compact = getattr(args, 'no_detail', False)
    
    # Format options
    fmt = getattr(args, 'format', 'text')
    json_out = getattr(args, 'json', False) or (fmt == 'json')
    no_html = getattr(args, 'no_html', False)
    if fmt == 'html':
        no_html = False

    if not json_out:
        print(BANNER)
        print(f"\n  {DIM}{BONE_WHITE}✦ Ryuk:{RESET}  {ITALIC}{ASH_GREY}\"{random.choice(RYUK_QUOTES)}\"{RESET}\n")
        print(_div("─", 66, DARK_GREY))
        print(f"\n  {PALE_GOLD}Target{RESET}  {BONE_WHITE}{os.path.abspath(target)}{RESET}")
        if only_ids:
            print(f"  {PALE_GOLD}Scope {RESET}  {ASH_GREY}{', '.join(only_ids)}{RESET}")
        if min_sev:
            print(f"  {PALE_GOLD}Filter{RESET}  {SEVERITY_COLORS.get(min_sev,ASH_GREY)}{min_sev}+{RESET}")
        print(f"\n{_div('─', 66, DARK_GREY)}\n")

    t0        = time.time()
    spinners  = {}
    timings   = {}

    def on_start(sid, name):
        if json_out:
            return
        icon = SCANNER_ICONS.get(sid, "◈")
        sp = Spinner(name, icon)
        spinners[sid] = sp
        sp.start()

    def on_done(sid, name, n, elapsed):
        timings[sid] = (n, elapsed)
        if json_out:
            return
        sp = spinners.get(sid)
        if sp:
            sp.stop(n, elapsed)

    try:
        findings = run_scan(
            target, only=active_ids, min_severity=min_sev,
            on_scanner_start=on_start, on_scanner_done=on_done,
        )
    except Exception as e:
        print(f"  {CRIMSON}{BOLD}[† FATAL]{RESET}  {e}")
        sys.exit(1)

    elapsed = time.time() - t0

    # JSON stdout mode
    if json_out:
        from .models import calculate_risk_score
        payload = {
            "target": os.path.abspath(target),
            "verdict": ("CONDEMNED" if any(f.severity=="CRITICAL" for f in findings)
                        else "HIGH_RISK" if any(f.severity=="HIGH" for f in findings)
                        else "MEDIUM_RISK" if any(f.severity=="MEDIUM" for f in findings)
                        else "CLEAN"),
            "risk_score": calculate_risk_score(findings),
            "summary": {s: sum(1 for f in findings if f.severity==s)
                        for s in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]},
            "findings": [f.to_dict() for f in findings],
        }
        print(json.dumps(payload, indent=2))
        exit_code = 1 if any(f.severity in ("CRITICAL", "HIGH") for f in findings) else 0
        sys.exit(exit_code)

    print()
    by_sev = {}
    for f in findings: by_sev.setdefault(f.severity, []).append(f)

    if not findings:
        print(f"  {TEAL}{BOLD}◇  The repository is clean.{RESET}")
        print(f"  {DIM}{ASH_GREY}Even gods make mistakes. Scan again later.{RESET}\n")
    else:
        for sev in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]:
            group = by_sev.get(sev, [])
            if not group: continue
            col   = SEVERITY_COLORS.get(sev, BONE_WHITE)
            glyph = SEVERITY_GLYPHS.get(sev, "·")
            cnt   = len(group)
            title = f"{glyph}  {sev}  ({cnt} finding{'s' if cnt!=1 else ''})"
            bw    = len(title) + 4
            print(f"  {col}{BOLD}╔{'═'*bw}╗{RESET}")
            print(f"  {col}{BOLD}║  {title}  ║{RESET}")
            print(f"  {col}{BOLD}╚{'═'*bw}╝{RESET}\n")
            for f in group:
                print_finding(f, fix_hints=fix_hints, compact=compact)

    print(f"  {GHOST_BLUE}{DIM}L:{RESET}  {ITALIC}{ASH_GREY}{random.choice(L_THOUGHTS)}{RESET}\n")
    print_summary(findings, elapsed, os.path.abspath(target), timings)

    # Reports
    out_dir = getattr(args, 'output_dir', '.') or '.'
    os.makedirs(out_dir, exist_ok=True)

    md_path = os.path.join(out_dir, "shadowci_report.md")
    json_path = os.path.join(out_dir, "shadowci_report.json")
    html_path = os.path.join(out_dir, "shadowci_report.html")

    generate_markdown_report(findings, target, md_path)
    generate_json_report(findings, target, json_path)
    if not no_html:
        generate_html_report(findings, target, html_path)

    print(f"  {PALE_GOLD}Case files written:{RESET}")
    print(f"    {DIM}{BONE_WHITE}✦{RESET}  {md_path}")
    print(f"    {DIM}{BONE_WHITE}✦{RESET}  {json_path}")
    if not no_html:
        print(f"    {DIM}{BONE_WHITE}✦{RESET}  {html_path}")
    print(f"\n  {DIM}{ASH_GREY}「 The names have been written. There is no going back. 」{RESET}\n")

    if any(f.severity in ("CRITICAL", "HIGH") for f in findings):
        sys.exit(1)


def cmd_version(args=None):
    print(f"\n  {CRIMSON}{BOLD}ShadowCI{RESET}  {ASH_GREY}v2.0.0{RESET}  {DIM}Death Note Edition  |  by ne0k1ra{RESET}")
    from .engine import ALL_SCANNERS
    print(f"  {DIM}{len(ALL_SCANNERS)} scanners loaded{RESET}\n")


def cmd_list(args=None):
    from .engine import ALL_SCANNERS
    print(f"\n  {PALE_GOLD}{BOLD}Available Scanners{RESET}  {DIM}({len(ALL_SCANNERS)} total){RESET}\n")
    for sid, name, _ in ALL_SCANNERS:
        icon = SCANNER_ICONS.get(sid, "◈")
        print(f"  {CRIMSON}†{RESET}  {icon}  {PALE_GOLD}{sid:<14}{RESET}  {ASH_GREY}{name}{RESET}")
    print(f"\n  {DIM}Usage: shadowci scan <path> --only secrets,dockerfile,kubernetes{RESET}\n")


def cmd_help(args=None):
    from .engine import ALL_SCANNERS
    print(BANNER)
    print(f"\n  {DIM}{BONE_WHITE}✦ Ryuk:{RESET}  {ITALIC}{ASH_GREY}\"{random.choice(RYUK_QUOTES)}\"{RESET}\n")
    print(_div("─", 66, DARK_GREY))
    print(f"\n  {PALE_GOLD}{BOLD}USAGE{RESET}\n")

    cmds = [
        ("shadowci scan <path>",                        "Full judgment scan"),
        ("shadowci scan <path> --fix-hints",            "Show remediation per finding"),
        ("shadowci scan <path> --no-detail",            "Compact output (CI-friendly)"),
        ("shadowci scan <path> --json",                 "JSON to stdout (no UI)"),
        ("shadowci scan <path> --severity HIGH",        "Filter to HIGH and above"),
        ("shadowci scan <path> --only secrets,deps",    "Run specific scanners only"),
        ("shadowci scan <path> -o reports/",            "Custom report output dir"),
        ("shadowci scan <path> --no-html",              "Skip HTML report generation"),
        ("shadowci list",                               "List all scanner IDs"),
        ("shadowci version",                            "Show version info"),
    ]
    for cmd, desc in cmds:
        print(f"  {BONE_WHITE}{cmd:<46}{RESET}  {DIM}{ASH_GREY}{desc}{RESET}")

    print(f"\n{_div('─', 66, DARK_GREY)}\n  {PALE_GOLD}{BOLD}SCANNERS  ({len(ALL_SCANNERS)} total){RESET}\n")

    descs = {
        "secrets":     "34 patterns: AWS, GCP, Azure, GitHub, OpenAI, Stripe, MongoDB…",
        "dockerfile":  "USER root, :latest, curl|sh, EXPOSE 22, secrets in ENV/ARG",
        "workflows":   "pull_request_target, write-all, unpinned actions, curl|sh steps",
        "env":         ".env exposure + real credential value analysis",
        "terraform":   "0.0.0.0/0 rules, public S3, hardcoded creds, wildcard IAM",
        "gitignore":   "Sensitive files not covered by .gitignore rules",
        "deps":        "CVEs in requirements.txt, package.json, Pipfile, pyproject.toml",
        "kubernetes":  "Privileged pods, RBAC wildcards, hostPath, missing TLS, resource limits",
        "permissions": "World-writable files, overly-open secret files, SUID/SGID bits",
    }
    for sid, name, _ in ALL_SCANNERS:
        icon = SCANNER_ICONS.get(sid, "◈")
        desc = descs.get(sid, "")
        print(f"  {CRIMSON}†{RESET}  {icon}  {PALE_GOLD}{sid:<14}{RESET}  {BONE_WHITE}{name}{RESET}")
        print(f"              {DIM}{ASH_GREY}{desc}{RESET}\n")

    print(_div("─", 66, DARK_GREY))
    print(f"\n  {DIM}{ASH_GREY}Reports: .md  .json  .html (Death Note styled)")
    print(f"  Exit code 1 if CRITICAL or HIGH findings detected.{RESET}\n")


def main():
    p = argparse.ArgumentParser(prog="shadowci", add_help=False)
    sub = p.add_subparsers(dest="command")

    sp = sub.add_parser("scan")
    sp.add_argument("path")
    sp.add_argument("-o", "--output-dir", default=".", metavar="DIR")
    sp.add_argument("--only",       nargs="*", metavar="SCANNERS", help="Run specific scanners only")
    sp.add_argument("--skip",       nargs="*", metavar="SCANNERS", help="Skip specific scanners")
    sp.add_argument("--severity",   metavar="LEVEL")
    sp.add_argument("--format",     choices=["text", "html", "json", "markdown"], default="text", help="Output format")
    sp.add_argument("--no-detail",  action="store_true")
    sp.add_argument("--fix-hints",  action="store_true", help="Show remediation steps per finding")
    sp.add_argument("--json",       action="store_true", help="Output JSON to stdout (alias for --format json)")
    sp.add_argument("--no-html",    action="store_true", help="Skip HTML report generation")

    sub.add_parser("help")
    sub.add_parser("list")
    sub.add_parser("version")

    args = p.parse_args()
    cmds = {"scan": cmd_scan, "help": cmd_help, "list": cmd_list, "version": cmd_version}
    
    if args.command in cmds:
        cmds[args.command](args)
    else:
        cmd_help()


if __name__ == "__main__":
    main()
