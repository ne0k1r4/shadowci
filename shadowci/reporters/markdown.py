import os
from datetime import datetime
from typing import List
from ..models import Finding, SEVERITY_ORDER


SEVERITY_ICONS = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🟢",
    "INFO":     "🔵",
}

SEVERITY_SYMBOLS = {
    "CRITICAL": "† CRITICAL",
    "HIGH":     "⚠ HIGH",
    "MEDIUM":   "◈ MEDIUM",
    "LOW":      "◦ LOW",
    "INFO":     "· INFO",
}

DN_HEADER = """\
<!--
  ██████╗ ███████╗ █████╗ ████████╗██╗  ██╗    ███╗   ██╗ ██████╗ ████████╗███████╗
  ██╔══██╗██╔════╝██╔══██╗╚══██╔══╝██║  ██║    ████╗  ██║██╔═══██╗╚══██╔══╝██╔════╝
  ██║  ██║█████╗  ███████║   ██║   ███████║    ██╔██╗ ██║██║   ██║   ██║   █████╗
  ██║  ██║██╔══╝  ██╔══██║   ██║   ██╔══██║    ██║╚██╗██║██║   ██║   ██║   ██╔══╝
  ██████╔╝███████╗██║  ██║   ██║   ██║  ██║    ██║ ╚████║╚██████╔╝   ██║   ███████╗
  ╚═════╝ ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝    ╚═╝  ╚═══╝ ╚═════╝    ╚═╝   ╚══════╝
  "The human whose name is written in this note shall die."
-->
"""


def generate_markdown_report(findings: List[Finding], target_path: str,
                              output_path: str = "shadowci_report.md"):
    now   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total = len(findings)

    counts = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    lines = [DN_HEADER]
    lines.append("# † ShadowCI — Death Note Security Report")
    lines.append("")
    lines.append("> *\"I am Justice. And I will judge your repository.\"*")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append(f"**🎯 Target:** `{os.path.abspath(target_path)}`")
    lines.append(f"**🕐 Scan Time:** {now}")
    lines.append(f"**📊 Total Findings:** {total}")
    lines.append(f"**⚖️ Scanner:** ShadowCI v2.0.0 by ne0k1ra")
    lines.append("")

    # Verdict block
    condemned = counts.get("CRITICAL", 0) + counts.get("HIGH", 0) > 0
    if condemned:
        lines.append("> ### 🔴 VERDICT: CONDEMNED")
        lines.append("> *This repository's name has been written in the Death Note.*")
        lines.append("> *Critical or High severity findings were detected.*")
    else:
        lines.append("> ### 🟡 VERDICT: SURVIVES — FOR NOW")
        lines.append("> *L is still watching. Review all findings carefully.*")
    lines.append("")
    lines.append("---")
    lines.append("")

    # Summary table
    lines.append("## 📋 Summary")
    lines.append("")
    lines.append("| Symbol | Severity | Count | Status |")
    lines.append("|--------|----------|-------|--------|")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        c    = counts.get(sev, 0)
        icon = SEVERITY_ICONS.get(sev, "⚪")
        sym  = SEVERITY_SYMBOLS.get(sev, sev)
        bar  = "█" * min(c, 20) if c > 0 else "░"
        lines.append(f"| {icon} | **{sev}** | {c} | `{bar}` |")
    lines.append("")
    lines.append("---")
    lines.append("")

    if not findings:
        lines.append("## ✅ No Security Issues Detected")
        lines.append("")
        lines.append("*The Death Note remains blank. The repository is clean.*")
        lines.append("")
    else:
        by_severity = {}
        for f in findings:
            by_severity.setdefault(f.severity, []).append(f)

        sev_desc = {
            "CRITICAL": "Immediate action required. These findings represent severe security risks.",
            "HIGH":     "High priority. These should be fixed before deployment.",
            "MEDIUM":   "Moderate risk. Plan remediation within your next sprint.",
            "LOW":      "Low risk. Good to fix but not urgent.",
            "INFO":     "Informational findings for awareness.",
        }

        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            group = by_severity.get(sev, [])
            if not group:
                continue

            icon = SEVERITY_ICONS.get(sev, "⚪")
            sym  = SEVERITY_SYMBOLS.get(sev, sev)
            desc = sev_desc.get(sev, "")

            lines.append(f"## {icon} {sym}")
            lines.append("")
            lines.append(f"*{desc}*")
            lines.append("")

            for i, f in enumerate(group, 1):
                loc = f.file
                if f.line:
                    loc += f":{f.line}"
                lines.append(f"### {i}. {f.message}")
                lines.append("")
                lines.append(f"| Field | Value |")
                lines.append(f"|-------|-------|")
                lines.append(f"| **File** | `{loc}` |")
                lines.append(f"| **Scanner** | `{f.scanner}` |")
                lines.append(f"| **Severity** | `{sev}` |")
                if f.detail:
                    lines.append(f"| **Detail** | {f.detail} |")
                lines.append("")

            lines.append("---")
            lines.append("")

    lines.append("## 📖 About ShadowCI")
    lines.append("")
    lines.append("ShadowCI is a repository security intelligence scanner for DevSecOps pipelines.")
    lines.append("Part of the **ne0k1ra security toolchain**:")
    lines.append("")
    lines.append("```")
    lines.append("kira-installer  →  hardened Arch Linux deployment")
    lines.append("wraith-net      →  attack surface intelligence")
    lines.append("lightscan       →  network recon engine")
    lines.append("shadowci        →  repo & pipeline security scanner  ← this tool")
    lines.append("grimoire        →  operator control center")
    lines.append("```")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append('*"I am Justice." — Kira*')
    lines.append("")
    lines.append(f"*Generated by ShadowCI v2.0.0 | {now}*")

    with open(output_path, 'w', encoding='utf-8') as fp:
        fp.write('\n'.join(lines))

    return output_path
