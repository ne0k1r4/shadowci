import json
import os
from datetime import datetime
from typing import List
from ..models import Finding


def generate_json_report(findings: List[Finding], target_path: str, output_path: str = "shadowci_report.json"):
    now = datetime.now().isoformat()

    counts = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    has_critical = counts.get("CRITICAL", 0) > 0
    has_high     = counts.get("HIGH", 0) > 0

    payload = {
        "shadowci": {
            "version": "1.0.0",
            "edition": "Death Note",
            "author": "ne0k1ra",
            "quote": "The human whose name is written in this note shall perish.",
        },
        "scan": {
            "timestamp": now,
            "target": os.path.abspath(target_path),
            "verdict": "CONDEMNED" if (has_critical or has_high) else "UNDER_WATCH",
        },
        "summary": {
            "total": len(findings),
            "critical": counts.get("CRITICAL", 0),
            "high":     counts.get("HIGH", 0),
            "medium":   counts.get("MEDIUM", 0),
            "low":      counts.get("LOW", 0),
            "info":     counts.get("INFO", 0),
        },
        "findings": [f.to_dict() for f in findings],
    }

    with open(output_path, 'w', encoding='utf-8') as fp:
        json.dump(payload, fp, indent=2)

    return output_path
