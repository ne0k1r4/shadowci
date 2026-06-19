from dataclasses import dataclass, asdict, field
from typing import Literal, List, Optional
import math

Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

SEVERITY_ORDER  = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEVERITY_WEIGHT = {"CRITICAL": 40, "HIGH": 15, "MEDIUM": 5, "LOW": 1, "INFO": 0}


@dataclass
class Finding:
    severity:    Severity
    message:     str
    file:        str
    scanner:     str
    line:        int = 0
    detail:      str = ""
    remediation: str = ""   # NEW: concrete fix instruction

    def to_dict(self) -> dict:
        return asdict(self)

    def __lt__(self, other):
        return SEVERITY_ORDER[self.severity] < SEVERITY_ORDER[other.severity]

    def __eq__(self, other):
        if not isinstance(other, Finding):
            return False
        return (self.severity, self.message, self.file, self.line) == \
               (other.severity, other.message, other.file, other.line)

    def __hash__(self):
        return hash((self.severity, self.message, self.file, self.line))


def deduplicate(findings: List[Finding]) -> List[Finding]:
    seen, result = set(), []
    for f in findings:
        key = (f.severity, f.message, f.file, f.line)
        if key not in seen:
            seen.add(key)
            result.append(f)
    return result


def calculate_risk_score(findings: List[Finding]) -> int:
    raw = sum(SEVERITY_WEIGHT.get(f.severity, 0) for f in findings)
    score = int(100 * (1 - math.exp(-raw / 60)))
    return min(score, 100)
