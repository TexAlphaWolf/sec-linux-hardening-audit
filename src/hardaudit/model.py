"""Data types shared by the engine, the reports and the fixer."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

SEVERITIES = ("high", "medium", "low")
SEVERITY_WEIGHT = {"high": 5, "medium": 3, "low": 1}
FAMILIES = ("debian", "rhel")
# pass / fail count towards the score. na = does not apply to this host.
# untestable = this run cannot find out (needs root, systemd, a package manager).
# error = the check itself broke.
STATUSES = ("pass", "fail", "na", "untestable", "error")


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    section: str
    severity: str
    check: dict[str, Any]
    why: str
    fix: str
    families: tuple[str, ...] = ()  # empty = every family
    apply: dict[str, Any] | None = None

    def applies_to(self, family: str) -> bool:
        return not self.families or family in self.families


@dataclass(frozen=True)
class Result:
    rule: Rule
    status: str
    detail: str = ""


@dataclass
class Report:
    family: str
    distro: str
    root: str
    results: list[Result] = field(default_factory=list)

    def count(self, status: str) -> int:
        return sum(1 for r in self.results if r.status == status)

    @property
    def score(self) -> float | None:
        """Weighted share of passed rules among those that could be judged, 0-100."""
        passed = sum(SEVERITY_WEIGHT[r.rule.severity] for r in self.results if r.status == "pass")
        failed = sum(SEVERITY_WEIGHT[r.rule.severity] for r in self.results if r.status == "fail")
        if passed + failed == 0:
            return None
        return round(100 * passed / (passed + failed), 1)

    def to_dict(self) -> dict[str, Any]:
        return {
            "distro": self.distro,
            "family": self.family,
            "root": self.root,
            "score": self.score,
            "counts": {s: self.count(s) for s in STATUSES},
            "results": [
                {
                    "id": r.rule.id,
                    "title": r.rule.title,
                    "section": r.rule.section,
                    "severity": r.rule.severity,
                    "status": r.status,
                    "detail": r.detail,
                    "fix": r.rule.fix,
                    "fixable": r.rule.apply is not None,
                }
                for r in self.results
            ],
        }
