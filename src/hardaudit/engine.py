"""Run the rules against a host."""

from __future__ import annotations

from collections.abc import Iterable

from hardaudit.checks import CHECKS
from hardaudit.host import Host
from hardaudit.model import Report, Result, Rule


def audit(
    host: Host,
    rules: Iterable[Rule],
    *,
    only: Iterable[str] = (),
    skip: Iterable[str] = (),
) -> Report:
    family = host.family()
    report = Report(family=family, distro=host.distro(), root=str(host.root))
    only_set, skip_set = set(only), set(skip)
    for rule in rules:
        if (only_set and rule.id not in only_set) or rule.id in skip_set:
            continue
        if not rule.applies_to(family):
            report.results.append(Result(rule, "na", f"not for the {family} family"))
            continue
        try:
            status, detail = CHECKS[rule.check["type"]](host, rule.check)
        except PermissionError as exc:
            # Whatever the check was reading is closed to this user: a result, not a crash.
            status, detail = (
                "untestable",
                f"permission denied on {exc.filename} (run as root for a full audit)",
            )
        except (KeyError, TypeError, ValueError, OSError) as exc:
            status, detail = "error", f"rule {rule.id} is broken: {type(exc).__name__}: {exc}"
        report.results.append(Result(rule, status, detail))
    return report
