"""Whole-system expectations, written by hand from what each tree contains."""

from __future__ import annotations

from hardaudit import rules
from hardaudit.engine import audit
from tests.conftest import posix_only

# What the neglected tree must fail, listed by hand (not computed from the rules).
INSECURE_FAILS = {
    *(f"HA-KRN-00{i}" for i in range(1, 9)),
    *(f"HA-NET-00{i}" for i in range(1, 10)),
    "HA-SSH-001", "HA-SSH-002", "HA-SSH-003", "HA-SSH-004", "HA-SSH-005", "HA-SSH-006", "HA-SSH-007",
    "HA-FS-001", "HA-FS-002", "HA-FS-003", "HA-FS-004", "HA-FS-005",
    "HA-ACC-001", "HA-ACC-002", "HA-ACC-003", "HA-ACC-004",
    "HA-ACC-005", "HA-ACC-006", "HA-ACC-007", "HA-ACC-008",
    "HA-PRM-001", "HA-PRM-002", "HA-PRM-003", "HA-PRM-004", "HA-PRM-005", "HA-PRM-006", "HA-PRM-007",
    "HA-PKG-001", "HA-PKG-005", "HA-PKG-007",
    "HA-LOG-001", "HA-LOG-003", "HA-LOG-004", "HA-LOG-005",
}  # fmt: skip


def statuses(report) -> dict[str, str]:  # type: ignore[no-untyped-def]
    return {r.rule.id: r.status for r in report.results}


@posix_only
def test_a_hardened_tree_passes_every_rule_that_can_be_judged(hardened):
    result = statuses(audit(hardened, rules.load()))
    assert {k: v for k, v in result.items() if v not in ("pass", "untestable")} == {}
    # Without a running system the audit daemon's boot state and the /tmp mount of systemd
    # cannot be known; they are reported as such, never guessed.
    assert result["HA-LOG-002"] == "untestable"


@posix_only
def test_a_neglected_tree_fails_exactly_what_it_should(insecure):
    result = statuses(audit(insecure, rules.load()))
    failed = {k for k, v in result.items() if v == "fail"}
    assert failed == INSECURE_FAILS, (
        sorted(failed - INSECURE_FAILS),
        sorted(INSECURE_FAILS - failed),
    )


@posix_only
def test_the_score_separates_the_two_trees(hardened, insecure):
    good = audit(hardened, rules.load()).score
    bad = audit(insecure, rules.load()).score
    assert good == 100.0
    assert bad is not None and bad < 45
