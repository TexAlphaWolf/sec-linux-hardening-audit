"""Every rule must be able to fail, and every fixable rule must be fixed by its own fix."""

from __future__ import annotations

import pytest

from hardaudit import fixes, rules
from hardaudit.engine import audit
from tests.conftest import posix_only
from tests.fixtures import FixtureHost, build_hardened
from tests.mutations import mutate

ALL = rules.load()
IDS = [r.id for r in ALL]


def _status(host, rule_id):  # type: ignore[no-untyped-def]
    return next(r for r in audit(host, ALL, only=[rule_id]).results).status


@posix_only
@pytest.mark.parametrize("rule_id", IDS)
def test_breaking_one_rule_makes_that_rule_fail(tmp_path, family, rule_id):
    rule = next(r for r in ALL if r.id == rule_id)
    build_hardened(tmp_path / "r", family)
    host = FixtureHost(tmp_path / "r")
    assert _status(host, rule_id) in ("pass", "untestable")
    if not mutate(tmp_path / "r", rule, family):
        pytest.skip("read from the running system only")
    host = FixtureHost(tmp_path / "r")
    assert _status(host, rule_id) == "fail"


@posix_only
@pytest.mark.parametrize("rule_id", [r.id for r in ALL if r.apply])
def test_the_fix_of_a_rule_makes_it_pass_again(tmp_path, family, rule_id):
    rule = next(r for r in ALL if r.id == rule_id)
    build_hardened(tmp_path / "r", family)
    assert mutate(tmp_path / "r", rule, family)
    host = FixtureHost(tmp_path / "r")
    report = audit(host, ALL)
    assert {r.rule.id: r.status for r in report.results}[rule_id] == "fail"
    changes = fixes.plan(host, report, ALL, only=[rule_id])
    assert changes, "a failing fixable rule must produce a change"
    fixes.apply(host, changes)
    assert _status(FixtureHost(tmp_path / "r"), rule_id) == "pass"
