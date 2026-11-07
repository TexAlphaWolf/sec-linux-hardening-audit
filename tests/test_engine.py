from __future__ import annotations

from hardaudit import cli, rules
from hardaudit.engine import audit
from hardaudit.model import Report, Result, Rule
from tests.conftest import posix_only

ALL = rules.load()


def one(**check) -> Rule:  # type: ignore[no-untyped-def]
    return Rule(
        id="HA-ZZ-001", title="T", section="S", severity="high", why="w", fix="f", check=check
    )


@posix_only
def test_only_and_skip_select_rules(hardened):
    assert [r.rule.id for r in audit(hardened, ALL, only=["HA-SSH-001"]).results] == ["HA-SSH-001"]
    ids = {r.rule.id for r in audit(hardened, ALL, skip=["HA-SSH-001"]).results}
    assert "HA-SSH-001" not in ids and len(ids) == len(ALL) - 1


@posix_only
def test_a_broken_rule_is_an_error_not_a_crash(hardened):
    broken = one(type="sysctl")  # no key: the rule file is wrong, the audit must go on
    report = audit(hardened, [broken, *ALL[:2]])
    assert report.results[0].status == "error" and "broken" in report.results[0].detail
    assert len(report.results) == 3


def test_a_rule_for_another_family_is_not_applicable(tmp_path):
    from hardaudit.host import Host

    (tmp_path / "etc").mkdir()
    (tmp_path / "etc/os-release").write_text("ID=rocky\nID_LIKE=rhel\n")
    only_debian = Rule(id="HA-ZZ-002", title="T", section="S", severity="low", why="w", fix="f",
                       check={"type": "path_absent", "paths": ["/x"]}, families=("debian",))  # fmt: skip
    (result,) = audit(Host(tmp_path), [only_debian]).results
    assert result.status == "na" and "rhel" in result.detail


def test_the_score_ignores_what_could_not_be_judged():
    r = lambda sev, st: Result(Rule("HA-A-001", "t", "s", sev, {"type": "x"}, "w", "f"), st)  # noqa: E731
    report = Report(
        "debian",
        "d",
        "/",
        [r("high", "pass"), r("low", "fail"), r("high", "untestable"), r("high", "na")],
    )
    assert report.score == round(100 * 5 / 6, 1)
    assert Report("debian", "d", "/", [r("high", "na")]).score is None


@posix_only
def test_apply_on_the_running_system_needs_root(monkeypatch, capsys):
    monkeypatch.setattr(cli.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(
        cli.fixes, "plan", lambda *a, **k: [cli.fixes.Change("X", "chmod", "/x", "x")]
    )
    monkeypatch.setattr(
        cli.fixes, "apply", lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not run"))
    )
    code = cli.main(["fix", "--apply"])
    assert code == 2 and "needs root" in capsys.readouterr().err
