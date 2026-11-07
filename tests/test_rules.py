import pytest

from hardaudit import rules


def test_the_bundled_rules_load_and_ids_are_unique():
    loaded = rules.load()
    assert len(loaded) >= 55
    assert len({r.id for r in loaded}) == len(loaded)


def test_every_rule_explains_itself():
    for rule in rules.load():
        assert len(rule.why) > 20 and len(rule.fix) > 10, rule.id
        assert not rule.title[0].islower() and not rule.title.endswith("."), rule.id


def test_every_fixable_rule_is_low_risk_by_construction():
    # A fix may only remove permission bits, set one stricter kernel value, edit one named
    # line, or block a module. Rules that can cut you off from a machine must not have one.
    for rule in rules.load():
        if rule.apply:
            assert rule.section not in ("SSH", "Software"), rule.id
            assert rule.apply["type"] in rules.APPLY_TYPES


def test_the_checked_value_of_a_fixable_sysctl_rule_equals_what_the_fix_sets():
    for rule in rules.load():
        if rule.apply and rule.apply["type"] == "sysctl":
            want = [str(v) for v in rule.check.get("expect_in", [rule.check.get("expect")])]
            assert str(rule.apply["value"]) in want, rule.id


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("[[rule]]\nid='HA-X-1'", "missing"),
        ("not toml [", "not valid TOML"),
        ("rule = 3", "array of tables"),
    ],
)
def test_malformed_rule_files_are_rejected_with_a_message(text, message):
    with pytest.raises(rules.RuleError, match=message):
        rules.parse(text, "t.toml")


def _rule(**over):
    base = {"id": "HA-ZZ-001", "title": "T", "section": "S", "severity": "low", "why": "w" * 30,
            "fix": "f" * 20, "check": {"type": "sysctl", "key": "a.b", "expect": "1"}}  # fmt: skip
    base.update(over)
    return base


@pytest.mark.parametrize(
    ("over", "message"),
    [
        ({"id": "bad"}, "id must look like"),
        ({"severity": "huge"}, "severity"),
        ({"families": ["plan9"]}, "families"),
        ({"check": {"type": "nope"}}, "check.type"),
        ({"apply": {"type": "rm_rf"}}, "apply.type"),
    ],
)
def test_each_invalid_field_is_named(over, message):
    with pytest.raises(rules.RuleError, match=message):
        rules._build(_rule(**over), "t.toml")


def test_duplicate_ids_across_files_are_refused(tmp_path):
    (tmp_path / "x.toml").write_text(
        '[[rule]]\nid="HA-KRN-001"\ntitle="T"\nsection="S"\nseverity="low"\nwhy="why"\nfix="fix"\n'
        'check={type="sysctl",key="a.b",expect="1"}\n'
    )
    with pytest.raises(rules.RuleError, match="duplicate"):
        rules.load(tmp_path)


def test_extra_rule_files_are_loaded(tmp_path):
    (tmp_path / "mine.toml").write_text(
        '[[rule]]\nid="HA-MY-001"\ntitle="Mine"\nsection="S"\nseverity="low"\nwhy="why"\nfix="fix"\n'
        'check={type="path_absent",paths=["/x"]}\n'
    )
    assert "HA-MY-001" in {r.id for r in rules.load(tmp_path)}
