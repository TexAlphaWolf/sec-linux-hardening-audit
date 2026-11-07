"""The documents must say what the code does."""

from pathlib import Path

from hardaudit import rules
from hardaudit.cli import rules_markdown

ROOT = Path(__file__).resolve().parent.parent


def test_the_rules_table_in_the_docs_is_the_generated_one():
    text = (ROOT / "docs/rules.md").read_text(encoding="utf-8")
    block = text.split("<!-- rules:start -->\n")[1].split("<!-- rules:end -->")[0]
    assert block.strip() == rules_markdown(rules.load()).strip()


def test_the_readme_counts_match_the_rules():
    loaded = rules.load()
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert f"{len(loaded)} rules" in readme
    assert f"Only {sum(1 for r in loaded if r.apply)} rules have a fix" in readme


def test_the_custom_rules_example_loads():
    assert [r.id for r in rules.load(ROOT / "examples")][-2:] == ["HA-MY-001", "HA-MY-002"]
