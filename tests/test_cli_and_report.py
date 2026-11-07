from __future__ import annotations

import json

import pytest

from hardaudit import __version__, cli
from tests.conftest import posix_only
from tests.fixtures import build_hardened, build_insecure


@pytest.fixture
def trees(tmp_path):
    build_hardened(tmp_path / "good", "debian")
    build_insecure(tmp_path / "bad", "debian")
    return tmp_path


def run(capsys, *argv):
    code = cli.main(list(argv))
    out = capsys.readouterr()
    return code, out.out, out.err


@posix_only
def test_exit_code_follows_the_failures(trees, capsys):
    assert run(capsys, "audit", "--root", str(trees / "good"))[0] == 0
    assert run(capsys, "audit", "--root", str(trees / "bad"))[0] == 1
    assert run(capsys, "audit", "--root", str(trees / "bad"), "--fail-on", "none")[0] == 0


@posix_only
def test_fail_on_threshold(trees, capsys):
    only_low = ["--only", "HA-KRN-003"]  # a low-severity rule that fails in the bad tree
    root = ["--root", str(trees / "bad")]
    assert run(capsys, "audit", *root, *only_low, "--fail-on", "high")[0] == 0
    assert run(capsys, "audit", *root, *only_low, "--fail-on", "low")[0] == 1


@posix_only
def test_the_bare_command_means_audit(trees, capsys):
    code, out, _ = run(capsys, "--root", str(trees / "good"))
    assert code == 0 and "score 100.0/100" in out


@posix_only
def test_text_report_is_ascii_and_lists_the_fix(trees, capsys):
    _, out, _ = run(capsys, "audit", "--root", str(trees / "bad"))
    out.encode("ascii")
    assert "FAIL" in out and "fix:" in out and "can do this" in out
    assert "PASS " not in out  # passed rules only with -v
    _, verbose, _ = run(capsys, "audit", "--root", str(trees / "bad"), "-v")
    assert "PASS " in verbose


@posix_only
def test_json_report_is_complete(trees, capsys):
    _, out, _ = run(capsys, "audit", "--root", str(trees / "bad"), "--format", "json")
    data = json.loads(out)
    assert data["family"] == "debian" and 0 <= data["score"] <= 100
    assert sum(data["counts"].values()) == len(data["results"])
    assert all({"id", "status", "severity", "fix", "fixable"} <= r.keys() for r in data["results"])


@posix_only
def test_html_report_is_self_contained_and_escaped(trees, capsys, tmp_path):
    target = tmp_path / "r.html"
    run(capsys, "audit", "--root", str(trees / "bad"), "--format", "html", "-o", str(target))
    page = target.read_text()
    assert page.startswith("<!doctype html>") and "<script" not in page and "http" not in page
    assert "<table>" in page and "HA-SSH-001" in page


@posix_only
def test_fix_is_a_dry_run_unless_apply_is_given(trees, capsys):
    root = str(trees / "bad")
    code, out, _ = run(capsys, "fix", "--root", root)
    assert code == 0 and "Dry run" in out and "Nothing was changed" in out
    assert run(capsys, "backups", "--root", root)[1].strip() == "No backups."


@posix_only
def test_fix_apply_then_undo_through_the_cli(trees, capsys):
    root = str(trees / "bad")
    code, out, _ = run(capsys, "fix", "--apply", "--root", root)
    assert code == 0 and "Backup:" in out and "Score:" in out
    (backup,) = run(capsys, "backups", "--root", root)[1].split()
    code, out, _ = run(capsys, "undo", backup, "--root", root)
    assert code == 0 and "Restored" in out


@posix_only
def test_fix_with_nothing_to_do(trees, capsys):
    code, out, _ = run(capsys, "fix", "--root", str(trees / "good"))
    assert code == 0 and "Nothing to fix" in out


def test_usage_errors_exit_2(capsys, tmp_path):
    code, _, err = run(capsys, "undo", "nope", "--root", str(tmp_path))
    assert code == 2 and "error:" in err
    code, _, err = run(capsys, "audit", "--rules-dir", str(tmp_path / "missing_dir_ok"))
    assert code in (0, 1)  # an empty extra directory is simply empty
    (tmp_path / "bad.toml").write_text("[[rule]]\nid='x'\n")
    code, _, err = run(capsys, "rules", "--rules-dir", str(tmp_path))
    assert code == 2 and "bad.toml" in err


def test_rules_lists_every_rule(capsys):
    code, out, _ = run(capsys, "rules")
    assert code == 0 and "HA-SSH-001" in out and len(out.splitlines()) >= 55


def test_version_and_help(capsys):
    with pytest.raises(SystemExit) as stop:
        cli.main(["--version"])
    assert stop.value.code == 0 and __version__ in capsys.readouterr().out
    assert cli.main([]) in (0, 1)  # no arguments audits the running system; any result is fine
