from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from hardaudit import fixes, rules
from hardaudit.engine import audit
from tests.conftest import posix_only
from tests.fixtures import FixtureHost

ALL = rules.load()


def snapshot(root: Path) -> dict[str, tuple[str, int]]:
    """Every file and directory under root: content hash and mode. Backups are excluded."""
    state = {}
    for path in sorted(root.rglob("*")):
        rel = str(path.relative_to(root))
        if rel.startswith("var/lib/hardaudit"):
            continue
        try:
            digest = hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else "dir"
        except PermissionError:
            digest = (
                "unreadable"  # an ordinary user cannot read a mode 000 shadow; the mode is compared
            )
        state[rel] = (digest, path.stat().st_mode & 0o7777)
    return state


@posix_only
def test_a_dry_run_changes_nothing(insecure):
    before = snapshot(insecure.root)
    report = audit(insecure, ALL)
    changes = fixes.plan(insecure, report, ALL)
    assert changes
    assert snapshot(insecure.root) == before
    assert not (insecure.root / "var/lib/hardaudit").exists()


@posix_only
def test_apply_raises_the_score_and_never_touches_unfixable_rules(insecure):
    before = audit(insecure, ALL)
    changes = fixes.plan(insecure, before, ALL)
    fixes.apply(insecure, changes)
    after = audit(FixtureHost(insecure.root), ALL)
    assert after.score is not None and before.score is not None and after.score > before.score
    fixable = {r.id for r in ALL if r.apply}
    for result in after.results:
        if result.rule.id in fixable:
            continue
        original = next(r for r in before.results if r.rule.id == result.rule.id)
        assert result.status == original.status, result.rule.id
    # Everything with an automatic fix passes now (the config-only edits included).
    still = [r.rule.id for r in after.results if r.rule.apply and r.status == "fail"]
    assert still == []


@posix_only
def test_undo_restores_the_tree_exactly(insecure):
    before = snapshot(insecure.root)
    backup = fixes.apply(insecure, fixes.plan(insecure, audit(insecure, ALL), ALL))
    assert snapshot(insecure.root) != before
    restored = fixes.undo(insecure, backup)
    assert restored > 0
    assert snapshot(insecure.root) == before  # content and mode, including removed new files


@posix_only
def test_applying_twice_changes_nothing_the_second_time(insecure):
    fixes.apply(insecure, fixes.plan(insecure, audit(insecure, ALL), ALL))
    again = fixes.plan(insecure, audit(FixtureHost(insecure.root), ALL), ALL)
    assert again == []


@posix_only
def test_chmod_only_ever_removes_permission_bits(insecure):
    path = insecure.root / "etc/crontab"
    path.chmod(
        0o644
    )  # not 0600, but also nothing beyond what 0600 would allow plus group/other read
    before_mode = path.stat().st_mode & 0o7777
    fixes.apply(insecure, fixes.plan(insecure, audit(insecure, ALL), ALL))
    after_mode = path.stat().st_mode & 0o7777
    assert after_mode & ~before_mode == 0  # no bit was added


@posix_only
def test_an_interrupted_apply_can_still_be_undone(insecure, monkeypatch):
    before = snapshot(insecure.root)
    changes = fixes.plan(insecure, audit(insecure, ALL), ALL)
    calls = {"n": 0}
    original = Path.write_text

    def flaky(self: Path, *a, **k):  # type: ignore[no-untyped-def]
        if self.name != "manifest.json":
            calls["n"] += 1
            if calls["n"] == 2:
                raise OSError("disk full")
        return original(self, *a, **k)

    monkeypatch.setattr(Path, "write_text", flaky)
    with pytest.raises(OSError, match="disk full"):
        fixes.apply(insecure, changes)
    monkeypatch.undo()
    (backup,) = fixes.list_backups(insecure)
    fixes.undo(insecure, backup)
    assert snapshot(insecure.root) == before


@posix_only
def test_undo_of_an_unknown_backup_is_an_error(insecure):
    with pytest.raises(fixes.FixError, match="no backup"):
        fixes.undo(insecure, "nope")


@posix_only
def test_a_backup_cannot_be_undone_twice(insecure):
    backup = fixes.apply(insecure, fixes.plan(insecure, audit(insecure, ALL), ALL))
    fixes.undo(insecure, backup)
    with pytest.raises(fixes.FixError):
        fixes.undo(insecure, backup)
    assert fixes.list_backups(insecure) == []


@posix_only
def test_two_applies_in_the_same_second_get_different_backups(insecure):
    first = fixes.apply(insecure, fixes.plan(insecure, audit(insecure, ALL), ALL))
    insecure_changes = fixes.plan(insecure, audit(FixtureHost(insecure.root), ALL), ALL)
    assert insecure_changes == []
    (insecure.root / "etc/crontab").chmod(0o666)
    second = fixes.apply(
        insecure, fixes.plan(insecure, audit(FixtureHost(insecure.root), ALL), ALL)
    )
    assert first != second


@posix_only
def test_nothing_to_change_is_refused(insecure):
    with pytest.raises(fixes.FixError, match="nothing"):
        fixes.apply(insecure, [])


@posix_only
def test_only_selects_rules_and_rejects_unknown_ones(insecure):
    report = audit(insecure, ALL)
    changes = fixes.plan(insecure, report, ALL, only=["HA-PRM-005"])
    assert {c.rule_id for c in changes} == {"HA-PRM-005"}
    with pytest.raises(fixes.FixError, match="unknown rule"):
        fixes.plan(insecure, report, ALL, only=["HA-XXX-999"])


@posix_only
def test_the_persisted_sysctl_file_is_valid_and_complete(insecure):
    fixes.apply(insecure, fixes.plan(insecure, audit(insecure, ALL), ALL))
    text = (insecure.root / "etc/sysctl.d/99-hardaudit.conf").read_text()
    lines = [ln for ln in text.splitlines() if ln and not ln.startswith("#")]
    assert "kernel.randomize_va_space = 2" in lines
    assert all(" = " in ln for ln in lines)


@posix_only
def test_runtime_sysctl_is_written_and_restored_on_a_running_system(tmp_path, family):
    # A "running system" view: /proc/sys holds the live values and is writable by the fix.
    from tests.fixtures import build_hardened, write

    root = tmp_path / "live"
    build_hardened(root, family)
    write(root, "/proc/sys/kernel/randomize_va_space", "0\n")
    host = FixtureHost(root)
    host.runtime = True  # this tree stands in for a running kernel
    report = audit(host, ALL, only=["HA-KRN-001"])
    assert report.results[0].status == "fail"
    changes = fixes.plan(host, report, ALL)
    assert any(c.kind == "sysctl_runtime" for c in changes)
    backup = fixes.apply(host, changes)
    assert (root / "proc/sys/kernel/randomize_va_space").read_text().strip() == "2"
    fixes.undo(host, backup)
    assert (root / "proc/sys/kernel/randomize_va_space").read_text().strip() == "0"
    manifest = json.loads(
        (root / f"var/lib/hardaudit/backups/{backup}/manifest.undone.json").read_text()
    )
    assert any(e["kind"] == "sysctl" for e in manifest["entries"])


@posix_only
def test_a_read_only_proc_sys_is_a_warning_not_a_failure(tmp_path, family):
    from tests.fixtures import build_hardened, write

    root = tmp_path / "ro"
    build_hardened(root, family)
    write(root, "/proc/sys/kernel/randomize_va_space", "0\n")
    (root / "proc/sys/kernel/randomize_va_space").chmod(0o444)
    host = FixtureHost(root)
    host.runtime = True
    changes = fixes.plan(host, audit(host, ALL, only=["HA-KRN-001"]), ALL)
    notes: list[str] = []
    import os

    if os.geteuid() == 0:  # root ignores file modes, so simulate the failing write instead
        original = Path.write_text

        def refuse(self, *a, **k):  # type: ignore[no-untyped-def]
            if "proc/sys" in str(self):
                raise OSError(30, "Read-only file system")
            return original(self, *a, **k)

        import pytest as _p

        with _p.MonkeyPatch.context() as mp:
            mp.setattr(Path, "write_text", refuse)
            backup = fixes.apply(host, changes, notes)
    else:
        backup = fixes.apply(host, changes, notes)
    assert notes and "randomize_va_space" in notes[0] and "99-hardaudit.conf" in notes[0]
    assert "kernel.randomize_va_space = 2" in (root / "etc/sysctl.d/99-hardaudit.conf").read_text()
    fixes.undo(host, backup)  # nothing runtime to restore, the file goes away
    assert not (root / "etc/sysctl.d/99-hardaudit.conf").exists()


@posix_only
def test_directories_created_by_a_fix_are_removed_by_undo(insecure):
    import shutil

    shutil.rmtree(insecure.root / "etc/modprobe.d")  # a system that has no modprobe.d at all
    before = snapshot(insecure.root)
    backup = fixes.apply(insecure, fixes.plan(insecure, audit(insecure, ALL), ALL))
    assert (insecure.root / "etc/modprobe.d/hardaudit.conf").exists()
    fixes.undo(insecure, backup)
    assert not (insecure.root / "etc/modprobe.d").exists()
    assert snapshot(insecure.root) == before


@posix_only
def test_undo_never_deletes_a_directory_that_gained_other_files(insecure):
    import shutil

    shutil.rmtree(insecure.root / "etc/modprobe.d")
    backup = fixes.apply(insecure, fixes.plan(insecure, audit(insecure, ALL), ALL))
    (insecure.root / "etc/modprobe.d/mine.conf").write_text("# added later by the admin\n")
    fixes.undo(insecure, backup)
    assert (insecure.root / "etc/modprobe.d/mine.conf").exists()
