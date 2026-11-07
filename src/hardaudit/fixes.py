"""Apply the safe fixes, with a backup of everything touched, and undo them.

Only rules that carry an ``apply`` table are ever changed, and each change only removes
permissions, sets a kernel parameter to a stricter value, or edits one named line. A dry run
(the default) changes nothing and shows exactly what would be written.

Backups live under ``<root>/var/lib/hardaudit/backups/<id>/`` as a ``manifest.json`` plus a
copy of every file as it was. ``undo`` puts the files back (and removes the ones that did not
exist before) and restores the kernel parameters it changed.
"""

from __future__ import annotations

import base64
import contextlib
import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from hardaudit.checks import expand_paths
from hardaudit.host import Host
from hardaudit.model import Report, Rule

SYSCTL_FILE = "/etc/sysctl.d/99-hardaudit.conf"
MODPROBE_FILE = "/etc/modprobe.d/hardaudit.conf"
BACKUPS = "/var/lib/hardaudit/backups"


class FixError(RuntimeError):
    pass


@dataclass
class Change:
    """One planned change, described in words and as data."""

    rule_id: str
    kind: str  # write_file | chmod | sysctl_runtime
    path: str
    summary: str
    data: dict[str, Any] = field(default_factory=dict)


# -- planning --------------------------------------------------------------------------------
def _sysctl_changes(host: Host, rule: Rule, planned: dict[str, str]) -> list[Change]:
    key, value = rule.check["key"], str(rule.apply["value"])  # type: ignore[index]
    path = "/proc/sys/" + key.replace(".", "/")
    planned[key] = value
    if not host.runtime:
        return []  # a directory tree has no running kernel; only the file is written
    return [
        Change(
            rule.id,
            "sysctl_runtime",
            path,
            f"set {key} = {value} now",
            {"key": key, "value": value},
        )
    ]


def _chmod_changes(host: Host, rule: Rule) -> list[Change]:
    allowed = int(rule.check["max_mode"], 8)
    out = []
    for path in expand_paths(host, rule.check["paths"]):
        info = host.stat(path)
        if info is None:
            continue
        new = info[0] & allowed
        if new != info[0]:
            out.append(
                Change(
                    rule.id,
                    "chmod",
                    path,
                    f"chmod {info[0]:04o} -> {new:04o} {path}",
                    {"mode": new},
                )
            )
    return out


def _set_line(text: str, key: str, value: str) -> str:
    """Replace the last uncommented ``key`` line, or append one."""
    lines = text.splitlines()
    pattern = re.compile(rf"^\s*{re.escape(key)}(\s|=|$)", re.I)
    index = max((i for i, ln in enumerate(lines) if pattern.match(ln)), default=None)
    new = f"{key}\t{value}"
    if index is None:
        lines.append(new)
    else:
        lines[index] = new
    return "\n".join(lines) + "\n"


def plan(
    host: Host, report: Report, rules: list[Rule], *, only: list[str] | None = None
) -> list[Change]:
    """Changes that would fix the failing, fixable rules (optionally only the named ones)."""
    by_id = {r.id: r for r in rules}
    failing = [r.rule.id for r in report.results if r.status == "fail" and r.rule.apply]
    if only:
        unknown = [i for i in only if i not in by_id]
        if unknown:
            raise FixError(f"unknown rule id: {', '.join(unknown)}")
        failing = [i for i in failing if i in only]
    sysctl_values: dict[str, str] = {}
    module_names: list[str] = []
    changes: list[Change] = []
    config_edits: dict[str, str] = {}
    for rule_id in failing:
        rule = by_id[rule_id]
        kind = rule.apply["type"]  # type: ignore[index]
        if kind == "sysctl":
            changes += _sysctl_changes(host, rule, sysctl_values)
        elif kind == "chmod":
            changes += _chmod_changes(host, rule)
        elif kind == "module_block":
            module_names.append(rule.check["module"])
        elif kind == "config_line":
            file, key, value = (rule.apply[k] for k in ("file", "key", "value"))  # type: ignore[index]
            text = config_edits.get(file, host.read(file))
            if text is None:
                continue
            config_edits[file] = _set_line(text, key, value)
            changes.append(
                Change(
                    rule.id,
                    "write_file",
                    file,
                    f"set {key} {value} in {file}",
                    {"content": config_edits[file]},
                )
            )
    if sysctl_values:
        old = host.read(SYSCTL_FILE) or ""
        body = old.rstrip("\n") + ("\n" if old else "")
        for key, value in sysctl_values.items():
            body += f"{key} = {value}\n"
        changes.append(
            Change(
                "*",
                "write_file",
                SYSCTL_FILE,
                f"persist {len(sysctl_values)} kernel setting(s) in {SYSCTL_FILE}",
                {"content": body if old else "# written by hardaudit\n" + body},
            )
        )
    if module_names:
        old = host.read(MODPROBE_FILE) or ""
        body = old if old else "# written by hardaudit\n"
        for name in module_names:
            body += f"install {name} /bin/true\n"
        changes.append(
            Change(
                "*",
                "write_file",
                MODPROBE_FILE,
                f"block {len(module_names)} module(s) in {MODPROBE_FILE}",
                {"content": body},
            )
        )
    return changes


# -- applying --------------------------------------------------------------------------------
def _backup_dir(host: Host, backup_id: str) -> Path:
    return host.path(f"{BACKUPS}/{backup_id}")


def apply(host: Host, changes: list[Change], warnings: list[str] | None = None) -> str:
    """Make the changes and return the backup id for ``undo``.

    A kernel setting that cannot be changed on the running system (a container or a
    hardened VM mounts /proc/sys read-only) is not fatal: its value is still saved in the
    sysctl file, and a note is added to ``warnings``.
    """
    if not changes:
        raise FixError("nothing to change")
    backup_id = time.strftime("%Y%m%dT%H%M%S", time.gmtime())
    folder = _backup_dir(host, backup_id)
    suffix = 0
    while folder.exists():
        suffix += 1
        folder = _backup_dir(host, f"{backup_id}-{suffix}")
    backup_id = folder.name
    folder.mkdir(parents=True, mode=0o700)
    entries: list[dict[str, Any]] = []
    # Write the manifest first, then update it after each change, so an interrupted run
    # can still be undone up to the point it reached.
    manifest = folder / "manifest.json"

    def save() -> None:
        manifest.write_text(json.dumps({"entries": entries}, indent=1), encoding="utf-8")

    save()
    for change in changes:
        target = host.path(change.path)
        if change.kind == "write_file":
            existed = target.exists()
            entry: dict[str, Any] = {"kind": "file", "path": change.path, "existed": existed}
            if existed:
                entry["mode"] = target.stat().st_mode & 0o7777
                entry["content"] = base64.b64encode(target.read_bytes()).decode()
            # Directories that do not exist yet are recorded first, outermost first, so that
            # undoing in reverse removes the file and then the empty directories.
            missing = []
            for parent in reversed(target.parents):
                if parent != host.root and not parent.exists() and host.root in parent.parents:
                    missing.append("/" + str(parent.relative_to(host.root)).replace("\\", "/"))
            entries.extend({"kind": "dir", "path": name} for name in missing)
            entries.append(entry)
            save()
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(change.data["content"], encoding="utf-8")
            if not existed:
                target.chmod(0o644)
        elif change.kind == "chmod":
            entries.append(
                {"kind": "mode", "path": change.path, "mode": target.stat().st_mode & 0o7777}
            )
            save()
            target.chmod(change.data["mode"])
        elif change.kind == "sysctl_runtime":
            if not host.runtime:
                continue  # a directory tree has no running kernel to change
            old = target.read_text(encoding="utf-8").strip() if target.exists() else None
            if old is None:
                continue
            try:
                target.write_text(change.data["value"], encoding="utf-8")
            except OSError as exc:
                if warnings is not None:
                    warnings.append(
                        f"could not set {change.data['key']} on the running system ({exc.strerror or exc}); "
                        f"it is saved in {SYSCTL_FILE} and applies after 'sysctl --system' or a reboot"
                    )
                continue
            entries.append({"kind": "sysctl", "path": change.path, "old": old})
            save()
    return backup_id


def list_backups(host: Host) -> list[str]:
    folder = host.path(BACKUPS)
    return (
        sorted(p.name for p in folder.iterdir() if (p / "manifest.json").exists())
        if folder.is_dir()
        else []
    )


def undo(host: Host, backup_id: str) -> int:
    """Restore everything recorded in a backup, newest change first. Returns how many."""
    manifest = _backup_dir(host, backup_id) / "manifest.json"
    if not manifest.exists():
        raise FixError(f"no backup named {backup_id}")
    entries = json.loads(manifest.read_text(encoding="utf-8"))["entries"]
    for entry in reversed(entries):
        target = host.path(entry["path"])
        if entry["kind"] == "file":
            if entry["existed"]:
                target.write_bytes(base64.b64decode(entry["content"]))
                target.chmod(entry["mode"])
            elif target.exists():
                target.unlink()
        elif entry["kind"] == "dir":
            with contextlib.suppress(OSError):
                target.rmdir()  # only if empty: never delete something that has content
        elif entry["kind"] == "mode":
            target.chmod(entry["mode"])
        elif entry["kind"] == "sysctl" and host.runtime:
            target.write_text(entry["old"], encoding="utf-8")
    manifest.rename(manifest.with_name("manifest.undone.json"))
    return len(entries)
