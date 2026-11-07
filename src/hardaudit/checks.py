"""The check types. Each takes the host and the rule's ``check`` table and returns
``(status, detail)``. A check never raises for a missing or unreadable file: that is a
result ("na" or "untestable"), not a crash.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any

from hardaudit.host import Host

Outcome = tuple[str, str]
Check = Callable[[Host, dict[str, Any]], Outcome]


def _family_list(table: dict[str, list[str]], family: str) -> list[str]:
    return list(table.get(family, []))


# -- sysctl ----------------------------------------------------------------------------------
def check_sysctl(host: Host, spec: dict[str, Any]) -> Outcome:
    key = spec["key"]
    value = host.sysctl(key)
    if value is None:
        if host.runtime:
            return "na", f"{key} does not exist on this kernel"
        return (
            "untestable",
            f"{key} is not set in the sysctl files (the kernel default is unknown offline)",
        )
    if "min" in spec:
        try:
            ok = int(value) >= int(spec["min"])
        except ValueError:
            return "error", f"{key} is {value!r}, not a number"
        return ("pass" if ok else "fail"), f"{key} = {value} (needs at least {spec['min']})"
    wanted = [str(v) for v in spec.get("expect_in", [spec.get("expect")])]
    ok = value in wanted
    return ("pass" if ok else "fail"), f"{key} = {value} (wanted {' or '.join(wanted)})"


def expand_paths(host: Host, patterns: list[str]) -> list[str]:
    """Literal paths stay as they are; patterns with * ? [ are expanded on this host."""
    out: list[str] = []
    for pattern in patterns:
        out += host.glob(pattern) if any(c in pattern for c in "*?[") else [pattern]
    return out


# -- file_mode -------------------------------------------------------------------------------
def check_file_mode(host: Host, spec: dict[str, Any]) -> Outcome:
    problems: list[str] = []
    seen = 0
    for path in expand_paths(host, spec["paths"]):
        info = host.stat(path)
        if info is None:
            continue
        seen += 1
        mode, uid, _gid = info
        allowed = int(spec["max_mode"], 8)
        if mode & ~allowed & 0o7777:
            problems.append(f"{path} is {mode:04o}, allowed {allowed:04o}")
        if "owner_uid" in spec and uid != spec["owner_uid"]:
            problems.append(f"{path} is owned by uid {uid}, wanted {spec['owner_uid']}")
    if seen == 0:
        return "na", "none of the files exists on this host"
    if problems:
        return "fail", "; ".join(problems)
    return "pass", f"{seen} file(s) within {spec['max_mode']}"


# -- config ----------------------------------------------------------------------------------
def _config_lines(host: Host, name: str, depth: int = 0) -> list[str]:
    """Lines of a config file with ``Include`` directives expanded in place (sshd style)."""
    text = host.read(name)
    if text is None or depth > 5:
        return []
    out: list[str] = []
    for line in text.splitlines():
        include = re.match(r"^\s*Include\s+(.+)$", line, re.I)
        if include:
            for pattern in include.group(1).split():
                if not pattern.startswith("/"):
                    pattern = "/etc/ssh/" + pattern
                for found in host.glob(pattern):
                    out += _config_lines(host, found, depth + 1)
        else:
            out.append(line)
    return out


def config_value(host: Host, spec: dict[str, Any]) -> tuple[str | None, bool]:
    """(value, found). First occurrence wins (sshd) unless ``last_wins``. Anything after a
    ``Match`` line is conditional and is ignored."""
    lines: list[str] = []
    for name in spec["files"]:
        lines += _config_lines(host, name)
    for pattern in spec.get("dropins", []):
        for name in host.glob(pattern):
            lines += _config_lines(host, name)
    value: str | None = None
    wanted = spec["key"].lower()
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if re.match(r"^match\s", stripped, re.I):
            break
        parts = re.split(r"[\s=]+", stripped, maxsplit=1)
        if len(parts) == 2 and parts[0].lower() == wanted:
            value = parts[1].strip().strip('"')
            if not spec.get("last_wins"):
                return value, True
    return value, value is not None


def check_config(host: Host, spec: dict[str, Any]) -> Outcome:
    if not any(host.exists(n) for n in spec["files"]):
        return "na", f"{spec['files'][0]} does not exist"
    value, found = config_value(host, spec)
    shown = value
    if not found:
        shown = spec.get("default")
        if shown is None:
            return "fail", f"{spec['key']} is not set"
    assert shown is not None
    source = "" if found else " (default, not set in the file)"
    lowered = shown.lower()
    if "max" in spec or "min" in spec:
        try:
            number = int(shown)
        except ValueError:
            return "fail", f"{spec['key']} is {shown!r}, not a number"
        if "max" in spec and not 0 <= number <= int(spec["max"]):
            return "fail", f"{spec['key']} = {shown}{source}, must be 0 to {spec['max']}"
        if "min" in spec and number < int(spec["min"]):
            return "fail", f"{spec['key']} = {shown}{source}, must be at least {spec['min']}"
        return "pass", f"{spec['key']} = {shown}{source}"
    wanted = [str(v).lower() for v in spec["expect_in"]]
    ok = lowered in wanted
    return ("pass" if ok else "fail"), (
        f"{spec['key']} = {shown}{source} (wanted {' or '.join(wanted)})"
    )


# -- mount -----------------------------------------------------------------------------------
def check_mount(host: Host, spec: dict[str, Any]) -> Outcome:
    table = host.mounts()
    if not table:
        return "untestable", "cannot read the mount table"
    options = table.get(spec["path"])
    if options is None and not host.runtime:
        return (
            "untestable",
            f"{spec['path']} is not in /etc/fstab; systemd may still mount it at boot",
        )
    if options is None:
        return "fail", f"{spec['path']} is not a separate mount"
    missing = [o for o in spec["require"] if o not in options]
    if missing:
        return "fail", f"{spec['path']} is mounted without {', '.join(missing)}"
    return "pass", f"{spec['path']} has {', '.join(spec['require'])}"


# -- package ---------------------------------------------------------------------------------
def check_package(host: Host, spec: dict[str, Any]) -> Outcome:
    family = host.family()
    if family == "other":
        return "untestable", "package names differ by distribution and this one is not known"
    installed = host.packages()
    if installed is None:
        return "untestable", "cannot read the package database (no dpkg status, no rpm)"
    if "absent" in spec:
        names = _family_list(spec["absent"], family)
        present = sorted(n for n in names if n in installed)
        if present:
            return "fail", f"installed: {', '.join(present)}"
        return "pass", f"not installed: {', '.join(names)}"
    names = _family_list(spec["present"], family)
    have = [n for n in names if n in installed]
    if have:
        return "pass", f"installed: {', '.join(have)}"
    return "fail", f"not installed: {', '.join(names)}"


# -- module ----------------------------------------------------------------------------------
_MODPROBE_DIRS = ("/etc/modprobe.d", "/usr/lib/modprobe.d", "/lib/modprobe.d", "/run/modprobe.d")


def module_blocked(host: Host, module: str) -> bool:
    pattern = re.compile(rf"^\s*install\s+{re.escape(module)}\s+(/usr)?/bin/(true|false)\b", re.M)
    for folder in _MODPROBE_DIRS:
        for name in host.glob(f"{folder}/*.conf"):
            text = host.read(name)
            if text is not None and pattern.search(text):
                return True
    return False


def check_module(host: Host, spec: dict[str, Any]) -> Outcome:
    module = spec["module"]
    if module in host.modules_loaded():
        return "fail", f"{module} is loaded right now"
    if module_blocked(host, module):
        return "pass", f"{module} cannot be loaded (install line in modprobe.d)"
    return "fail", f"{module} can be loaded: no 'install {module} /bin/true' line in modprobe.d"


# -- accounts --------------------------------------------------------------------------------
_LOGIN_OK = {"root", "sync", "shutdown", "halt"}


def check_accounts(host: Host, spec: dict[str, Any]) -> Outcome:
    test = spec["test"]
    if test == "empty_password":
        shadow = host.read("/etc/shadow")
        if shadow is None:
            return "untestable", "/etc/shadow is not readable (run as root)"
        empty = [ln.split(":")[0] for ln in shadow.splitlines() if ln.count(":") >= 2
                 and ln.split(":")[1] == ""]  # fmt: skip
        return ("fail", f"no password: {', '.join(empty)}") if empty else ("pass", "none")
    passwd = host.read("/etc/passwd")
    if passwd is None:
        return "na", "/etc/passwd does not exist"
    rows = [ln.split(":") for ln in passwd.splitlines() if ln.count(":") >= 6 and ln[0] != "#"]
    if test == "uid0_only_root":
        extra = [r[0] for r in rows if r[2] == "0" and r[0] != "root"]
        return ("fail", f"uid 0: {', '.join(extra)}") if extra else ("pass", "only root has uid 0")
    if test == "unique_uids":
        seen: dict[str, str] = {}
        dup = []
        for r in rows:
            if r[2] in seen:
                dup.append(f"{r[0]} and {seen[r[2]]} share uid {r[2]}")
            seen[r[2]] = r[0]
        return ("fail", "; ".join(dup)) if dup else ("pass", "every uid is used once")
    if test == "system_shells":
        bad = []
        for r in rows:
            if r[0] in _LOGIN_OK or not r[2].isdigit() or int(r[2]) >= 1000:
                continue
            if r[6].strip() not in ("", "/sbin/nologin", "/usr/sbin/nologin", "/bin/false",
                                    "/usr/bin/false", "/bin/sync", "/sbin/shutdown", "/sbin/halt"):  # fmt: skip
                bad.append(f"{r[0]} ({r[6]})")
        return (
            ("fail", f"system accounts with a shell: {', '.join(bad)}")
            if bad
            else ("pass", "system accounts cannot log in")
        )
    return "error", f"unknown accounts test {test!r}"


# -- service ---------------------------------------------------------------------------------
def check_service(host: Host, spec: dict[str, Any]) -> Outcome:
    unit = spec["unit"]
    done = host.systemctl("is-enabled", unit)
    if done is None:
        return "untestable", "service state is read with systemctl on the running system only"
    state = done.stdout.strip() or done.stderr.strip()
    if "not been booted with systemd" in state or "Failed to connect" in state:
        return "untestable", "systemd is not running here"
    first = state.splitlines()[0] if state else "unknown"
    if spec["state"] == "enabled" and (first == "not-found" or "No such file" in state):
        return "na", f"{unit} is not installed (see the rule that checks for the package)"
    if spec["state"] == "disabled":
        ok = first in ("disabled", "masked", "not-found", "static", "indirect") or (
            "No such file" in state or "not-found" in state
        )
        return ("pass" if ok else "fail"), f"{unit} is {first}"
    ok = first in ("enabled", "enabled-runtime", "static")
    return ("pass" if ok else "fail"), f"{unit} is {first}"


# -- file_regex ------------------------------------------------------------------------------
def check_file_regex(host: Host, spec: dict[str, Any]) -> Outcome:
    names = [n for n in expand_paths(host, spec["paths"]) if host.exists(n)]
    if not names:
        return "na", "none of the files exists on this host"
    texts = [host.read(n) for n in names]
    if all(t is None for t in texts):
        return "untestable", f"cannot read {', '.join(names)} (run as root)"
    joined = "\n".join(t for t in texts if t is not None)
    if "forbid" in spec:
        hit = re.search(spec["forbid"], joined, re.M)
        return ("fail", f"found {hit.group(0)!r}") if hit else ("pass", "pattern not present")
    ok = re.search(spec["require"], joined, re.M) is not None
    return ("pass", "required line present") if ok else ("fail", "required line missing")


# -- path_absent -----------------------------------------------------------------------------
def check_path_absent(host: Host, spec: dict[str, Any]) -> Outcome:
    present: list[str] = []
    unreadable: list[str] = []
    for path in expand_paths(host, spec["paths"]):
        try:
            if host.exists(path):
                present.append(path)
        except PermissionError:
            unreadable.append(path)  # a directory we may not enter: we cannot say it is absent
    if present:
        return "fail", f"present: {', '.join(present)}"
    if unreadable:
        return "untestable", f"cannot look at {', '.join(unreadable)} (run as root)"
    return "pass", "none present"


CHECKS: dict[str, Check] = {
    "sysctl": check_sysctl,
    "file_mode": check_file_mode,
    "config": check_config,
    "mount": check_mount,
    "package": check_package,
    "module": check_module,
    "accounts": check_accounts,
    "service": check_service,
    "file_regex": check_file_regex,
    "path_absent": check_path_absent,
}
