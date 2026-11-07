"""Break exactly one rule in a hardened tree. Derived from each rule's check type, so every
rule that is added is exercised without writing a test for it by hand."""

from __future__ import annotations

import re
from pathlib import Path

from hardaudit.model import Rule
from tests.fixtures import chmod, write, write_packages, write_sysctl

PACKAGE_BAD = {
    "debian": {"HA-PKG-001": "telnet", "HA-PKG-002": "rsh-client", "HA-PKG-003": "nis",
               "HA-PKG-004": "tftpd-hpa", "HA-PKG-005": "avahi-daemon"},
    "rhel": {"HA-PKG-001": "telnet", "HA-PKG-002": "rsh", "HA-PKG-003": "ypbind",
             "HA-PKG-004": "tftp-server", "HA-PKG-005": "avahi"},
}  # fmt: skip


def _read(root: Path, name: str) -> str:
    return (root / name.lstrip("/")).read_text(encoding="utf-8")


def _bad_sysctl(spec: dict) -> str:  # type: ignore[type-arg]
    if "min" in spec:
        return str(int(spec["min"]) - 1)
    wanted = [str(v) for v in spec.get("expect_in", [spec.get("expect")])]
    return "7" if "7" not in wanted else "8"


def _drop_key(text: str, key: str) -> str:
    return "".join(
        ln for ln in text.splitlines(keepends=True) if not re.match(rf"^\s*{key}[\s=]", ln, re.I)
    )


def mutate(root: Path, rule: Rule, family: str) -> bool:
    """Break the rule in the tree at ``root``. False when this rule cannot be broken offline."""
    spec = rule.check
    kind = spec["type"]
    if kind == "sysctl":
        values = {}
        for line in _read(root, "/etc/sysctl.d/10-fixture.conf").splitlines():
            k, v = line.split(" = ")
            values[k] = v
        values[spec["key"]] = _bad_sysctl(spec)
        write_sysctl(root, values)
    elif kind == "file_mode":
        target = next(p for p in _expand(root, spec["paths"]))
        chmod(root, target, 0o777)
    elif kind == "config":
        file = spec["files"][0]
        text = _drop_key(_read(root, file), spec["key"])
        if "min" in spec and "max" not in spec:
            bad = str(int(spec["min"]) - 1)
        elif "max" in spec:
            bad = str(int(spec["max"]) + 1000)
        else:
            bad = "bogus"
        # Prepend: first-wins files (sshd) and last-wins files (login.defs) both see it,
        # so for last-wins files append instead.
        text = (
            text + f"{spec['key']} {bad}\n"
            if spec.get("last_wins")
            else f"{spec['key']} {bad}\n" + text
        )
        write(root, file, text, 0o600 if "ssh" in file else 0o644)
    elif kind == "mount":
        write(root, "/etc/fstab", "/dev/sda1 / ext4 defaults 0 1\n"
              f"tmpfs {spec['path']} tmpfs defaults 0 0\n")  # fmt: skip
    elif kind == "package":
        from tests.fixtures import PACKAGES_HARD

        names = list(PACKAGES_HARD[family])
        if "absent" in spec:
            names.append(PACKAGE_BAD[family][rule.id])
        else:
            wanted = set(spec["present"][family])
            names = [n for n in names if n not in wanted]
        write_packages(root, family, names)
    elif kind == "module":
        (root / "etc/modprobe.d/harden.conf").write_text(
            _drop_key_install(_read(root, "/etc/modprobe.d/harden.conf"), spec["module"]),
            encoding="utf-8",
        )
    elif kind == "accounts":
        _break_accounts(root, spec["test"])
    elif kind == "file_regex":
        path = spec["paths"][0]
        if "require" in spec:
            write(root, path, "# nothing\n", 0o440 if "sudoers" in path else 0o644)
        else:
            write(root, path, "Welcome to \\r on \\m\n")
    elif kind == "path_absent":
        write(root, spec["paths"][0], "+ +\n")
    else:  # service: read from systemd on a running system only
        return False
    return True


def _drop_key_install(text: str, module: str) -> str:
    return "".join(ln for ln in text.splitlines(keepends=True) if f"install {module} " not in ln)


def _expand(root: Path, patterns: list[str]) -> list[str]:
    out = []
    for pattern in patterns:
        if any(c in pattern for c in "*?["):
            base = root / pattern.lstrip("/")
            out += ["/" + str(p.relative_to(root)) for p in sorted(base.parent.glob(base.name))]
        else:
            out.append(pattern)
    return out


def _break_accounts(root: Path, test: str) -> None:
    passwd = _read(root, "/etc/passwd")
    if test == "empty_password":
        write(root, "/etc/shadow", _read(root, "/etc/shadow") + "bob::19000:::::\n", 0o640)
    elif test == "uid0_only_root":
        write(root, "/etc/passwd", passwd + "toor:x:0:0::/root:/bin/bash\n")
    elif test == "unique_uids":
        write(root, "/etc/passwd", passwd + "carol:x:1000:1000::/home/carol:/bin/bash\n")
    elif test == "system_shells":
        write(root, "/etc/passwd", passwd + "svc:x:998:998::/srv:/bin/bash\n")
