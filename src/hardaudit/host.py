"""Read-only view of the machine being audited.

Everything is read through ``Host`` so the same checks run against the live system
(``root="/"``) and against a directory tree (an extracted image, a mounted disk, a test fixture).
Commands (systemctl, rpm) are only run for the live system, or for ``rpm`` with ``--root``.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from collections.abc import Callable
from pathlib import Path

Runner = Callable[[list[str]], "subprocess.CompletedProcess[str]"]

_DEBIAN = {"debian", "ubuntu", "raspbian", "linuxmint", "kali", "pop"}
_RHEL = {"rhel", "centos", "rocky", "almalinux", "fedora", "ol", "amzn"}


def _run(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, capture_output=True, text=True, timeout=30, check=False)


def parse_os_release(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in text.splitlines():
        match = re.match(r"^([A-Z_]+)=(.*)$", line.strip())
        if match:
            values[match.group(1)] = match.group(2).strip().strip("\"'")
    return values


def family_of(os_release: dict[str, str]) -> str:
    ids = {os_release.get("ID", "").lower(), *os_release.get("ID_LIKE", "").lower().split()}
    if ids & _DEBIAN:
        return "debian"
    if ids & _RHEL:
        return "rhel"
    return "other"


class Host:
    def __init__(
        self, root: str | Path = "/", run: Runner | None = None, *, runtime: bool | None = None
    ) -> None:
        self.root = Path(root)
        self.live = self.root == Path("/")
        # True when /proc describes a running kernel. A directory tree (an image, a fixture)
        # has no kernel: kernel settings come from the sysctl files, mounts from /etc/fstab.
        self.runtime = self.live if runtime is None else runtime
        self._run = run or _run
        self._packages: set[str] | bool | None = False  # False = not loaded yet

    # -- files ---------------------------------------------------------------------------
    def path(self, name: str) -> Path:
        return self.root / name.lstrip("/")

    def read(self, name: str) -> str | None:
        """File contents, or None if it is missing or unreadable."""
        try:
            return self.path(name).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None

    def readable(self, name: str) -> bool:
        return self.read(name) is not None

    def exists(self, name: str) -> bool:
        return self.path(name).exists() or self.path(name).is_symlink()

    def stat(self, name: str) -> tuple[int, int, int] | None:
        """(permission bits, uid, gid) or None if missing."""
        try:
            info = self.path(name).stat()
        except OSError:
            return None
        return info.st_mode & 0o7777, info.st_uid, info.st_gid

    def glob(self, pattern: str) -> list[str]:
        """Paths (as seen from inside the audited system) matching a glob, sorted."""
        base = self.path(pattern)
        found = sorted(base.parent.glob(base.name)) if base.parent.is_dir() else []
        return ["/" + str(p.relative_to(self.root)).replace("\\", "/") for p in found]

    # -- system ---------------------------------------------------------------------------
    def os_release(self) -> dict[str, str]:
        text = self.read("/etc/os-release") or self.read("/usr/lib/os-release") or ""
        return parse_os_release(text)

    def family(self) -> str:
        return family_of(self.os_release())

    def distro(self) -> str:
        info = self.os_release()
        return info.get("PRETTY_NAME") or info.get("NAME") or "unknown"

    def sysctl(self, key: str) -> str | None:
        """The running value, or for a directory tree the value the sysctl files configure."""
        if self.runtime:
            text = self.read("/proc/sys/" + key.replace(".", "/"))
            return text.strip() if text is not None else None
        return self._sysctl_configured().get(key)

    def _sysctl_configured(self) -> dict[str, str]:
        by_name: dict[str, str] = {}
        for folder in ("/lib/sysctl.d", "/usr/lib/sysctl.d", "/run/sysctl.d", "/etc/sysctl.d"):
            for path in self.glob(f"{folder}/*.conf"):
                by_name[path.rsplit("/", 1)[1]] = path  # later folders override same names
        ordered = [by_name[n] for n in sorted(by_name)]
        if self.exists("/etc/sysctl.conf"):
            ordered.append("/etc/sysctl.conf")
        values: dict[str, str] = {}
        for path in ordered:
            for line in (self.read(path) or "").splitlines():
                line = line.strip()
                if not line or line[0] in "#;" or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                key = key.strip().lstrip("-").replace("/", ".")
                values[key] = value.strip()
        return values

    def mounts(self) -> dict[str, set[str]]:
        """Mount point -> its options. A running system is read from /proc; a tree from fstab."""
        table: dict[str, set[str]] = {}
        if self.runtime:
            text = self.read("/proc/self/mounts") or self.read("/proc/mounts") or ""
            fields = (1, 3)
        else:
            text = self.read("/etc/fstab") or ""
            fields = (1, 3)
        for line in text.splitlines():
            parts = line.split()
            if len(parts) >= 4 and not parts[0].startswith("#"):
                table[parts[fields[0]]] = set(parts[fields[1]].split(","))
        return table

    def modules_loaded(self) -> set[str]:
        text = self.read("/proc/modules") or ""
        return {line.split()[0] for line in text.splitlines() if line.strip()}

    # -- packages -------------------------------------------------------------------------
    def packages(self) -> set[str] | None:
        """Installed package names, or None when this run cannot tell."""
        if self._packages is not False:
            return self._packages  # type: ignore[return-value]
        found: set[str] | None = None
        dpkg = self.read("/var/lib/dpkg/status")
        if dpkg is not None:
            found = set()
            for block in dpkg.split("\n\n"):
                name = re.search(r"^Package: (\S+)", block, re.M)
                status = re.search(r"^Status: (.*)$", block, re.M)
                if (
                    name
                    and status
                    and status.group(1).endswith(" installed")
                    and (
                        "deinstall" not in status.group(1)
                        and "not-installed" not in status.group(1)
                    )
                ):
                    found.add(name.group(1))
        elif shutil.which("rpm") or self._run is not _run:  # a test may inject a fake rpm
            command = ["rpm", "-qa", "--qf", "%{NAME}\\n"]
            if not self.live:
                command[1:1] = ["--root", str(self.root)]
            try:
                done = self._run(command)
            except (OSError, subprocess.SubprocessError):
                done = None
            if done is not None and done.returncode == 0:
                found = {line.strip() for line in done.stdout.splitlines() if line.strip()}
        self._packages = found
        return found

    # -- services -------------------------------------------------------------------------
    def systemctl(self, *args: str) -> subprocess.CompletedProcess[str] | None:
        """Run systemctl on the live system only; None when that is not possible."""
        if not self.live or (shutil.which("systemctl") is None and self._run is _run):
            return None
        try:
            return self._run(["systemctl", *args])
        except (OSError, subprocess.SubprocessError):
            return None
