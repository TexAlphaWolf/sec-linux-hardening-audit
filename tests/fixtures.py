"""Fake root file systems for the two supported families, and mutations that break one rule.

The hardened tree is written out by hand from what a hardened system looks like, NOT derived
from the rules, so a wrong expected value in a rule file shows up as a failing test.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from hardaudit.host import Host

FAMILIES = ("debian", "rhel")

OS_RELEASE = {
    "debian": 'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\nNAME="Debian GNU/Linux"\nID=debian\n',
    "rhel": 'NAME="Rocky Linux"\nPRETTY_NAME="Rocky Linux 9.4 (Blue Onyx)"\nID="rocky"\nID_LIKE="rhel centos fedora"\n',
}

SYSCTL_HARD = {
    "kernel.randomize_va_space": "2", "fs.suid_dumpable": "0", "kernel.dmesg_restrict": "1",
    "kernel.kptr_restrict": "2", "kernel.yama.ptrace_scope": "1", "fs.protected_hardlinks": "1",
    "fs.protected_symlinks": "1", "kernel.unprivileged_bpf_disabled": "2",
    "net.ipv4.ip_forward": "0", "net.ipv4.conf.all.accept_redirects": "0",
    "net.ipv4.conf.all.send_redirects": "0", "net.ipv4.conf.all.accept_source_route": "0",
    "net.ipv4.conf.all.log_martians": "1", "net.ipv4.conf.all.rp_filter": "1",
    "net.ipv4.tcp_syncookies": "1", "net.ipv4.icmp_echo_ignore_broadcasts": "1",
    "net.ipv4.icmp_ignore_bogus_error_responses": "1",
}  # fmt: skip

SYSCTL_BAD = {
    "kernel.randomize_va_space": "0", "fs.suid_dumpable": "2", "kernel.dmesg_restrict": "0",
    "kernel.kptr_restrict": "0", "kernel.yama.ptrace_scope": "0", "fs.protected_hardlinks": "0",
    "fs.protected_symlinks": "0", "kernel.unprivileged_bpf_disabled": "0",
    "net.ipv4.ip_forward": "1", "net.ipv4.conf.all.accept_redirects": "1",
    "net.ipv4.conf.all.send_redirects": "1", "net.ipv4.conf.all.accept_source_route": "1",
    "net.ipv4.conf.all.log_martians": "0", "net.ipv4.conf.all.rp_filter": "0",
    "net.ipv4.tcp_syncookies": "0", "net.ipv4.icmp_echo_ignore_broadcasts": "0",
    "net.ipv4.icmp_ignore_bogus_error_responses": "0",
}  # fmt: skip

SSHD_HARD = """\
Include /etc/ssh/sshd_config.d/*.conf
PermitRootLogin no
PasswordAuthentication no
PermitEmptyPasswords no
MaxAuthTries 3
LoginGraceTime 30
X11Forwarding no
ClientAliveInterval 300
ClientAliveCountMax 2
IgnoreRhosts yes
HostbasedAuthentication no
PermitUserEnvironment no
LogLevel VERBOSE
"""

LOGIN_DEFS_HARD = "PASS_MAX_DAYS\t180\nPASS_MIN_DAYS\t1\nPASS_WARN_AGE\t14\nUMASK\t027\n"

PASSWD = (
    "root:x:0:0:root:/root:/bin/bash\n"
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    "sync:x:4:65534:sync:/bin:/bin/sync\n"
    "alice:x:1000:1000::/home/alice:/bin/bash\n"
)
SHADOW = "root:$6$x:19000:1:180:14:::\ndaemon:*:19000:::::\nalice:$6$y:19000:1:180:14:::\n"

PACKAGES_HARD = {
    "debian": ["bash", "coreutils", "auditd", "aide", "ufw", "openssh-server"],
    "rhel": ["bash", "coreutils", "audit", "aide", "firewalld", "openssh-server"],
}
FSTAB_HARD = (
    "/dev/sda1 / ext4 defaults 0 1\n"
    "tmpfs /tmp tmpfs defaults,nosuid,nodev,noexec 0 0\n"
    "tmpfs /dev/shm tmpfs defaults,nosuid,nodev,noexec 0 0\n"
)


def write(root: Path, name: str, text: str, mode: int = 0o644) -> Path:
    path = root / name.lstrip("/")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    if os.name == "posix":
        path.chmod(mode)
    return path


def chmod(root: Path, name: str, mode: int) -> None:
    (root / name.lstrip("/")).chmod(mode)


def write_sysctl(root: Path, values: dict[str, str]) -> None:
    write(root, "/etc/sysctl.d/10-fixture.conf", "".join(f"{k} = {v}\n" for k, v in values.items()))


def write_packages(root: Path, family: str, names: list[str]) -> None:
    if family == "debian":
        body = "".join(f"Package: {n}\nStatus: install ok installed\nVersion: 1\n\n" for n in names)
        write(root, "/var/lib/dpkg/status", body)
    else:
        write(root, "/var/lib/fixture-rpm.txt", "".join(f"{n}\n" for n in names))


def build_hardened(root: Path, family: str) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    write(root, "/etc/os-release", OS_RELEASE[family])
    write_sysctl(root, SYSCTL_HARD)
    write(root, "/etc/fstab", FSTAB_HARD)
    write(root, "/etc/ssh/sshd_config", SSHD_HARD, 0o600)
    (root / "etc/ssh/sshd_config.d").mkdir(parents=True, exist_ok=True)
    for kind in ("rsa", "ed25519"):
        write(root, f"/etc/ssh/ssh_host_{kind}_key", "KEY\n", 0o600)
    write(root, "/etc/login.defs", LOGIN_DEFS_HARD)
    write(root, "/etc/passwd", PASSWD)
    write(root, "/etc/group", "root:x:0:\nalice:x:1000:\n")
    # RHEL ships shadow files with mode 0000; Debian with 0640. Both must pass.
    shadow_mode = 0o000 if family == "rhel" else 0o640
    write(root, "/etc/shadow", SHADOW, shadow_mode)
    write(root, "/etc/gshadow", "root:*::\n", shadow_mode)
    write(root, "/etc/crontab", "# none\n", 0o600)
    for name in ("d", "hourly", "daily", "weekly", "monthly"):
        d = root / f"etc/cron.{name}"
        d.mkdir(parents=True, exist_ok=True)
        d.chmod(0o700)
    write(
        root,
        "/etc/modprobe.d/harden.conf",
        "install cramfs /bin/true\ninstall udf /bin/true\ninstall usb-storage /bin/true\n",
    )
    write_packages(root, family, PACKAGES_HARD[family])
    write(root, "/etc/sudoers", "Defaults\tuse_pty\nroot ALL=(ALL) ALL\n", 0o440)
    write(root, "/etc/security/limits.conf", "* hard core 0\n")
    write(root, "/etc/issue", "Authorised use only.\n")
    write(root, "/etc/issue.net", "Authorised use only.\n")
    return root


def build_insecure(root: Path, family: str) -> Path:
    """A neglected system: defaults of an old install, everything left open."""
    build_hardened(root, family)
    write_sysctl(root, SYSCTL_BAD)
    write(root, "/etc/fstab", "/dev/sda1 / ext4 defaults 0 1\ntmpfs /tmp tmpfs defaults 0 0\n"
          "tmpfs /dev/shm tmpfs defaults 0 0\n")  # fmt: skip
    write(root, "/etc/ssh/sshd_config", "PermitRootLogin yes\nPasswordAuthentication yes\n"
          "PermitEmptyPasswords yes\nMaxAuthTries 10\nX11Forwarding yes\n", 0o644)  # fmt: skip
    write(
        root,
        "/etc/login.defs",
        "PASS_MAX_DAYS\t99999\nPASS_MIN_DAYS\t0\nPASS_WARN_AGE\t-1\nUMASK\t022\n",
    )
    write(
        root,
        "/etc/passwd",
        PASSWD + "toor:x:0:0::/root:/bin/bash\nsvc:x:998:998::/srv:/bin/bash\n",
        0o666,
    )
    write(root, "/etc/shadow", SHADOW + "bob::19000:::::\n", 0o644)
    chmod(root, "/etc/crontab", 0o666)
    chmod(root, "/etc/cron.d", 0o777)
    chmod(root, "/etc/ssh/ssh_host_rsa_key", 0o644)
    (root / "etc/modprobe.d/harden.conf").unlink()
    names = [*PACKAGES_HARD[family], "telnet", "avahi-daemon" if family == "debian" else "avahi"]
    write_packages(root, family, [n for n in names if n not in ("auditd", "audit", "aide")])
    write(root, "/etc/sudoers", "root ALL=(ALL) ALL\n", 0o440)
    write(root, "/etc/security/limits.conf", "# nothing\n")
    write(root, "/etc/issue", "Welcome to \\s \\r \\m\n")
    write(root, "/etc/hosts.equiv", "+ +\n")
    return root


class FixtureHost(Host):
    """Host for a fixture tree: files made by the test user count as owned by root, and the
    RHEL package list comes from a text file instead of the rpm program."""

    def stat(self, name: str) -> tuple[int, int, int] | None:
        info = super().stat(name)
        if info is None:
            return None
        mode, uid, gid = info
        return mode, 0 if uid == os.getuid() else uid, gid

    def __init__(self, root: Path) -> None:
        def fake_rpm(command: list[str]) -> subprocess.CompletedProcess[str]:
            listing = Path(root, "var/lib/fixture-rpm.txt")
            if command[0] == "rpm" and listing.exists():
                return subprocess.CompletedProcess(command, 0, listing.read_text(), "")
            return subprocess.CompletedProcess(command, 1, "", "no rpm")

        super().__init__(root, run=fake_rpm)
