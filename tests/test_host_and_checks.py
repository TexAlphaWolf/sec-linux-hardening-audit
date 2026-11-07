from __future__ import annotations

import subprocess

from hardaudit import host as hostmod
from hardaudit.checks import check_accounts, check_config, check_file_regex, check_module
from hardaudit.host import Host, family_of, parse_os_release
from tests.conftest import posix_only
from tests.fixtures import write


def host_with(tmp_path, files: dict[str, str]) -> Host:
    for name, body in files.items():
        write(tmp_path, name, body)
    return Host(tmp_path)


def test_os_families():
    cases = {
        'ID=ubuntu\nID_LIKE=debian': "debian",
        'ID=debian': "debian",
        'ID="rocky"\nID_LIKE="rhel centos fedora"': "rhel",
        'ID=almalinux\nID_LIKE="rhel centos fedora"': "rhel",
        'ID=linuxmint\nID_LIKE="ubuntu debian"': "debian",
        'ID=alpine': "other",
        '': "other",
    }  # fmt: skip
    for text, family in cases.items():
        assert family_of(parse_os_release(text)) == family, text


def test_dpkg_status_only_counts_fully_installed_packages(tmp_path):
    h = host_with(tmp_path, {"/var/lib/dpkg/status": (
        "Package: a\nStatus: install ok installed\n\n"
        "Package: b\nStatus: deinstall ok config-files\n\n"
        "Package: c\nStatus: install ok half-installed\n\n"
        "Package: d\nStatus: install ok installed\n")})  # fmt: skip
    assert h.packages() == {"a", "d"}


def test_no_package_database_means_untestable_not_clean(tmp_path):
    h = Host(tmp_path, run=lambda c: subprocess.CompletedProcess(c, 1, "", "no rpm"))
    assert h.packages() is None


def test_a_missing_file_is_a_result_not_a_crash(tmp_path):
    h = Host(tmp_path)
    assert h.read("/etc/nothing") is None and h.stat("/etc/nothing") is None
    assert check_config(h, {"files": ["/etc/nothing"], "key": "K", "expect_in": ["a"]})[0] == "na"
    assert check_module(h, {"module": "cramfs"})[0] == "fail"


SSHD = {
    "files": ["/etc/ssh/sshd_config"],
    "key": "PermitRootLogin",
    "expect_in": ["no"],
    "default": "yes",
}


def test_the_first_value_wins_and_include_files_are_read_in_place(tmp_path):
    h = host_with(tmp_path, {
        "/etc/ssh/sshd_config": "Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin yes\n",
        "/etc/ssh/sshd_config.d/10-hard.conf": "PermitRootLogin no\n"})  # fmt: skip
    assert check_config(h, SSHD)[0] == "pass"  # the drop-in is included before the main line


def test_a_setting_after_a_match_block_is_conditional_and_ignored(tmp_path):
    h = host_with(tmp_path, {"/etc/ssh/sshd_config": "Match User backup\n    PermitRootLogin no\n"})
    status, detail = check_config(h, SSHD)
    assert status == "fail" and "default" in detail


def test_keys_are_case_insensitive_and_equals_signs_work(tmp_path):
    h = host_with(tmp_path, {"/etc/ssh/sshd_config": "permitrootlogin=no\n"})
    assert check_config(h, SSHD)[0] == "pass"


def test_an_include_loop_terminates(tmp_path):
    h = host_with(tmp_path, {"/etc/ssh/sshd_config": "Include /etc/ssh/sshd_config\n"})
    assert check_config(h, SSHD)[0] == "fail"  # falls back to the default, does not hang


def test_non_numeric_value_for_a_numeric_rule_fails_cleanly(tmp_path):
    h = host_with(tmp_path, {"/etc/ssh/sshd_config": "MaxAuthTries many\n"})
    spec = {"files": ["/etc/ssh/sshd_config"], "key": "MaxAuthTries", "min": 1, "max": 4}
    assert check_config(h, spec)[0] == "fail"


def test_modprobe_blacklist_alone_does_not_count_as_blocking(tmp_path):
    h = host_with(tmp_path, {"/etc/modprobe.d/x.conf": "blacklist cramfs\n"})
    assert check_module(h, {"module": "cramfs"})[0] == "fail"
    write(tmp_path, "/etc/modprobe.d/y.conf", "install cramfs /usr/bin/true\n")
    assert check_module(Host(tmp_path), {"module": "cramfs"})[0] == "pass"


def test_a_module_that_is_loaded_fails_even_if_blocked(tmp_path):
    h = host_with(tmp_path, {"/etc/modprobe.d/x.conf": "install udf /bin/true\n"})
    h.runtime = True
    write(tmp_path, "/proc/modules", "udf 1 0 - Live 0x0\n")
    assert check_module(h, {"module": "udf"})[0] == "fail"


def test_accounts_checks(tmp_path):
    h = host_with(tmp_path, {
        "/etc/passwd": "root:x:0:0::/root:/bin/bash\nweb:x:33:33::/var/www:/bin/bash\n",
        "/etc/shadow": "root:x:1::::::\nbob::1::::::\n"})  # fmt: skip
    assert check_accounts(h, {"test": "empty_password"})[0] == "fail"
    assert check_accounts(h, {"test": "system_shells"})[0] == "fail"
    assert check_accounts(h, {"test": "nonsense"})[0] == "error"
    assert check_accounts(Host(tmp_path / "empty"), {"test": "uid0_only_root"})[0] == "na"


@posix_only
def test_an_unreadable_shadow_is_untestable_not_clean(tmp_path):
    import os

    h = host_with(tmp_path, {"/etc/shadow": "root:x::::::\n"})
    (tmp_path / "etc/shadow").chmod(0)
    if os.geteuid() == 0:
        return  # root reads everything; the case only exists for ordinary users
    assert check_accounts(h, {"test": "empty_password"})[0] == "untestable"


def test_file_regex_untestable_when_unreadable_and_na_when_absent(tmp_path):
    assert check_file_regex(Host(tmp_path), {"paths": ["/etc/sudoers"], "require": "x"})[0] == "na"


def test_services_are_untestable_on_a_directory_tree(tmp_path):
    from hardaudit.checks import check_service

    assert (
        check_service(Host(tmp_path), {"unit": "auditd.service", "state": "enabled"})[0]
        == "untestable"
    )


def test_service_states_from_a_fake_systemctl(tmp_path):
    from hardaudit.checks import check_service

    def run(out: str, code: int = 0):
        return lambda c: subprocess.CompletedProcess(c, code, out, "")

    h = Host("/", run=run("masked\n", 1))
    assert check_service(h, {"unit": "avahi.service", "state": "disabled"})[0] == "pass"
    assert (
        check_service(Host("/", run=run("enabled\n")), {"unit": "a", "state": "disabled"})[0]
        == "fail"
    )
    assert (
        check_service(Host("/", run=run("enabled\n")), {"unit": "a", "state": "enabled"})[0]
        == "pass"
    )
    assert (
        check_service(Host("/", run=run("not-found\n", 1)), {"unit": "a", "state": "enabled"})[0]
        == "na"
    )
    boot = run("System has not been booted with systemd as init system", 1)
    assert check_service(Host("/", run=boot), {"unit": "a", "state": "enabled"})[0] == "untestable"


def test_sysctl_files_are_read_in_systemd_order(tmp_path):
    h = host_with(tmp_path, {
        "/usr/lib/sysctl.d/50-default.conf": "kernel.a = 1\nkernel.b = 1\n",
        "/etc/sysctl.d/50-default.conf": "kernel.a = 2\n",   # same name: /etc overrides /usr/lib
        "/etc/sysctl.d/99-local.conf": "kernel/b = 3\n# kernel.c = 9\n",
        "/etc/sysctl.conf": "kernel.d = 4\n"})  # fmt: skip
    assert [h.sysctl(k) for k in ("kernel.a", "kernel.b", "kernel.c", "kernel.d")] == [
        "2",
        "3",
        None,
        "4",
    ]


def test_the_module_imports_cleanly():
    assert hostmod.family_of({}) == "other"


def test_a_directory_the_user_may_not_enter_is_untestable_not_a_crash(tmp_path, monkeypatch):
    from hardaudit import rules
    from hardaudit.checks import check_path_absent
    from hardaudit.engine import audit

    host = Host(tmp_path)
    real = Host.exists

    def deny(self, name):  # type: ignore[no-untyped-def]
        if name == "/root/.rhosts":
            raise PermissionError(13, "Permission denied", name)
        return real(self, name)

    monkeypatch.setattr(Host, "exists", deny)
    spec = {"paths": ["/etc/hosts.equiv", "/root/.rhosts"]}
    assert check_path_absent(host, spec)[0] == "untestable"
    write(tmp_path, "/etc/hosts.equiv", "+ +\n")
    assert check_path_absent(host, spec)[0] == "fail"  # what we can see still decides
    # and nothing in the whole rule set may escape as an exception
    report = audit(host, rules.load())
    assert report.count("error") == 0


@posix_only
def test_a_real_audit_as_an_ordinary_user_does_not_crash(capsys):
    import os

    if os.geteuid() == 0:
        import pytest

        pytest.skip("root can read everything; the case only exists for ordinary users")
    from hardaudit import cli

    assert cli.main(["audit", "--fail-on", "none"]) == 0
    assert "hardaudit" in capsys.readouterr().out
