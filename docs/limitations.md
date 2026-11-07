# Limitations

## What the audit sees

- **Configuration, not behaviour.** `PasswordAuthentication no` in `sshd_config` is what is checked, not whether sshd was reloaded afterwards or what `sshd -T` says on a machine with a different OpenSSH version. The SSH reader was compared with `sshd -T` of OpenSSH 9.6 only; defaults of other versions can differ (before OpenSSH 7.0, root login was allowed by default).
- **SSH `Match` blocks are ignored**: what they set applies only to some users or addresses, so it is not the global setting. `Include` files are followed, the first value found wins (as in sshd), a relative `Include` is relative to `/etc/ssh`.
- **Running system versus a directory tree.** On a running system kernel settings are read from `/proc/sys`, mounts from `/proc/self/mounts`. With `--root` there is no kernel: settings come from `/etc/sysctl.conf` and `sysctl.d`, mounts from `/etc/fstab`. A setting not configured there, or a mount that systemd creates at boot (`tmp.mount`), is **untestable**, not a failure.
- **Services** (`HA-LOG-002`) are read with `systemctl` on the running system only.
- **Packages** are read from the dpkg database or with `rpm`. On other distributions (Alpine, Arch, SUSE) the generic rules work and the package rules are untestable. These were not tested.
- **Permissions**: mode bits and the owner uid 0 are checked, not the group. Symbolic links are followed; with `--root`, an absolute link points outside the tree.
- **A user that cannot read a file** (`/etc/shadow`, `sudoers`) gets "untestable" for the rules that need it. Run as root for a complete audit.
- **Not covered at all**: PAM, firewall rules, auditd rules, SELinux/AppArmor, listening services, container and Kubernetes settings, password quality, GRUB, time sync, mail.

## The score

A weighted share of passed rules among the rules that could be judged (high 5, medium 3, low 1). It is this project's own measure, useful for comparing a machine before and after or two machines with each other, not a standard. A score of 100 means these 60 rules pass, not that the machine is secure.

## The fixes

- `login.defs` changes apply to **new accounts only**. Existing ones need `chage`.
- Blocking a module does not unload it. While it is loaded the rule keeps failing; `rmmod` it or reboot.
- Kernel settings written to the running system are not persistent by themselves; the fix also writes `/etc/sysctl.d/99-hardaudit.conf`. In a container the live write is refused and only the file is written, with a warning.
- **`undo` restores whole files as they were before `fix --apply`.** If you edited one of those files by hand after applying, undo overwrites your edit with the old content. Directories are only removed if empty.
- One fix at a time is not supported: `fix --apply` applies every fixable failing rule (or those named with `--only`) in one backup.
- Nothing prevents two `fix --apply` runs at the same time.

## What was verified where

See [evaluation](evaluation.md). In short: the rules and fixes on fixture trees of both families; the real round trip on Ubuntu 24.04 (VM), Debian 12 and Rocky 9.3 (containers); the SSH comparison on Ubuntu 24.04 with OpenSSH 9.6. Debian 13, Alma 9 and Ubuntu 24.04 containers and the exported images of three distributions run in CI on every push.
