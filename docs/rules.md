# Rules

60 rules in 8 sections. The tables below are generated from the rule files by
`hardaudit rules --markdown` and a test fails if they drift apart.

Severity sets the weight in the score (high 5, medium 3, low 1). The rule ids and the wording are
this project's own; the topics follow what common hardening guides (CIS Benchmarks, distribution
hardening guides) cover, and nothing here is copied from them or approved by them. This is not a
CIS-certified tool.

**Automatic fix** means `hardaudit fix --apply` can do it. Every such fix only removes permission
bits, sets one kernel value to a stricter one, edits one named line, or blocks one module. Anything
that could lock you out of a machine (all SSH settings), break a service (forwarding, firewall,
mounts) or needs a decision (packages, accounts) is a suggested command only.

<!-- rules:start -->
### Accounts

| Id | Severity | Rule | Automatic fix |
|---|---|---|---|
| `HA-ACC-001` | high | No account has an empty password | no (suggested command only) |
| `HA-ACC-002` | high | Only root has user id 0 | no (suggested command only) |
| `HA-ACC-003` | medium | Every user id is used by one account | no (suggested command only) |
| `HA-ACC-004` | medium | System accounts cannot log in | no (suggested command only) |
| `HA-ACC-005` | medium | New passwords expire within a year | edits one line |
| `HA-ACC-006` | low | Passwords cannot be changed again immediately | edits one line |
| `HA-ACC-007` | low | Users are warned at least a week before a password expires | edits one line |
| `HA-ACC-008` | low | New files are not readable by other users by default | edits one line |

### Filesystem

| Id | Severity | Rule | Automatic fix |
|---|---|---|---|
| `HA-FS-001` | low | The cramfs file system cannot be loaded | blocks the module |
| `HA-FS-002` | low | The udf file system cannot be loaded | no (suggested command only) |
| `HA-FS-003` | low | USB mass storage cannot be loaded | no (suggested command only) |
| `HA-FS-004` | medium | /tmp is a separate mount with nodev, nosuid and noexec | no (suggested command only) |
| `HA-FS-005` | medium | /dev/shm is mounted with nodev, nosuid and noexec | no (suggested command only) |

### Kernel

| Id | Severity | Rule | Automatic fix |
|---|---|---|---|
| `HA-KRN-001` | high | Address space layout randomisation is fully enabled | kernel setting |
| `HA-KRN-002` | medium | Processes that change privilege do not dump core | kernel setting |
| `HA-KRN-003` | low | Ordinary users cannot read the kernel log | kernel setting |
| `HA-KRN-004` | low | Kernel pointers are hidden from ordinary users | no (suggested command only) |
| `HA-KRN-005` | low | Process tracing (ptrace) is limited to a process's own children | no (suggested command only) |
| `HA-KRN-006` | medium | Hard links cannot be made to files the user does not own | kernel setting |
| `HA-KRN-007` | medium | Symbolic links in sticky directories are not followed blindly | kernel setting |
| `HA-KRN-008` | medium | Unprivileged users cannot load eBPF programs | no (suggested command only) |

### Logging

| Id | Severity | Rule | Automatic fix |
|---|---|---|---|
| `HA-LOG-001` | medium | The audit daemon is installed | no (suggested command only) |
| `HA-LOG-002` | medium | The audit daemon is enabled at boot | no (suggested command only) |
| `HA-LOG-003` | low | Commands run through sudo get a pseudo-terminal | no (suggested command only) |
| `HA-LOG-004` | low | Core dumps are disabled for users | no (suggested command only) |
| `HA-LOG-005` | low | The login banner does not reveal the system | no (suggested command only) |

### Network

| Id | Severity | Rule | Automatic fix |
|---|---|---|---|
| `HA-NET-001` | medium | The host does not forward IPv4 packets | no (suggested command only) |
| `HA-NET-002` | medium | ICMP redirects are not accepted | kernel setting |
| `HA-NET-003` | low | ICMP redirects are not sent | kernel setting |
| `HA-NET-004` | medium | Source-routed packets are refused | kernel setting |
| `HA-NET-005` | low | Packets with impossible source addresses are logged | kernel setting |
| `HA-NET-006` | medium | Reverse-path filtering is on | no (suggested command only) |
| `HA-NET-007` | medium | SYN cookies are enabled | kernel setting |
| `HA-NET-008` | low | Broadcast ICMP echo requests are ignored | kernel setting |
| `HA-NET-009` | low | Bogus ICMP error responses are ignored | kernel setting |

### Permissions

| Id | Severity | Rule | Automatic fix |
|---|---|---|---|
| `HA-PRM-001` | high | /etc/passwd and /etc/group are writable by root only | removes permissions |
| `HA-PRM-002` | high | /etc/shadow and /etc/gshadow are not readable by others | removes permissions |
| `HA-PRM-003` | medium | The SSH server configuration is private to root | removes permissions |
| `HA-PRM-004` | high | SSH private host keys are private to root | removes permissions |
| `HA-PRM-005` | medium | The system crontab is private to root | removes permissions |
| `HA-PRM-006` | medium | The cron directories are private to root | removes permissions |
| `HA-PRM-007` | high | No remote-login trust files exist | no (suggested command only) |

### Software

| Id | Severity | Rule | Automatic fix |
|---|---|---|---|
| `HA-PKG-001` | high | No telnet client or server is installed | no (suggested command only) |
| `HA-PKG-002` | high | No rsh or rlogin software is installed | no (suggested command only) |
| `HA-PKG-003` | medium | No NIS software is installed | no (suggested command only) |
| `HA-PKG-004` | medium | No TFTP server is installed | no (suggested command only) |
| `HA-PKG-005` | low | Avahi (mDNS) is not installed | no (suggested command only) |
| `HA-PKG-006` | medium | A host firewall is installed | no (suggested command only) |
| `HA-PKG-007` | low | A file-integrity tool (AIDE) is installed | no (suggested command only) |

### SSH

| Id | Severity | Rule | Automatic fix |
|---|---|---|---|
| `HA-SSH-001` | high | Root cannot log in over SSH with a password | no (suggested command only) |
| `HA-SSH-002` | high | SSH password logins are disabled | no (suggested command only) |
| `HA-SSH-003` | high | Empty passwords are refused over SSH | no (suggested command only) |
| `HA-SSH-004` | medium | Authentication attempts per connection are limited | no (suggested command only) |
| `HA-SSH-005` | low | Unauthenticated connections time out quickly | no (suggested command only) |
| `HA-SSH-006` | low | X11 forwarding is off | no (suggested command only) |
| `HA-SSH-007` | low | Idle SSH sessions are closed | no (suggested command only) |
| `HA-SSH-008` | medium | SSH ignores .rhosts and .shosts files | no (suggested command only) |
| `HA-SSH-009` | medium | Host-based authentication is off | no (suggested command only) |
| `HA-SSH-010` | medium | Users cannot set environment variables through SSH | no (suggested command only) |
| `HA-SSH-011` | low | SSH logs at INFO level or more | no (suggested command only) |

<!-- rules:end -->

## Writing your own rules

Put `*.toml` files in a directory and pass `--rules-dir`. One table per rule:

```toml
[[rule]]
id = "HA-MY-001"
title = "No world-writable /srv/backup"
section = "Mine"
severity = "medium"
why = "Anyone could replace a backup."
fix = "chmod o-w /srv/backup"
check = { type = "file_mode", paths = ["/srv/backup"], max_mode = "0750", owner_uid = 0 }
```

Check types: `sysctl`, `file_mode`, `config`, `mount`, `package`, `module`, `accounts`, `service`,
`file_regex`, `path_absent`. See [examples/custom-rules.toml](../examples/custom-rules.toml) and
`src/hardaudit/rules/` for one of each. A malformed rule file is refused with the file and the
rule named; it never produces a half-checked audit.
