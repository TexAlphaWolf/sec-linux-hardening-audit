# Changelog

## 1.0.0

First release. 60 rules in 8 areas for the Debian/Ubuntu and RHEL families, run on a live system or on a directory tree (`--root`). Text, JSON and HTML reports with a weighted score; `fix` (dry run by default) and `fix --apply` for the 23 rules whose fix is safe to automate, with a backup of every file touched and `undo`; your own rules as TOML. Tools that measure every rule, compare the SSH reader with the real `sshd -T`, and round-trip the fixes on a real system.
