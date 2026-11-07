# Security policy

hardaudit reads configuration files and, with `fix --apply`, **changes** them as root. Two kinds of problem matter:

- **A fix that breaks or weakens a system**, or an `undo` that does not restore what it recorded.
- **Input that makes the audit misjudge or crash**: a crafted config file or package database that makes a failing rule pass, or an exception instead of a result.

Please report either through GitHub's **private vulnerability reporting** (Security tab, "Report a vulnerability") rather than a public issue. You will get an answer within a few days.

A rule that is missing, or one you disagree with, is a feature request: [docs/limitations.md](docs/limitations.md) lists what is known.

Supported: the latest release.

What the code does about its own risk: `fix` is a dry run unless `--apply` is given; only rules with a declared, low-risk fix are ever changed (a test fails if an SSH, package, mount or account rule gets one); every file is backed up before it changes and the backup manifest is saved after each step; the rule files are data (TOML), never code, and a malformed one is refused with its file and rule named.
