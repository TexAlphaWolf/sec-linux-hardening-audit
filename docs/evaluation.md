# Evaluation

Everything here is produced by a script in the repository and re-run by CI. Where a number was
measured only once, on one machine, it says so.

| Script | What it measures | Needs |
|---|---|---|
| `tools/evaluate.py` | each rule against a deliberately broken tree, each fix, both families, speed | nothing |
| `tools/crosscheck_sshd.py` | hardaudit's reading of `sshd_config` against the real `sshd -T` | root, openssh-server |
| `tools/system_check.py` | audit, fix, undo on a real system and a byte comparison of `/etc` | root, a machine you can change |

## 1. Every rule, broken on purpose

`tests/fixtures.py` writes a *hardened* tree and a *neglected* tree for each family (Debian-style and
RHEL-style: different os-release, package database, and the 0640 versus 0000 mode of `/etc/shadow`).
The hardened tree is written by hand from what a hardened system looks like; it is **not** derived
from the rules, so a wrong expected value in a rule file makes tests fail.
`tests/mutations.py` then breaks one rule at a time, choosing the break from the rule's check type
(wrong sysctl value, mode 0777, a bad config line, a mount without options, an extra package, a
removed modprobe line, an empty password, a missing line, a forbidden file).

| Result | Debian-style | RHEL-style |
|---|---|---|
| hardened tree: rules failing | 0 | 0 |
| neglected tree: rules failing | 51 (listed by hand in the test) | 51 |
| hardened / neglected score | 100.0 / 15.3 | 100.0 / 15.3 |
| rules that fail when broken on purpose | 59 of 59 | 59 of 59 |
| fixes that make their own rule pass | 23 of 23 | 23 of 23 |

The 60th rule (is the audit daemon enabled) reads systemd and cannot be tested on a directory tree.

These tests are not vacuous: changing one expected value in `kernel.toml`, or making `chmod` keep the
bits it should remove, turns the matching tests red (checked by hand while writing them).

**What this does not show.** The trees are written by the same author as the rules. They prove the code
follows its own rubric, not that the rubric matches every real system. That is what sections 2 and 3 are for.

## 2. SSH settings against the real sshd

`sshd -T` prints the settings the server will really use. `tools/crosscheck_sshd.py` writes random
configurations (keys repeated, spelled in different cases, `=` or spaces, split between the main
file and `Include`d files, with a `Match` block) and compares, for the 11 keys the rules use, the value
hardaudit computes with the value sshd reports.

| Run | Result |
|---|---|
| 4 seeds x 500 configurations x 11 keys, OpenSSH 9.6p1 (Ubuntu 24.04) | 22,000 values compared, 0 differences |
| the same tool with "first value wins" deliberately broken | 197 differences in 200 configurations |
| the same tool with `Match` handling deliberately broken | 82 differences in 200 configurations |

The last two rows are there to show the comparison can fail. CI repeats seed 1.

Two spellings differ and are treated as the same thing, because they are: sshd prints `without-password`
for `prohibit-password` and `silent` for `QUIET`.

## 3. A real system, round trip

`tools/system_check.py` as root on a real system: audit, plan the fixes, apply them, audit again, undo,
and compare every file and directory under `/etc` (hash and mode).

| | Ubuntu 24.04 (VM) | Debian 12 (container) | Rocky 9.3 (container) |
|---|---|---|---|
| Rules judged (pass + fail) | 44 of 60 | 44 of 60 | 43 of 60 |
| Passed / failed | 25 / 19 | 26 / 18 | 25 / 18 |
| Not applicable / untestable | 16 / 0 | 15 / 1 | 16 / 1 |
| Errors | 0 | 0 | 0 |
| Changes applied | 11 | 10 | 8 |
| Score | 67.5 to 82.5 | 71.9 to 79.8 | 73.0 to 78.4 |
| Live kernel settings refused (read-only /proc/sys) | 0 | 3 | 3 |
| Files and directories under /etc compared after undo | 597 | 157 | 238 |
| Differences after undo | **0** | **0** | **0** |
| Time of the audit | 12 ms | 4 ms | 39 ms |

The Ubuntu run is a throwaway VM; the other two ran on a Windows PC with Docker Desktop. A container shares
the host kernel and mounts `/proc/sys` read-only, so three kernel settings (`dmesg_restrict`,
`send_redirects`, `log_martians`) could not be set live. The fix wrote them to
`/etc/sysctl.d/99-hardaudit.conf`, printed a warning for each, and the three rules still fail until the
next `sysctl --system` or reboot; they are listed in `fixable_still_failing`. That is the intended
behaviour. In the containers the untestable rule is the audit daemon's boot state, because there is no systemd.

Each of these is one run on one image on one day. Debian 13, Alma 9 and the other images are CI jobs
(Actions tab: "real system"), which had not run when this page was written.

## 4. Things the measurements found

These are mistakes found by running things, in the order they were found. Most were in the checks, some
in my expectations.

- **An exported image has no `/proc`.** My first design read kernel settings from `/proc/sys`; on a directory tree all 17 sysctl rules would have been "not applicable". Offline, settings now come from the sysctl files and what cannot be known is "untestable".
- **`undo` left a directory behind.** The fixture tests passed. The real-system round trip showed `/etc/modprobe.d` still existing after undo, because the machine had not had one and the fix created it. Created directories are now recorded and removed if empty, with a test that they are kept if someone added a file.
- **Applying in a container.** `/proc/sys` is read-only there, so the live write fails. That used to abort the run midway; it is now a warning and the persistent file is still written.
- **A missing unit counted twice.** "audit daemon enabled" failed when auditd was not installed, so one problem cost two rules. It is now "not applicable".
- **The SSH comparison first measured nothing.** `sshd -T` refused to run (no `/run/sshd`), every scenario was skipped, and the script printed "0 differences" over 0 comparisons. It now exits with an error if sshd refuses more than a tenth of the configurations.
- **My idea that sshd accepts `true`/`false` was wrong.** sshd rejects them; the generator and a normalisation I had added were removed.
- **My generator wrote directives sshd does not allow in a `Match` block**, so sshd rejected the file. Fixed in the tool, not in hardaudit.
- **An audit as an ordinary user crashed (found by CI, not by me).** Everything I ran myself ran as root. On GitHub's runner, as a normal user, `Path.exists()` raised `PermissionError` for `/root/.rhosts` and the engine only caught other exceptions, so the whole audit ended with `error: Permission denied`. A check must never raise for something it cannot read: it is now "untestable" (a path rule still reports what it *can* see: a file that is present is a failure even if another path could not be checked). Regression tests cover a simulated denial and a real audit as a non-root user. Reproduced locally by running the suite as a throwaway user.
- **My test fixtures only worked as root.** They created `/etc/sudoers` read-only and RHEL's `/etc/shadow` as mode 000, then rewrote or re-read them; as a normal user that raised `PermissionError`. The same bug made `tools/evaluate.py` fail in CI. Fixed in the fixture helpers.
- **Debian-family "real system" jobs were red for a reason in my CI script, not in the tool.** The step parsed the whole output as JSON, but `apt-get update` prints its progress first (`dnf` is quiet, so Rocky and Alma were green). The script now silences apt and reads only the last line.
- Expectations I got wrong in tests, not bugs in the tool: two mounts in the neglected tree that do fail, a test that built both trees in one directory, and rule titles starting with a lower-case word.

## 5. What is not measured

- Real systems other than the three in section 3 (Ubuntu 24.04 VM, Debian 12 and Rocky 9.3 containers), until the CI jobs have run. A real machine with systemd running, where the audit daemon and mounts can be read, is covered only by the Ubuntu VM.
- Distributions outside Debian/Ubuntu and the RHEL family.
- Any OpenSSH version other than 9.6.
- Whether the rules match what an auditor expects. They follow common topics but are not checked against a benchmark.
