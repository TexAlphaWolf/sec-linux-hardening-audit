"""Compare how hardaudit reads sshd_config with what the real sshd says it will use.

For each random configuration, ``sshd -T`` (the OpenSSH server in test mode, which prints the
effective settings) is the reference. hardaudit's value for every SSH key it checks must be
the same. Needs root and openssh-server; it temporarily replaces /etc/ssh/sshd_config and
puts the original back afterwards.

    python tools/crosscheck_sshd.py [COUNT] [SEED]
"""

from __future__ import annotations

import json
import random
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from hardaudit import rules
from hardaudit.checks import config_value
from hardaudit.host import Host

SSHD = Path("/etc/ssh/sshd_config")
DROPIN = Path("/etc/ssh/sshd_config.d")

DOMAINS = {
    "PermitRootLogin": ["yes", "no", "prohibit-password", "forced-commands-only"],
    "PasswordAuthentication": ["yes", "no"],
    "PermitEmptyPasswords": ["yes", "no"],
    "MaxAuthTries": ["1", "3", "4", "6", "10"],
    "LoginGraceTime": ["30", "60", "120", "0"],
    "X11Forwarding": ["yes", "no"],
    "ClientAliveInterval": ["0", "60", "300", "900"],
    "IgnoreRhosts": ["yes", "no"],
    "HostbasedAuthentication": ["yes", "no"],
    "PermitUserEnvironment": ["yes", "no"],
    "LogLevel": ["QUIET", "INFO", "VERBOSE", "DEBUG"],
}


ALIASES = {"without-password": "prohibit-password", "silent": "quiet"}


def spell(key: str, value: str, rng: random.Random) -> str:
    key = rng.choice([key, key.lower(), key.upper()])
    return f"{key}{rng.choice([' ', '  ', '=', ' = '])}{value}"


def scenario(rng: random.Random) -> tuple[str, dict[str, str]]:
    """(main file text, {drop-in file name: text})"""
    main: list[str] = []
    dropins: dict[str, str] = {}
    if rng.random() < 0.6:
        main.append("Include /etc/ssh/sshd_config.d/*.conf")
    pieces = []
    for key, values in DOMAINS.items():
        for _ in range(rng.choice([0, 0, 1, 1, 2])):  # sometimes repeated: first one wins
            pieces.append(spell(key, rng.choice(values), rng))
    rng.shuffle(pieces)
    in_main = pieces[: len(pieces) // 2]
    in_drop = pieces[len(pieces) // 2 :]
    main += in_main
    if rng.random() < 0.4:
        allowed = (
            "PermitRootLogin",
            "PasswordAuthentication",
            "X11Forwarding",
            "MaxAuthTries",
            "PermitEmptyPasswords",
        )
        inside = [spell(k, rng.choice(DOMAINS[k]), rng) for k in rng.sample(allowed, 3)]
        main += ["", "# a comment", "Match User backup", *(f"    {line}" for line in inside)]
    text = "\n".join(main) + "\n"
    if in_drop:
        dropins["10-test.conf"] = "\n".join(in_drop[: len(in_drop) // 2]) + "\n"
        dropins["50-test.conf"] = "\n".join(in_drop[len(in_drop) // 2 :]) + "\n"
    return text, dropins


def effective(output: str) -> dict[str, str]:
    values = {}
    for line in output.splitlines():
        key, _, value = line.partition(" ")
        values[key] = value.strip()
    return values


def main() -> int:
    count = int(sys.argv[1]) if len(sys.argv) > 1 else 300
    seed = int(sys.argv[2]) if len(sys.argv) > 2 else 1
    rng = random.Random(seed)
    if shutil.which("sshd") is None and not Path("/usr/sbin/sshd").exists():
        print("sshd is not installed", file=sys.stderr)
        return 2
    sshd = shutil.which("sshd") or "/usr/sbin/sshd"
    subprocess.run(["ssh-keygen", "-A"], capture_output=True, check=False)
    Path("/run/sshd").mkdir(mode=0o755, exist_ok=True)  # sshd -T refuses to run without it
    ssh_rules = [r for r in rules.load() if r.section == "SSH"]
    original = SSHD.read_text() if SSHD.exists() else None
    existing = sorted(DROPIN.glob("*.conf")) if DROPIN.is_dir() else []
    saved = {p.name: p.read_text() for p in existing}
    created_dir = not DROPIN.exists()
    DROPIN.mkdir(exist_ok=True)
    for p in existing:
        p.unlink()
    compared = mismatches = skipped = 0
    last_error = ""
    examples: list[dict[str, str]] = []
    try:
        for _ in range(count):
            text, dropins = scenario(rng)
            SSHD.write_text(text)
            for p in DROPIN.glob("*.conf"):
                p.unlink()
            for name, body in dropins.items():
                (DROPIN / name).write_text(body)
            done = subprocess.run([sshd, "-T"], capture_output=True, text=True, check=False)
            if done.returncode != 0:
                skipped += 1  # sshd itself refused this random file; nothing to compare
                last_error = done.stderr.strip()
                continue
            truth = effective(done.stdout)
            host = Host("/")
            for rule in ssh_rules:
                spec = rule.check
                value, found = config_value(host, spec)
                ours = (value if found else spec["default"]).lower()
                theirs = truth.get(spec["key"].lower(), "?").lower()
                # sshd -T prints two values under their other names; same meaning.
                ours, theirs = (ALIASES.get(v, v) for v in (ours, theirs))
                compared += 1
                if ours != theirs:
                    mismatches += 1
                    if len(examples) < 5:
                        examples.append(
                            {
                                "key": spec["key"],
                                "hardaudit": ours,
                                "sshd": theirs,
                                "config": text,
                                "dropins": json.dumps(dropins),
                            }
                        )
    finally:
        for p in DROPIN.glob("*.conf"):
            p.unlink()
        for name, body in saved.items():
            (DROPIN / name).write_text(body)
        if created_dir:
            DROPIN.rmdir()
        if original is None:
            SSHD.unlink(missing_ok=True)
        else:
            SSHD.write_text(original)
    if skipped * 10 > count:
        print(
            f"sshd refused {skipped} of {count} configurations, so this measures nothing: {last_error}",
            file=sys.stderr,
        )
        return 2
    print(
        json.dumps(
            {
                "scenarios": count,
                "skipped_by_sshd": skipped,
                "values_compared": compared,
                "mismatches": mismatches,
                "examples": examples,
            },
            indent=1,
        )
    )
    return 0 if mismatches == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
