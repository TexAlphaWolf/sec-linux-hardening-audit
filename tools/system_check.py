"""Round trip on a REAL running system (run as root; meant for throwaway machines and
containers): audit, fix --apply, audit again, undo, and prove that /etc is byte-identical
to how it started. Prints one JSON line with the numbers. Exit 1 on any mismatch.

    python tools/system_check.py [--keep-going]
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from hardaudit import fixes, rules
from hardaudit.engine import audit
from hardaudit.host import Host

# Docker bind-mounts these and rewrites them itself; they say nothing about hardaudit.
VOLATILE = {"/etc/hosts", "/etc/hostname", "/etc/resolv.conf", "/etc/mtab"}


def snapshot() -> dict[str, tuple[str, int]]:
    state: dict[str, tuple[str, int]] = {}
    for base, dirs, files in os.walk("/etc"):
        for name in [*dirs, *files]:
            path = os.path.join(base, name)
            if path in VOLATILE or os.path.islink(path):
                continue
            try:
                mode = os.stat(path).st_mode & 0o7777
                digest = (
                    "dir"
                    if os.path.isdir(path)
                    else hashlib.sha256(Path(path).read_bytes()).hexdigest()
                )
            except OSError:
                continue
            state[path] = (digest, mode)
    return state


def main() -> int:
    if os.geteuid() != 0:
        print("run as root", file=sys.stderr)
        return 2
    host = Host("/")
    ruleset = rules.load()
    started = time.perf_counter()
    first = audit(host, ruleset)
    audit_seconds = time.perf_counter() - started
    errors = [r.rule.id for r in first.results if r.status == "error"]

    before = snapshot()
    changes = fixes.plan(host, first, ruleset)
    notes: list[str] = []
    backup = fixes.apply(host, changes, notes) if changes else None
    second = audit(Host("/"), ruleset)
    if backup:
        fixes.undo(Host("/"), backup)
    after = snapshot()
    # The backup directory itself lives outside /etc; everything else must match.
    differences = sorted(k for k in before.keys() | after.keys() if before.get(k) != after.get(k))
    fixable_still_failing = [
        r.rule.id for r in second.results if r.rule.apply and r.status == "fail"
    ]
    result = {
        "distro": first.distro,
        "family": first.family,
        "rules": len(first.results),
        "audit_ms": round(audit_seconds * 1000),
        "counts": {s: first.count(s) for s in ("pass", "fail", "na", "untestable", "error")},
        "score_before": first.score,
        "score_after_fix": second.score,
        "changes": len(changes),
        "warnings": notes,
        "fixable_still_failing": fixable_still_failing,
        "etc_files_compared": len(before),
        "etc_differences_after_undo": differences,
        "errors": errors,
    }
    print(json.dumps(result))
    ok = not errors and not differences and (second.score or 0) >= (first.score or 0)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
