"""Measure hardaudit and print the numbers quoted in docs/evaluation.md.

    python tools/evaluate.py

Uses the fixture trees from tests/ (Debian and RHEL family), so it needs no root and no
containers. The system round trip and the sshd comparison have their own scripts.
"""

from __future__ import annotations

import collections
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from tests.fixtures import FixtureHost, build_hardened, build_insecure
from tests.mutations import mutate

from hardaudit import fixes, rules
from hardaudit.engine import audit
from hardaudit.host import Host


def main() -> int:
    ruleset = rules.load()
    print(f"rules: {len(ruleset)}")
    print("  by section:", dict(collections.Counter(r.section for r in ruleset)))
    print("  by severity:", dict(collections.Counter(r.severity for r in ruleset)))
    print(f"  with an automatic fix: {sum(1 for r in ruleset if r.apply)}")
    print(f"  Debian-only: {sum(1 for r in ruleset if r.families == ('debian',))}, "
          f"RHEL-only: {sum(1 for r in ruleset if r.families == ('rhel',))}")  # fmt: skip

    failures = 0
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        for family in ("debian", "rhel"):
            good = audit(FixtureHost(build_hardened(base / f"g-{family}", family)), ruleset)
            bad = audit(FixtureHost(build_insecure(base / f"b-{family}", family)), ruleset)
            print(f"{family}: hardened score {good.score}, neglected score {bad.score}, "
                  f"neglected fails {bad.count('fail')}")  # fmt: skip

            broken = fixed = untestable = 0
            for n, rule in enumerate(ruleset):
                root = base / f"m-{family}-{n}"
                build_hardened(root, family)
                if not mutate(root, rule, family):
                    untestable += 1
                    continue
                status = {r.rule.id: r.status for r in audit(FixtureHost(root), ruleset).results}[
                    rule.id
                ]
                broken += status == "fail"
                failures += status != "fail"
                if rule.apply:
                    host = FixtureHost(root)
                    plan = fixes.plan(host, audit(host, ruleset), ruleset, only=[rule.id])
                    if plan:
                        fixes.apply(host, plan)
                    again = {r.rule.id: r.status for r in audit(FixtureHost(root), ruleset).results}
                    fixed += again[rule.id] == "pass"
                    failures += again[rule.id] != "pass"
            applicable = sum(1 for r in ruleset if r.applies_to(family))
            print(f"  {family}: {broken}/{applicable - untestable} rules fail when broken on purpose, "
                  f"{untestable} cannot be tested offline (service state), "
                  f"{fixed}/{sum(1 for r in ruleset if r.apply)} fixes make their rule pass")  # fmt: skip

        host = FixtureHost(base / "g-debian")
        started = time.perf_counter()
        for _ in range(200):
            audit(FixtureHost(base / "g-debian"), ruleset)
        per_run = (time.perf_counter() - started) / 200 * 1000
        print(f"speed: {per_run:.1f} ms per full audit of a fixture tree ({len(ruleset)} rules)")
        del host

    live = Host("/")
    if live.sysctl("kernel.randomize_va_space") is not None:
        missing = [
            r.check["key"]
            for r in ruleset
            if r.check["type"] == "sysctl" and live.sysctl(r.check["key"]) is None
        ]
        print(f"this kernel: {sum(1 for r in ruleset if r.check['type'] == 'sysctl') - len(missing)} of "
              f"{sum(1 for r in ruleset if r.check['type'] == 'sysctl')} sysctl keys exist"
              + (f" (missing here: {', '.join(missing)})" if missing else ""))  # fmt: skip
        started = time.perf_counter()
        report = audit(live, ruleset)
        print(f"this machine ({report.distro}): {report.score} in {(time.perf_counter() - started) * 1000:.0f} ms, "
              f"{report.count('error')} errors")  # fmt: skip
    print("OK" if failures == 0 else f"{failures} UNEXPECTED RESULTS")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
