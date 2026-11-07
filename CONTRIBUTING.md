# Contributing

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
ruff check . && ruff format --check . && mypy && pytest --cov
python tools/evaluate.py
```

- **Standard library only for the package.** Rules are TOML read with `tomllib`.
- **A new rule** is a `[[rule]]` in `src/hardaudit/rules/*.toml`. Use your own words for the title, reason and fix; do not copy text from a benchmark. Then:
  1. add it to the hand-written hardened tree in `tests/fixtures.py` so it passes there, and to the neglected tree if it should fail there (and to `INSECURE_FAILS` in `tests/test_baselines.py`);
  2. `tests/test_each_rule.py` breaks and fixes it automatically from its check type; if the type is new, teach `tests/mutations.py` how to break it;
  3. regenerate the table: `hardaudit rules --markdown`, paste between the markers in `docs/rules.md`, and update the counts in the README (`tests/test_docs.py` tells you).
- **A new fix** may only remove permission bits, set a stricter value, edit one named line, or block a module. Anything that can lock someone out (SSH, firewall, accounts) must stay a suggestion.
- **Report what could not be tested as such.** A rule that needs root, systemd or a package manager that is not there is `untestable`, never a pass or a fail.
- Tests build their own trees; do not commit system files.
