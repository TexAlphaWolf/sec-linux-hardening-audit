"""Load and validate the rule files (TOML)."""

from __future__ import annotations

import re
import tomllib
from importlib import resources
from pathlib import Path
from typing import Any

from hardaudit.model import FAMILIES, SEVERITIES, Rule

CHECK_TYPES = (
    "sysctl", "file_mode", "config", "mount", "package", "module", "accounts",
    "service", "file_regex", "path_absent",
)  # fmt: skip
APPLY_TYPES = ("sysctl", "chmod", "config_line", "module_block")
_ID = re.compile(r"^HA-[A-Z]{2,5}-\d{3}$")
_REQUIRED = ("id", "title", "section", "severity", "check", "why", "fix")


class RuleError(ValueError):
    """A rule file is malformed. The message names the file and the rule."""


def _build(raw: dict[str, Any], origin: str) -> Rule:
    name = raw.get("id", "?")
    where = f"{origin}: rule {name}"
    for key in _REQUIRED:
        if key not in raw:
            raise RuleError(f"{where}: missing '{key}'")
    if not _ID.match(raw["id"]):
        raise RuleError(f"{where}: id must look like HA-SSH-001")
    if raw["severity"] not in SEVERITIES:
        raise RuleError(f"{where}: severity must be one of {', '.join(SEVERITIES)}")
    families = tuple(raw.get("families", ()))
    if any(f not in FAMILIES for f in families):
        raise RuleError(f"{where}: families must be among {', '.join(FAMILIES)}")
    check = raw["check"]
    if not isinstance(check, dict) or check.get("type") not in CHECK_TYPES:
        raise RuleError(f"{where}: check.type must be one of {', '.join(CHECK_TYPES)}")
    apply = raw.get("apply")
    if apply is not None and (not isinstance(apply, dict) or apply.get("type") not in APPLY_TYPES):
        raise RuleError(f"{where}: apply.type must be one of {', '.join(APPLY_TYPES)}")
    return Rule(
        id=raw["id"],
        title=raw["title"],
        section=raw["section"],
        severity=raw["severity"],
        check=check,
        why=raw["why"].strip(),
        fix=raw["fix"].strip(),
        families=families,
        apply=apply,
    )


def parse(text: str, origin: str = "<string>") -> list[Rule]:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise RuleError(f"{origin}: not valid TOML: {exc}") from exc
    raw_rules = data.get("rule", [])
    if not isinstance(raw_rules, list):
        raise RuleError(f"{origin}: 'rule' must be an array of tables ([[rule]])")
    return [_build(raw, origin) for raw in raw_rules]


def load(extra_dir: str | Path | None = None) -> list[Rule]:
    """The bundled rules, plus any ``*.toml`` in ``extra_dir``. Ids must be unique."""
    rules: list[Rule] = []
    folder = resources.files("hardaudit") / "rules"
    for entry in sorted(folder.iterdir(), key=lambda e: e.name):
        if entry.name.endswith(".toml"):
            rules += parse(entry.read_text(encoding="utf-8"), f"rules/{entry.name}")
    if extra_dir is not None:
        for path in sorted(Path(extra_dir).glob("*.toml")):
            rules += parse(path.read_text(encoding="utf-8"), str(path))
    seen: set[str] = set()
    for rule in rules:
        if rule.id in seen:
            raise RuleError(f"duplicate rule id {rule.id}")
        seen.add(rule.id)
    return rules
