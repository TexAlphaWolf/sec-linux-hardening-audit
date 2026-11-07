"""Render docs/demo.png from a real run on a made-up, neglected system (a fixture tree).

pip install -e ".[dev]" && playwright install chromium
python tools/screenshot.py
"""

from __future__ import annotations

import contextlib
import html
import io
import re
import sys
import tempfile
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from tests.fixtures import build_insecure

from hardaudit import cli

OUT = ROOT / "docs" / "demo.png"


def run(*argv: str) -> str:
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        cli.main(list(argv))
    return buffer.getvalue()


def colour(text: str) -> str:
    text = html.escape(text)
    text = re.sub(r"^(FAIL)", r'<span class="bad">\1</span>', text, flags=re.M)
    text = re.sub(r"\[(high)( *)\]", r'[<span class="bad">\1</span>\2]', text)
    text = re.sub(r"\[(medium)\]", r'[<span class="warn">\1</span>]', text)
    text = re.sub(r"^(score [\d.]+/100)", r'<span class="score">\1</span>', text, flags=re.M)
    text = re.sub(r"^(Score: .*)$", r'<span class="score">\1</span>', text, flags=re.M)
    return re.sub(r"^(\$ .*)$", r'<span class="cmd">\1</span>', text, flags=re.M)


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        tree = Path(tmp) / "neglected"
        build_insecure(tree, "debian")
        audit = run("audit", "--root", str(tree), "--fail-on", "none").splitlines()
        # keep the picture readable: the header and the first few findings
        shown = "\n".join([*audit[:2], "", *audit[3 : 3 + 4 * 8]])
        dry = run("fix", "--root", str(tree)).splitlines()
        applied = run("fix", "--apply", "--root", str(tree)).splitlines()
    parts = [
        "$ hardaudit audit --root ./neglected-system",
        shown,
        "    ... (51 failing rules in all)",
        "",
        "$ hardaudit fix --root ./neglected-system",
        *dry[:6],
        "  ...",
        "",
        "$ hardaudit fix --apply --root ./neglected-system",
        *[ln for ln in applied if ln.startswith(("Done", "Score"))],
    ]
    body = colour("\n".join(parts).replace(str(tree), "./neglected-system"))
    page = f"""<!doctype html><meta charset="utf-8"><style>
body{{margin:0;background:#0d1117}}
pre{{margin:0;padding:22px 26px;font:14px/1.45 ui-monospace,Menlo,Consolas,monospace;color:#c9d1d9;width:1000px;box-sizing:border-box}}
.bad{{color:#ff7b72;font-weight:700}}.warn{{color:#e3b341}}.score{{color:#7ee787;font-weight:700}}.cmd{{color:#79c0ff}}
</style><pre>{body}</pre>"""
    with sync_playwright() as p:
        browser = p.chromium.launch()
        shot = browser.new_page(viewport={"width": 1000, "height": 400}, device_scale_factor=2)
        shot.set_content(page)
        shot.locator("pre").screenshot(path=str(OUT))
        browser.close()
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
