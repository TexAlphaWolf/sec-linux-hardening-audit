"""Text, JSON and HTML output. The text output is ASCII only so it survives any terminal."""

from __future__ import annotations

import html
import json

from hardaudit import __version__
from hardaudit.model import SEVERITIES, STATUSES, Report

_ORDER = {s: i for i, s in enumerate(SEVERITIES)}


def _sorted(report: Report, status: str) -> list:  # type: ignore[type-arg]
    return sorted(
        (r for r in report.results if r.status == status),
        key=lambda r: (_ORDER[r.rule.severity], r.rule.id),
    )


def text(report: Report, *, verbose: bool = False) -> str:
    score = "n/a" if report.score is None else f"{report.score:.1f}/100"
    counts = "  ".join(f"{s} {report.count(s)}" for s in STATUSES)
    out = [
        f"hardaudit {__version__}  {report.distro}  ({report.family} family, root {report.root})",
        f"score {score}   {counts}",
        "",
    ]
    for status in ("fail", "error"):
        for r in _sorted(report, status):
            out.append(f"{status.upper():<5} {r.rule.id}  [{r.rule.severity:<6}] {r.rule.title}")
            out.append(f"      {r.detail}")
            if status == "fail":
                out.append(f"      fix: {r.rule.fix}")
                if r.rule.apply:
                    out.append("      (hardaudit fix --apply can do this)")
            out.append("")
    shown = ("untestable", "pass", "na") if verbose else ("untestable",)
    for status in shown:
        for r in _sorted(report, status):
            out.append(f"{status.upper():<10} {r.rule.id}  {r.rule.title}: {r.detail}")
    if not verbose:
        out.append("")
        out.append("(use -v to list passed and not-applicable rules)")
    return "\n".join(out).rstrip() + "\n"


def to_json(report: Report) -> str:
    return json.dumps(report.to_dict(), indent=2)


_STYLE = """
body{font:15px/1.5 system-ui,sans-serif;max-width:60rem;margin:2rem auto;padding:0 1rem;color:#1b1f23}
h1{font-size:1.3rem;margin:0}.sub{color:#57606a;margin:.2rem 0 1rem}
.score{font-size:2.4rem;font-weight:700}.pill{display:inline-block;padding:.05rem .5rem;border-radius:1rem;font-size:.8rem;font-weight:600}
.fail{background:#ffebe9;color:#82071e}.pass{background:#dafbe1;color:#116329}.untestable,.na,.error{background:#eaeef2;color:#424a53}
.high{color:#82071e}.medium{color:#7d4e00}.low{color:#57606a}
table{border-collapse:collapse;width:100%}td,th{text-align:left;padding:.4rem .5rem;border-bottom:1px solid #d0d7de;vertical-align:top}
code{font-size:.85rem}.fixline{color:#57606a;font-size:.85rem}
"""


def to_html(report: Report) -> str:
    score = "n/a" if report.score is None else f"{report.score:.1f}"
    rows = []
    order = {"fail": 0, "error": 1, "untestable": 2, "pass": 3, "na": 4}
    for r in sorted(
        report.results, key=lambda r: (order[r.status], _ORDER[r.rule.severity], r.rule.id)
    ):
        fix = (
            f'<div class="fixline">fix: {html.escape(r.rule.fix)}</div>'
            if r.status == "fail"
            else ""
        )
        rows.append(
            f'<tr><td><span class="pill {r.status}">{r.status}</span></td>'
            f"<td><code>{r.rule.id}</code></td>"
            f'<td class="{r.rule.severity}">{r.rule.severity}</td>'
            f'<td>{html.escape(r.rule.title)}<div class="fixline">{html.escape(r.detail)}</div>{fix}</td></tr>'
        )
    summary = " &middot; ".join(f"{s} {report.count(s)}" for s in STATUSES)
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f"<title>hardaudit report</title><style>{_STYLE}</style></head><body>"
        f"<h1>hardaudit {__version__}</h1>"
        f'<p class="sub">{html.escape(report.distro)} ({report.family} family, root {html.escape(report.root)})</p>'
        f'<div class="score">{score}<small> / 100</small></div><p class="sub">{summary}</p>'
        "<table><tr><th>Status</th><th>Rule</th><th>Severity</th><th>Check</th></tr>"
        + "".join(rows)
        + "</table></body></html>"
    )
