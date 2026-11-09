"""Reporters: serialize ScanResult to JSON / Markdown / HTML / SARIF."""
from __future__ import annotations

import html
import json

from ..core.models import SEVERITY_ORDER, ScanResult


def to_json(result: ScanResult, indent: int = 2) -> str:
    return json.dumps(result.to_dict(), indent=indent, ensure_ascii=False)


def to_markdown(result: ScanResult) -> str:
    counts = result.counts()
    lines = [
        f"# AttackSurfaceX report — {result.target}",
        "",
        f"Profile: `{result.profile}`",
        "",
        "| Severity | Count |",
        "|---|---|",
    ]
    lines += [f"| {sev} | {counts[sev]} |" for sev in (s.value for s in SEVERITY_ORDER)]
    lines += ["", "## Findings", ""]
    for f in result.sorted_findings():
        lines += [
            f"### [{f.severity.value.upper()}] {f.title}",
            "",
            f"- **Target:** `{f.target}`",
            f"- **Confidence:** {f.confidence.value}",
            f"- **Module:** {f.module}",
        ]
        if f.cwe:
            lines.append(f"- **CWE:** {f.cwe}")
        if f.owasp:
            lines.append(f"- **OWASP:** {f.owasp}")
        lines += [
            f"- **Evidence:** {f.evidence}",
            f"- **Remediation:** {f.remediation}",
        ]
        if f.false_positive_notes:
            lines.append(f"- **False-positive notes:** {f.false_positive_notes}")
        if f.references:
            lines.append("- **References:** " + ", ".join(f.references))
        lines.append("")
    return "\n".join(lines)


def to_html(result: ScanResult) -> str:
    counts = result.counts()
    cards = "".join(
        f'<div class="card sev-{s.value}"><b>{s.value.upper()}</b><span>{counts[s.value]}</span></div>'
        for s in SEVERITY_ORDER
    )
    rows = []
    for f in result.sorted_findings():
        rows.append(
            f'<tr class="sev-{f.severity.value}" data-sev="{f.severity.value}">'
            f"<td>{f.severity.value.upper()}</td><td>{html.escape(f.title)}</td>"
            f"<td><code>{html.escape(f.target)}</code></td>"
            f"<td>{html.escape(f.evidence)}</td>"
            f"<td>{html.escape(f.remediation)}</td></tr>"
        )
    filters = "".join(
        f'<button onclick="flt(\'{s.value}\')">{s.value}</button>' for s in SEVERITY_ORDER
    )
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>AttackSurfaceX — {html.escape(result.target)}</title>
<style>
body{{font-family:system-ui,sans-serif;margin:2rem;background:#0f172a;color:#e2e8f0}}
.cards{{display:flex;gap:1rem;margin-bottom:1.5rem}}
.card{{padding:1rem 1.5rem;border-radius:.5rem;background:#1e293b}}
.card span{{display:block;font-size:1.8rem}}
.sev-critical b,.sev-critical td:first-child{{color:#f87171}}
.sev-high b,.sev-high td:first-child{{color:#fb923c}}
.sev-medium b,.sev-medium td:first-child{{color:#facc15}}
.sev-low b,.sev-low td:first-child{{color:#38bdf8}}
.sev-info b,.sev-info td:first-child{{color:#94a3b8}}
table{{border-collapse:collapse;width:100%}}
td,th{{border:1px solid #334155;padding:.5rem;text-align:left;vertical-align:top}}
button{{margin-right:.5rem;padding:.4rem .8rem;background:#1e293b;color:#e2e8f0;border:1px solid #475569;border-radius:.3rem;cursor:pointer}}
button:hover{{background:#334155}}
code{{color:#7dd3fc}}
</style></head><body>
<h1>AttackSurfaceX report</h1>
<p>Target: <b>{html.escape(result.target)}</b> · Profile: <code>{html.escape(result.profile)}</code></p>
<div class="cards">{cards}</div>
<div>{filters}<button onclick="flt('')">all</button></div>
<table id="t"><thead><tr><th>Severity</th><th>Finding</th><th>Target</th><th>Evidence</th><th>Remediation</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table>
<script>
function flt(sev){{
  document.querySelectorAll('#t tbody tr').forEach(r=>{{
    r.style.display = (!sev || r.dataset.sev===sev) ? '' : 'none';
  }});
}}
</script>
</body></html>"""


def to_sarif(result: ScanResult) -> str:
    """SARIF 2.1.0 for GitHub Code Scanning."""
    level_map = {
        "critical": "error", "high": "error", "medium": "warning",
        "low": "note", "info": "note",
    }
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "AttackSurfaceX",
                    "version": __import__("asx").__version__,
                    "informationUri": "https://github.com/gevarru/AttackSurfaceX",
                    "rules": [],
                }
            },
            "results": [
                {
                    "ruleId": f.module,
                    "level": level_map[f.severity.value],
                    "message": {"text": f"{f.title} — {f.evidence} Remediation: {f.remediation}"},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.target},
                        }
                    }],
                }
                for f in result.sorted_findings()
            ],
        }],
    }
    return json.dumps(sarif, indent=2, ensure_ascii=False)
