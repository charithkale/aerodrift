"""Incident report: a PDF (reportlab) describing what drifted and how the agent fixed it.

Falls back to Markdown when reportlab is not installed.
"""
from __future__ import annotations

import textwrap
import time

from .daemon import CycleResult


def _ts(t):
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(t)) if t else "-"


def _wrap_code(src: str, width: int = 88) -> str:
    """Wrap long generated lines for display only (the stored source is untouched)."""
    out = []
    for line in src.splitlines():
        ind = " " * (len(line) - len(line.lstrip()))
        out += textwrap.wrap(line, width, subsequent_indent=ind + "    ", break_long_words=False,
                             break_on_hyphens=False) or [""]
    return "\n".join(out)


def write_incident_report(path: str, res: CycleResult, detection_seconds: float | None = None) -> str:
    facts = [
        ("Detected at", _ts(res.detected_at)),
        ("Detection latency", "%.2f s after the change" % detection_seconds if detection_seconds is not None else "n/a"),
        ("Mode", "auto-remediation APPLIED" if res.applied else "DRY-RUN (nothing changed in the cloud)"),
        ("Remediated at", _ts(res.remediated_at)),
        ("Verification", {True: "passed - targeted findings no longer present", False: "FAILED - findings remain",
                          None: "not performed (dry-run)"}[res.verified]),
    ]
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.platypus import Paragraph, Preformatted, SimpleDocTemplate, Spacer, Table, TableStyle
    except ImportError:
        return _markdown(path.rsplit(".", 1)[0] + ".md", res, facts)

    ss = getSampleStyleSheet()
    doc = SimpleDocTemplate(path, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm,
                            topMargin=18 * mm, bottomMargin=18 * mm, title="AeroDrift incident report")
    wrap = ss["BodyText"]

    def table(rows, widths, header=True):
        rows = [[Paragraph(str(c).replace("&", "&amp;").replace("<", "&lt;"), wrap) for c in r] for r in rows]
        t = Table(rows, colWidths=widths, repeatRows=1 if header else 0)
        style = [("GRID", (0, 0), (-1, -1), 0.4, colors.grey), ("VALIGN", (0, 0), (-1, -1), "TOP")]
        if header:
            style.append(("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e8eef7")))
        t.setStyle(TableStyle(style))
        return t

    story = [Paragraph("AeroDrift - Incident Report", ss["Title"]),
             Paragraph("Security-group drift detected and handled by the AeroDrift agent.", wrap),
             Spacer(1, 6 * mm), Paragraph("Summary", ss["Heading2"]),
             table(facts, [45 * mm, 125 * mm], header=False),
             Spacer(1, 5 * mm), Paragraph("What drifted", ss["Heading2"])]
    story.append(table([["Severity", "SG", "Rule", "Finding"]] +
                       [[f.severity, f.sg_id, f.rule.describe(), f.message] for f in res.findings],
                       [22 * mm, 26 * mm, 42 * mm, 80 * mm]))
    story += [Spacer(1, 5 * mm), Paragraph("Changes vs approved baseline", ss["Heading2"]),
              table([["Change", "Resource", "Detail"]] +
                    ([[c.kind, c.target, c.detail] for c in res.changes] or [["none", "", ""]]),
                    [40 * mm, 40 * mm, 90 * mm])]
    story += [Spacer(1, 5 * mm), Paragraph("How the agent fixed it", ss["Heading2"]),
              Paragraph("The remediation below was generated with Python's ast module, validated against a "
                        "whitelist (single function, only ec2.revoke_security_group_ingress), then executed "
                        "with empty builtins.", wrap), Spacer(1, 2 * mm),
              Preformatted(_wrap_code(res.source or "(no action)"), ss["Code"]), Spacer(1, 3 * mm)]
    if res.call_log:
        story.append(table([["Mode", "API", "Security group"]] +
                           [["dry-run" if c["dry_run"] else "applied", c["method"], c["GroupId"]]
                            for c in res.call_log], [30 * mm, 80 * mm, 60 * mm]))
    if res.notes or res.skipped:
        story += [Spacer(1, 4 * mm), Paragraph("Notes", ss["Heading2"])]
        story += [Paragraph("- " + n, wrap) for n in res.notes]
    doc.build(story)
    return path


def _markdown(path, res, facts):
    lines = ["# AeroDrift - Incident Report", ""] + ["- **%s**: %s" % kv for kv in facts]
    lines += ["", "## Findings"] + ["- [%s] %s" % (f.severity, f.message) for f in res.findings]
    lines += ["", "## Generated remediation", "```python", res.source, "```"]
    open(path, "w").write("\n".join(lines))
    return path
