"""
Generates a real PDF incident report (reportlab) summarising an
inspection batch: class distribution, blocked requests with the rules/
ML class that triggered the block, and a model performance snapshot.
"""

from __future__ import annotations

import io
from datetime import datetime, timezone
from typing import Any, Dict, List

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

NAVY = colors.HexColor("#0B1F3A")
LIGHT_GREY = colors.HexColor("#F1F5F9")
CRITICAL = colors.HexColor("#DC2626")
HIGH = colors.HexColor("#EA580C")
MEDIUM = colors.HexColor("#CA8A04")


def _severity_color(sev: str):
    return {"critical": CRITICAL, "high": HIGH, "medium": MEDIUM}.get((sev or "").lower(), colors.grey)


def generate_incident_report(
    batch_id: str,
    class_counts: Dict[str, int],
    blocked_requests: List[Dict[str, Any]],
    model_summary: Dict[str, Any],
) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=18 * mm, rightMargin=18 * mm, topMargin=16 * mm, bottomMargin=16 * mm,
    )
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("TitleNavy", parent=styles["Title"], textColor=NAVY, fontSize=20)
    h2 = ParagraphStyle("H2", parent=styles["Heading2"], textColor=NAVY)
    body = styles["BodyText"]

    story = [
        Paragraph("ShieldWAF &mdash; Web Application Firewall Incident Report", title_style),
        Spacer(1, 4 * mm),
        Paragraph(
            f"Batch ID: <b>{batch_id}</b> &nbsp;&nbsp;|&nbsp;&nbsp; "
            f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
            body,
        ),
        Spacer(1, 6 * mm),
        Paragraph("1. Request Classification Summary", h2),
    ]

    class_table_data = [["Class", "Request Count"]] + [
        [k, str(v)] for k, v in sorted(class_counts.items(), key=lambda x: -x[1])
    ]
    t1 = Table(class_table_data, colWidths=[90 * mm, 40 * mm])
    t1.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT_GREY]),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#CBD5E1")),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story += [t1, Spacer(1, 6 * mm)]

    story.append(Paragraph("2. Blocked Requests (rule engine + classifier)", h2))
    if blocked_requests:
        rows = [["Client IP", "Path", "Predicted", "Rule Match", "Severity"]]
        for r in blocked_requests[:60]:
            rule_names = ", ".join(m["name"] for m in r.get("rule_matches", [])) or "-"
            rows.append([
                r.get("client_ip", "-"),
                (r.get("path", "-") or "-")[:40],
                r.get("predicted_class", "-"),
                Paragraph(rule_names, ParagraphStyle("small", fontSize=7.5)),
                r.get("severity", "-"),
            ])
        t2 = Table(rows, colWidths=[28 * mm, 40 * mm, 26 * mm, 56 * mm, 20 * mm], repeatRows=1)
        style_cmds = [
            ("BACKGROUND", (0, 0), (-1, 0), NAVY),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#CBD5E1")),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]
        for i in range(1, len(rows)):
            sev_val = blocked_requests[i - 1].get("severity", "")
            style_cmds.append(("TEXTCOLOR", (4, i), (4, i), _severity_color(sev_val)))
        t2.setStyle(TableStyle(style_cmds))
        story += [t2]
    else:
        story.append(Paragraph("No requests were blocked in this batch.", body))

    story += [Spacer(1, 6 * mm), Paragraph("3. Model Snapshot", h2)]
    story.append(Paragraph(
        f"Random Forest macro ROC-AUC (one-vs-rest): <b>{model_summary.get('roc_auc_macro_ovr', 'n/a')}</b> "
        f"&nbsp;|&nbsp; Anomaly detector benign-vs-attack AUC: "
        f"<b>{model_summary.get('anomaly_auc', 'n/a')}</b> &nbsp;|&nbsp; "
        f"Trained on {model_summary.get('n_train', 'n/a')} synthetic requests.",
        body,
    ))
    story += [Spacer(1, 4 * mm), Paragraph(
        "<i>Note: classifier trained on requests built from real, documented "
        "OWASP-style payload strings with randomised benign structure (see "
        "dataset.py) &mdash; high accuracy reflects separability of these "
        "known payload patterns, not an audited real-world false-positive rate.</i>",
        ParagraphStyle("note", parent=body, fontSize=8, textColor=colors.grey),
    )]

    doc.build(story)
    return buf.getvalue()
