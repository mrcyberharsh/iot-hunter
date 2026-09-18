"""Local report generation — PDF (ReportLab) and JSON."""
from __future__ import annotations

import json
import logging
import os
import time
from typing import Any, Dict, List, Optional

from .models import Finding

log = logging.getLogger(__name__)

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether,
    )
    REPORTLAB_AVAILABLE = True
except Exception:  # pragma: no cover
    REPORTLAB_AVAILABLE = False

_SEVERITY_COLORS = {
    "critical": colors.HexColor("#7f1d1d") if REPORTLAB_AVAILABLE else None,
    "high":     colors.HexColor("#b91c1c") if REPORTLAB_AVAILABLE else None,
    "medium":   colors.HexColor("#b45309") if REPORTLAB_AVAILABLE else None,
    "low":      colors.HexColor("#0369a1") if REPORTLAB_AVAILABLE else None,
    "info":     colors.HexColor("#374151") if REPORTLAB_AVAILABLE else None,
}


class Reporter:
    def __init__(self, config: Dict[str, Any]):
        rcfg = config.get("reporting", {}) or {}
        self.output_dir = rcfg.get("output_dir", "./reports")
        self.company = rcfg.get("company_name", "Organisation")
        self.title = rcfg.get("report_title", "IoT Security Assessment")
        self.formats = set(rcfg.get("formats", ["pdf", "json"]))
        os.makedirs(self.output_dir, exist_ok=True)

    # ------------------------------------------------------------------ #
    def _stamp(self) -> str:
        return time.strftime("%Y%m%d-%H%M%S")

    # ------------------------------------------------------------------ #
    def export_json(self, data: Dict[str, Any], filename: Optional[str] = None) -> str:
        path = os.path.join(
            self.output_dir, filename or f"iothunter-{self._stamp()}.json"
        )
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, default=str)
        log.info("JSON report written to %s", path)
        return path

    # ------------------------------------------------------------------ #
    def export_pdf(
        self,
        session: Dict[str, Any],
        findings: List[Finding],
        compliance: Dict[str, Any],
        remediation_plan: List[Dict[str, Any]],
        filename: Optional[str] = None,
    ) -> str:
        if not REPORTLAB_AVAILABLE:
            raise RuntimeError("reportlab is required for PDF export")

        path = os.path.join(
            self.output_dir, filename or f"iothunter-{self._stamp()}.pdf"
        )

        styles = getSampleStyleSheet()
        styles.add(ParagraphStyle(
            name="H1Custom", parent=styles["Heading1"], fontSize=18, spaceAfter=10,
            textColor=colors.HexColor("#111827"),
        ))
        styles.add(ParagraphStyle(
            name="H2Custom", parent=styles["Heading2"], fontSize=13, spaceBefore=12,
            spaceAfter=6, textColor=colors.HexColor("#1f2937"),
        ))
        styles.add(ParagraphStyle(
            name="BodyCustom", parent=styles["BodyText"], fontSize=9, leading=12,
        ))
        styles.add(ParagraphStyle(
            name="Mono", parent=styles["BodyText"], fontName="Courier", fontSize=8,
            leading=10,
        ))

        doc = SimpleDocTemplate(
            path, pagesize=A4,
            leftMargin=18 * mm, rightMargin=18 * mm,
            topMargin=18 * mm, bottomMargin=18 * mm,
            title=f"{self.title} — {self.company}",
            author="iot-hunter",
        )

        story: List[Any] = []
        story.append(Paragraph(f"{self.title}", styles["H1Custom"]))
        story.append(Paragraph(self.company, styles["BodyCustom"]))
        story.append(Spacer(1, 6))
        story.append(Paragraph(
            f"Generated: {session.get('finished_at', time.strftime('%Y-%m-%d %H:%M:%S'))}",
            styles["BodyCustom"],
        ))
        story.append(Paragraph(
            f"Interface: {session.get('interface', 'n/a')} &nbsp;|&nbsp; "
            f"Subnet: {session.get('subnet', 'n/a')} &nbsp;|&nbsp; "
            f"Hosts discovered: {len(session.get('devices', []))}",
            styles["BodyCustom"],
        ))
        story.append(Spacer(1, 12))

        # --- Executive summary ----------------------------------------- #
        story.append(Paragraph("1. Executive Summary", styles["H2Custom"]))
        summary = compliance.get("summary", {})
        score = compliance.get("score", 0)
        band = compliance.get("score_band", "n/a")

        summary_rows = [
            ["Metric", "Value"],
            ["Compliance score", f"{score}/100 ({band})"],
            ["Total findings", str(summary.get("total", 0))],
            ["Critical", str(summary.get("critical", 0))],
            ["High", str(summary.get("high", 0))],
            ["Medium", str(summary.get("medium", 0))],
            ["Low", str(summary.get("low", 0))],
            ["Informational", str(summary.get("info", 0))],
        ]
        t = Table(summary_rows, colWidths=[65 * mm, 90 * mm])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#d1d5db")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1),
             [colors.white, colors.HexColor("#f9fafb")]),
        ]))
        story.append(t)

        # --- Asset inventory -------------------------------------------- #
        story.append(PageBreak())
        story.append(Paragraph("2. Asset Inventory", styles["H2Custom"]))
        devices = session.get("devices", [])
        if devices:
            rows = [["IP", "MAC", "Vendor", "Hostname", "Type", "Open ports"]]
            for d in devices:
                ports = ", ".join(str(p["port"]) for p in d.get("ports", [])) or "-"
                rows.append([
                    d.get("ip", ""),
                    d.get("mac", "") or "-",
                    (d.get("vendor", "") or "-")[:28],
                    (d.get("hostname", "") or "-")[:28],
                    (d.get("device_type", "") or "-")[:22],
                    ports[:48],
                ])
            t = Table(rows, repeatRows=1, colWidths=[
                24 * mm, 30 * mm, 34 * mm, 34 * mm, 30 * mm, 30 * mm
            ])
            t.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 7.5),
                ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#d1d5db")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1),
                 [colors.white, colors.HexColor("#f9fafb")]),
            ]))
            story.append(t)
        else:
            story.append(Paragraph("No devices discovered.", styles["BodyCustom"]))

        # --- Findings ---------------------------------------------------- #
        story.append(PageBreak())
        story.append(Paragraph("3. Findings", styles["H2Custom"]))
        if not findings:
            story.append(Paragraph(
                "No findings were produced during this assessment.",
                styles["BodyCustom"],
            ))
        else:
            order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
            ordered = sorted(findings, key=lambda f: (order.get(f.severity, 9), f.asset))
            for idx, f in enumerate(ordered, start=1):
                header = Table(
                    [[
                        Paragraph(f"<b>{idx}. {f.title}</b>", styles["BodyCustom"]),
                        Paragraph(
                            f"<b>{f.severity.upper()}</b>",
                            ParagraphStyle(
                                name=f"sev{idx}",
                                parent=styles["BodyCustom"],
                                textColor=_SEVERITY_COLORS.get(f.severity, colors.black),
                                alignment=2,
                            ),
                        ),
                    ]],
                    colWidths=[130 * mm, 25 * mm],
                )
                header.setStyle(TableStyle([
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
                    ("TOPPADDING", (0, 0), (-1, -1), 2),
                    ("LINEBELOW", (0, 0), (-1, -1), 0.4, colors.HexColor("#e5e7eb")),
                ]))

                block = [
                    header,
                    Paragraph(f"Asset: {f.asset or 'n/a'} &nbsp;|&nbsp; "
                               f"Category: {f.category} &nbsp;|&nbsp; {f.timestamp}",
                               styles["BodyCustom"]),
                    Paragraph(f.description, styles["BodyCustom"]),
                ]
                if f.evidence:
                    ev = json.dumps(f.evidence, indent=2, default=str)
                    block.append(Paragraph(ev.replace("\n", "<br/>"), styles["Mono"]))
                block.append(Spacer(1, 8))
                story.append(KeepTogether(block))

        # --- Compliance -------------------------------------------------- #
        story.append(PageBreak())
        story.append(Paragraph("4. Compliance Gaps", styles["H2Custom"]))
        if "iso27001" in compliance:
            story.append(Paragraph("ISO/IEC 27001:2022 Annex A", styles["H2Custom"]))
            rows = [["Control", "Title", "Findings"]]
            for item in compliance["iso27001"]["controls_triggered"]:
                rows.append([
                    item["control"], item["title"], str(len(item["findings"]))
                ])
            if len(rows) == 1:
                rows.append(["—", "No controls triggered", "0"])
            t = Table(rows, repeatRows=1, colWidths=[25 * mm, 105 * mm, 25 * mm])
            t.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#d1d5db")),
            ]))
            story.append(t)

        if "dpdp" in compliance:
            story.append(Paragraph("DPDP Act 2023", styles["H2Custom"]))
            rows = [["Reference", "Findings"]]
            for item in compliance["dpdp"]["obligations_triggered"]:
                rows.append([item["reference"], str(len(item["findings"]))])
            if len(rows) == 1:
                rows.append(["No obligations triggered", "0"])
            t = Table(rows, colWidths=[120 * mm, 35 * mm])
            t.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#d1d5db")),
            ]))
            story.append(t)
            if compliance["dpdp"].get("notification_required"):
                story.append(Paragraph(
                    "<b>Breach notification to the Data Protection Board is likely required "
                    "(DPDP Act Section 8(6)).</b>", styles["BodyCustom"],
                ))

        if "certin" in compliance:
            story.append(Paragraph("CERT-In Reporting Categories", styles["H2Custom"]))
            rows = [["Category", "Findings"]]
            for item in compliance["certin"]["categories"]:
                rows.append([item["category"], str(len(item["findings"]))])
            if len(rows) == 1:
                rows.append(["No categories triggered", "0"])
            t = Table(rows, colWidths=[120 * mm, 35 * mm])
            t.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#d1d5db")),
            ]))
            story.append(t)
            story.append(Paragraph(
                "Report qualifying incidents to CERT-In within 6 hours of detection.",
                styles["BodyCustom"],
            ))

        # --- Remediation -------------------------------------------------- #
        story.append(PageBreak())
        story.append(Paragraph("5. Remediation Plan", styles["H2Custom"]))
        if not remediation_plan:
            story.append(Paragraph("No remediation actions required.", styles["BodyCustom"]))
        for item in remediation_plan:
            story.append(Paragraph(
                f"[{item['priority']}] {item['title']} "
                f"<font size=8>({item['highest_severity']}; "
                f"{len(item['affected_assets'])} asset(s))</font>",
                styles["H2Custom"],
            ))
            if item["affected_assets"]:
                story.append(Paragraph(
                    "Affected: " + ", ".join(item["affected_assets"][:20]),
                    styles["BodyCustom"],
                ))
            for step in item["steps"]:
                for line in step.splitlines():
                    story.append(Paragraph(f"• {line}", styles["Mono"]))
            story.append(Spacer(1, 8))

        doc.build(story)
        log.info("PDF report written to %s", path)
        return path
