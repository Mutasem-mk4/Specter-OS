"""
Specter-OS — CISO Report Generator
Generates professional PDF security reports from campaign findings.
"""

import os
import json
from datetime import datetime, UTC
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak, KeepTogether,
)
from reportlab.platypus.flowables import HRFlowable
from reportlab.graphics.shapes import Drawing, Rect, String
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics import renderPDF

from app.config import settings
from app.utils.logger import get_logger

logger = get_logger("report")

# ── Color Palette ──
BLACK       = colors.HexColor("#0D0D0D")
DARK_BG     = colors.HexColor("#12141A")
RED_ACCENT  = colors.HexColor("#E63946")
ORANGE      = colors.HexColor("#F4A261")
YELLOW      = colors.HexColor("#E9C46A")
GREEN       = colors.HexColor("#2A9D8F")
STEEL       = colors.HexColor("#264653")
LIGHT_GRAY  = colors.HexColor("#F8F9FA")
MID_GRAY    = colors.HexColor("#ADB5BD")
WHITE       = colors.white

SEVERITY_COLORS = {
    "critical": colors.HexColor("#E63946"),
    "high":     colors.HexColor("#F4A261"),
    "medium":   colors.HexColor("#E9C46A"),
    "low":      colors.HexColor("#2A9D8F"),
    "info":     colors.HexColor("#6C757D"),
}


class CISOReportGenerator:
    """Generates enterprise-grade PDF security reports for Specter-OS campaigns."""

    def __init__(self):
        self.reports_dir = Path(settings.reports_dir)
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self._styles = self._build_styles()

    def _build_styles(self) -> dict:
        base = getSampleStyleSheet()
        return {
            "title": ParagraphStyle(
                "SpecterTitle",
                fontSize=28, fontName="Helvetica-Bold",
                textColor=WHITE, alignment=TA_CENTER, spaceAfter=8,
            ),
            "subtitle": ParagraphStyle(
                "SpecterSubtitle",
                fontSize=12, fontName="Helvetica",
                textColor=MID_GRAY, alignment=TA_CENTER, spaceAfter=4,
            ),
            "section_header": ParagraphStyle(
                "SpecterSection",
                fontSize=14, fontName="Helvetica-Bold",
                textColor=RED_ACCENT, spaceBefore=16, spaceAfter=6,
                borderPadding=(0, 0, 4, 0),
            ),
            "finding_title": ParagraphStyle(
                "FindingTitle",
                fontSize=11, fontName="Helvetica-Bold",
                textColor=BLACK, spaceAfter=4,
            ),
            "body": ParagraphStyle(
                "SpecterBody",
                fontSize=9, fontName="Helvetica",
                textColor=colors.HexColor("#333333"),
                leading=14, alignment=TA_JUSTIFY, spaceAfter=6,
            ),
            "code": ParagraphStyle(
                "SpecterCode",
                fontSize=8, fontName="Courier",
                textColor=colors.HexColor("#1A1A2E"),
                backColor=colors.HexColor("#F0F0F0"),
                borderPadding=6, leading=12,
            ),
            "label": ParagraphStyle(
                "SpecterLabel",
                fontSize=8, fontName="Helvetica-Bold",
                textColor=MID_GRAY, spaceAfter=2,
            ),
        }

    def _severity_badge(self, severity: str, width: float = 80) -> Table:
        """Create a colored severity badge."""
        color = SEVERITY_COLORS.get(severity.lower(), MID_GRAY)
        t = Table(
            [[Paragraph(
                severity.upper(),
                ParagraphStyle("badge", fontSize=8, fontName="Helvetica-Bold",
                               textColor=WHITE, alignment=TA_CENTER)
            )]],
            colWidths=[width],
        )
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), color),
            ("ROUNDEDCORNERS", [4]),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        return t

    def _cvss_bar(self, score: float, width: float = 200) -> Table:
        """Visual CVSS score bar."""
        filled = int((score / 10.0) * 20)
        bar = "█" * filled + "░" * (20 - filled)
        color = (
            RED_ACCENT if score >= 9.0 else
            ORANGE if score >= 7.0 else
            YELLOW if score >= 4.0 else
            GREEN
        )
        style = ParagraphStyle(
            "cvss_bar", fontSize=10, fontName="Courier",
            textColor=color,
        )
        label = ParagraphStyle(
            "cvss_label", fontSize=9, fontName="Helvetica-Bold",
            textColor=colors.HexColor("#333333"),
        )
        return Table(
            [[Paragraph(bar, style), Paragraph(f"  {score:.1f}/10", label)]],
            colWidths=[width, 50],
        )

    def _build_cover_page(self, campaign_data: dict) -> list:
        """Build the report cover page."""
        elements = []

        # Dark header block via a table
        header_data = [[
            Paragraph("⚡ SPECTER-OS", self._styles["title"]),
        ]]
        header_table = Table(header_data, colWidths=[16 * cm])
        header_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), DARK_BG),
            ("TOPPADDING", (0, 0), (-1, -1), 40),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
            ("LEFTPADDING", (0, 0), (-1, -1), 20),
            ("RIGHTPADDING", (0, 0), (-1, -1), 20),
        ]))
        elements.append(header_table)

        subtitle_data = [[
            Paragraph("Autonomous AI Red Team Report", self._styles["subtitle"]),
        ]]
        sub_table = Table(subtitle_data, colWidths=[16 * cm])
        sub_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), DARK_BG),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 40),
            ("LEFTPADDING", (0, 0), (-1, -1), 20),
            ("RIGHTPADDING", (0, 0), (-1, -1), 20),
        ]))
        elements.append(sub_table)
        elements.append(Spacer(1, 1 * cm))

        # Campaign meta table
        meta = [
            ["Campaign", campaign_data.get("name", "Unnamed Campaign")],
            ["Target", campaign_data.get("target_url", "—")],
            ["Agent Identified", campaign_data.get("agent_name", "Unknown")],
            ["Report Date", datetime.now(UTC).strftime("%Y-%m-%d")],
            ["Classification", "CONFIDENTIAL - Authorized Personnel Only"],
        ]
        meta_table = Table(meta, colWidths=[5 * cm, 11 * cm])
        meta_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), LIGHT_GRAY),
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("GRID", (0, 0), (-1, -1), 0.5, MID_GRAY),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ]))
        elements.append(meta_table)
        elements.append(PageBreak())
        return elements

    def _build_executive_summary(
        self, campaign_data: dict, findings: list[dict]
    ) -> list:
        """Build the executive summary section."""
        elements = []
        elements.append(Paragraph("Executive Summary", self._styles["section_header"]))
        elements.append(HRFlowable(width="100%", thickness=1, color=RED_ACCENT))
        elements.append(Spacer(1, 0.3 * cm))

        # Stats row
        total = len(findings)
        critical = sum(1 for f in findings if f["severity"] == "critical")
        high = sum(1 for f in findings if f["severity"] == "high")
        medium = sum(1 for f in findings if f["severity"] == "medium")
        low = sum(1 for f in findings if f["severity"] in ("low", "info"))

        stats_data = [
            [
                self._stat_cell(str(total), "TOTAL FINDINGS"),
                self._stat_cell(str(critical), "CRITICAL", RED_ACCENT),
                self._stat_cell(str(high), "HIGH", ORANGE),
                self._stat_cell(str(medium), "MEDIUM", YELLOW),
                self._stat_cell(str(low), "LOW/INFO", GREEN),
            ]
        ]
        stats_table = Table(stats_data, colWidths=[3.2 * cm] * 5)
        stats_table.setStyle(TableStyle([
            ("TOPPADDING", (0, 0), (-1, -1), 0),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ]))
        elements.append(stats_table)
        elements.append(Spacer(1, 0.5 * cm))

        # Summary text
        summary = campaign_data.get("executive_summary", (
            f"Specter-OS conducted an autonomous red-team engagement against the target AI agent "
            f"at {campaign_data.get('target_url', 'the specified endpoint')}. "
            f"The assessment identified {total} security findings, including "
            f"{critical} critical and {high} high-severity vulnerabilities requiring immediate remediation."
        ))
        elements.append(Paragraph(summary, self._styles["body"]))
        elements.append(Spacer(1, 0.5 * cm))

        return elements

    def _stat_cell(self, value: str, label: str, color=STEEL) -> Table:
        """Create a statistic display cell."""
        value_style = ParagraphStyle(
            "stat_val", fontSize=22, fontName="Helvetica-Bold",
            textColor=color, alignment=TA_CENTER,
        )
        label_style = ParagraphStyle(
            "stat_lbl", fontSize=7, fontName="Helvetica-Bold",
            textColor=MID_GRAY, alignment=TA_CENTER,
        )
        t = Table(
            [[Paragraph(value, value_style)], [Paragraph(label, label_style)]],
            colWidths=[3 * cm],
        )
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), LIGHT_GRAY),
            ("TOPPADDING", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, MID_GRAY),
        ]))
        return t

    def _build_findings_section(self, findings: list[dict]) -> list:
        """Build detailed findings section."""
        elements = []
        elements.append(PageBreak())
        elements.append(Paragraph("Detailed Findings", self._styles["section_header"]))
        elements.append(HRFlowable(width="100%", thickness=1, color=RED_ACCENT))
        elements.append(Spacer(1, 0.3 * cm))

        for i, finding in enumerate(findings, 1):
            severity = finding.get("severity", "info")
            sev_color = SEVERITY_COLORS.get(severity.lower(), MID_GRAY)

            # Finding header
            header_data = [[
                Paragraph(
                    f"F{i:02d} — {finding.get('title', 'Unnamed Finding')}",
                    ParagraphStyle(
                        "fh", fontSize=11, fontName="Helvetica-Bold",
                        textColor=WHITE,
                    )
                ),
                Paragraph(
                    severity.upper(),
                    ParagraphStyle(
                        "fsev", fontSize=9, fontName="Helvetica-Bold",
                        textColor=WHITE, alignment=TA_CENTER,
                    )
                ),
            ]]
            hdr_table = Table(header_data, colWidths=[13 * cm, 3 * cm])
            hdr_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (0, 0), STEEL),
                ("BACKGROUND", (1, 0), (1, 0), sev_color),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
            ]))
            elements.append(KeepTogether([hdr_table]))
            elements.append(Spacer(1, 0.2 * cm))

            # CVSS Score
            cvss = finding.get("cvss_score", 0.0)
            elements.append(Paragraph("CVSS Score", self._styles["label"]))
            elements.append(self._cvss_bar(cvss))
            elements.append(Spacer(1, 0.2 * cm))

            # Description
            elements.append(Paragraph("Description", self._styles["label"]))
            elements.append(Paragraph(
                finding.get("description", "—"), self._styles["body"]
            ))

            # PoC
            poc = finding.get("proof_of_concept", "")
            if poc:
                elements.append(Paragraph("Proof of Concept", self._styles["label"]))
                elements.append(Paragraph(
                    poc[:600].replace("\n", "<br/>"), self._styles["code"]
                ))
                elements.append(Spacer(1, 0.2 * cm))

            # Remediation
            elements.append(Paragraph("Remediation", self._styles["label"]))
            elements.append(Paragraph(
                finding.get("remediation", "—"), self._styles["body"]
            ))

            # OWASP Category
            owasp = finding.get("owasp_category", "")
            if owasp:
                elements.append(Paragraph("OWASP Category", self._styles["label"]))
                elements.append(Paragraph(owasp, self._styles["body"]))

            elements.append(HRFlowable(width="100%", thickness=0.5, color=MID_GRAY))
            elements.append(Spacer(1, 0.4 * cm))

        return elements

    def _build_recommendations(self, findings: list[dict]) -> list:
        """Build remediation roadmap section."""
        elements = []
        elements.append(PageBreak())
        elements.append(Paragraph("Remediation Roadmap", self._styles["section_header"]))
        elements.append(HRFlowable(width="100%", thickness=1, color=RED_ACCENT))
        elements.append(Spacer(1, 0.3 * cm))

        # Priority matrix
        critical_findings = [f for f in findings if f["severity"] == "critical"]
        high_findings = [f for f in findings if f["severity"] == "high"]

        if critical_findings:
            elements.append(Paragraph(
                "🔴 IMMEDIATE ACTION REQUIRED (Critical)", self._styles["finding_title"]
            ))
            for f in critical_findings:
                elements.append(Paragraph(
                    f"• <b>{f.get('title', '—')}</b>: {f.get('remediation', '—')[:200]}",
                    self._styles["body"],
                ))
            elements.append(Spacer(1, 0.3 * cm))

        if high_findings:
            elements.append(Paragraph(
                "🟠 HIGH PRIORITY (Complete within 7 days)", self._styles["finding_title"]
            ))
            for f in high_findings:
                elements.append(Paragraph(
                    f"• <b>{f.get('title', '—')}</b>: {f.get('remediation', '—')[:200]}",
                    self._styles["body"],
                ))

        elements.append(Spacer(1, 0.5 * cm))
        elements.append(Paragraph(
            "General Hardening Recommendations", self._styles["finding_title"]
        ))
        general = [
            "Implement a dedicated LLM Firewall (e.g., AegisFW) in front of all AI agents",
            "Apply strict output filtering to prevent data exfiltration through encoded responses",
            "Implement conversation session isolation — no cross-user memory contamination",
            "Deploy role-based prompt hardening with invariant system prompt sections",
            "Establish a continuous red-team schedule using Specter-OS for regression testing",
            "Integrate with OWASP's Agentic AI Top 10 checklist for compliance alignment",
        ]
        for rec in general:
            elements.append(Paragraph(f"• {rec}", self._styles["body"]))

        return elements

    async def generate(
        self,
        campaign_data: dict,
        findings: list[dict],
    ) -> str:
        """
        Generate a PDF report for a campaign.

        Args:
            campaign_data: Dict with campaign info (name, target_url, agent_name, etc.)
            findings: List of finding dicts (title, severity, cvss_score, etc.)

        Returns:
            Absolute path to the generated PDF file
        """
        timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
        safe_name = "".join(
            c if c.isalnum() or c in "-_" else "_"
            for c in campaign_data.get("name", "report")
        )
        filename = f"specter_report_{safe_name}_{timestamp}.pdf"
        filepath = self.reports_dir / filename

        logger.info(f"📄 Generating CISO report: {filename}")

        doc = SimpleDocTemplate(
            str(filepath),
            pagesize=A4,
            leftMargin=2 * cm,
            rightMargin=2 * cm,
            topMargin=2 * cm,
            bottomMargin=2 * cm,
            title=f"Specter-OS Report — {campaign_data.get('name', '')}",
            author="Specter-OS Autonomous Red Team Engine",
            subject="AI Agent Security Assessment",
        )

        elements = []
        elements += self._build_cover_page(campaign_data)
        elements += self._build_executive_summary(campaign_data, findings)
        elements += self._build_findings_section(findings)
        elements += self._build_recommendations(findings)

        # Footer note
        elements.append(PageBreak())
        elements.append(Spacer(1, 2 * cm))
        elements.append(Paragraph(
            "Generated by Specter-OS — Autonomous AI Red Teaming Engine",
            ParagraphStyle(
                "footer", fontSize=8, textColor=MID_GRAY, alignment=TA_CENTER
            )
        ))
        elements.append(Paragraph(
            "This report contains confidential security information. "
            "Unauthorized distribution is prohibited.",
            ParagraphStyle(
                "footer2", fontSize=7, textColor=MID_GRAY, alignment=TA_CENTER
            )
        ))

        doc.build(elements)
        logger.info(f"✅ Report saved: {filepath}")
        return str(filepath)
