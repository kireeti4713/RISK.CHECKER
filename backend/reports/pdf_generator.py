"""
PDF Report Generator for RISK CHECKER.
Builds professional cybersecurity assessment executive and technical audit reports using ReportLab.
"""

import os
from datetime import datetime
from typing import Dict, Any
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, KeepTogether
)


def get_severity_color(sev: str) -> colors.Color:
    s = str(sev).upper()
    if s == "CRITICAL":
        return colors.HexColor("#ef4444")
    elif s == "HIGH":
        return colors.HexColor("#f97316")
    elif s == "MEDIUM":
        return colors.HexColor("#f59e0b")
    else:
        return colors.HexColor("#10b981")


def generate_security_pdf_report(scan_data: Dict[str, Any], output_path: str) -> str:
    """Generates a comprehensive PDF security assessment report."""
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    doc = SimpleDocTemplate(
        output_path,
        pagesize=letter,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40
    )

    styles = getSampleStyleSheet()
    
    # Custom styles
    header_style = ParagraphStyle(
        "ReportHeader",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=24,
        leading=28,
        textColor=colors.HexColor("#0f172a")
    )
    subtitle_style = ParagraphStyle(
        "ReportSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=16,
        textColor=colors.HexColor("#0284c7")
    )
    meta_style = ParagraphStyle(
        "MetaText",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#475569")
    )
    section_h1 = ParagraphStyle(
        "SectionH1",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=15,
        leading=19,
        textColor=colors.HexColor("#0f172a"),
        spaceAfter=6,
        spaceBefore=14
    )
    body_style = ParagraphStyle(
        "ReportBody",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#1e293b")
    )
    code_style = ParagraphStyle(
        "ReportCode",
        parent=styles["Normal"],
        fontName="Courier",
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#0f172a")
    )

    elements = []

    # Title Banner
    elements.append(Paragraph("RISK CHECKER", header_style))
    elements.append(Paragraph("Intelligent Cybersecurity Risk Assessment Platform", subtitle_style))
    elements.append(Spacer(1, 10))
    elements.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#0284c7"), spaceAfter=14))

    # Assessment Meta Grid
    target_url = scan_data.get("target_url", "N/A")
    hostname = scan_data.get("hostname", "N/A")
    ip_addr = scan_data.get("ip_address", "N/A")
    created_at = scan_data.get("created_at", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    scan_id = scan_data.get("id", "N/A")
    risk_score = scan_data.get("risk_score", 0)
    risk_level = scan_data.get("risk_level", "LOW")

    meta_table_data = [
        [
            Paragraph(f"<b>Target URL:</b> {target_url}", meta_style),
            Paragraph(f"<b>Assessment Date:</b> {created_at}", meta_style)
        ],
        [
            Paragraph(f"<b>Hostname:</b> {hostname}", meta_style),
            Paragraph(f"<b>Report ID:</b> RC-SCAN-{scan_id}", meta_style)
        ],
        [
            Paragraph(f"<b>Resolved IP:</b> {ip_addr}", meta_style),
            Paragraph(f"<b>Engine Version:</b> RISK CHECKER v2.4 (Enterprise Core)", meta_style)
        ]
    ]
    meta_table = Table(meta_table_data, colWidths=[280, 250])
    meta_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ("PADDING", (0, 0), (-1, -1), 6),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LINEBELOW", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
    ]))
    elements.append(meta_table)
    elements.append(Spacer(1, 14))

    # Executive Summary Card
    elements.append(Paragraph("1. Executive Risk Summary", section_h1))
    
    sev_color = get_severity_color(risk_level)
    score_card_data = [
        [
            Paragraph(
                f"<font size=28 color='{sev_color.hexval()}'><b>{risk_score} / 100</b></font><br/>"
                f"<font size=12 color='{sev_color.hexval()}'><b>{risk_level} POSTURE RISK</b></font>",
                ParagraphStyle("ScoreBox", parent=styles["Normal"], alignment=1)
            ),
            Paragraph(
                f"During the defensive configuration assessment of <b>{hostname}</b>, the RISK CHECKER engine evaluated "
                f"HTTP response headers, Transport Layer Security (TLS/SSL) certificate parameters, TCP exposure, and DNS configuration.<br/><br/>"
                f"Overall, the target was assigned a risk score of <b>{risk_score}/100</b> resulting in a <b>{risk_level}</b> risk tier. "
                f"Identified configuration anomalies should be reviewed against your organization's security baseline.",
                body_style
            )
        ]
    ]
    score_table = Table(score_card_data, colWidths=[160, 370])
    score_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, 0), colors.HexColor("#0f172a")),
        ("BACKGROUND", (1, 0), (1, 0), colors.HexColor("#f1f5f9")),
        ("PADDING", (0, 0), (-1, -1), 10),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
    ]))
    elements.append(score_table)
    elements.append(Spacer(1, 14))

    # Severity Breakdown Counts
    findings = scan_data.get("findings", [])
    crit_count = sum(1 for f in findings if f.get("severity") == "CRITICAL")
    high_count = sum(1 for f in findings if f.get("severity") == "HIGH")
    med_count = sum(1 for f in findings if f.get("severity") == "MEDIUM")
    low_count = sum(1 for f in findings if f.get("severity") == "LOW")

    breakdown_data = [
        ["CRITICAL", "HIGH", "MEDIUM", "LOW", "TOTAL FINDINGS"],
        [str(crit_count), str(high_count), str(med_count), str(low_count), str(len(findings))]
    ]
    breakdown_table = Table(breakdown_data, colWidths=[105, 105, 105, 105, 110])
    breakdown_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 9),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("BACKGROUND", (0, 1), (-1, 1), colors.HexColor("#f8fafc")),
        ("FONTNAME", (0, 1), (-1, 1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 1), (-1, 1), 13),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("PADDING", (0, 0), (-1, -1), 6)
    ]))
    elements.append(breakdown_table)
    elements.append(Spacer(1, 16))

    # Detailed Findings Section
    elements.append(Paragraph("2. Detailed Security Findings & Recommendations", section_h1))
    
    if not findings:
        elements.append(Paragraph("<b>No significant security configuration deficiencies detected.</b> Target adheres to assessed security baselines.", body_style))
    else:
        for idx, finding in enumerate(findings, 1):
            sev = finding.get("severity", "LOW")
            s_color = get_severity_color(sev)
            
            finding_content = [
                [
                    Paragraph(f"<b>#{idx} — {finding.get('title')}</b>", ParagraphStyle("FTitle", parent=styles["Normal"], fontName="Helvetica-Bold", fontSize=10, textColor=colors.HexColor("#0f172a"))),
                    Paragraph(f"<font color='{s_color.hexval()}'><b>[{sev}]</b></font> &nbsp; <font color='#64748b'>Category: {finding.get('category')}</font>", ParagraphStyle("FMeta", parent=styles["Normal"], alignment=2, fontSize=9))
                ],
                [
                    Paragraph(f"<b>Description:</b> {finding.get('description')}", body_style),
                    ""
                ],
                [
                    Paragraph(f"<b>Evidence:</b> <font name='Courier' size=8>{finding.get('evidence') or 'N/A'}</font>", body_style),
                    ""
                ],
                [
                    Paragraph(f"<b>Potential Impact:</b> {finding.get('impact') or 'Configuration deviation.'}", body_style),
                    ""
                ],
                [
                    Paragraph(f"<b>Remediation Guidance:</b> <font color='#0284c7'><b>{finding.get('recommendation') or 'Review standard hardening.'}</b></font>", body_style),
                    ""
                ]
            ]
            
            f_table = Table(finding_content, colWidths=[380, 150])
            f_table.setStyle(TableStyle([
                ("SPAN", (0, 1), (1, 1)),
                ("SPAN", (0, 2), (1, 2)),
                ("SPAN", (0, 3), (1, 3)),
                ("SPAN", (0, 4), (1, 4)),
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
                ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#ffffff")),
                ("PADDING", (0, 0), (-1, -1), 5),
                ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#e2e8f0")),
                ("LINEBELOW", (0, 0), (-1, 0), 1, colors.HexColor("#cbd5e1")),
            ]))
            
            elements.append(KeepTogether([f_table, Spacer(1, 8)]))

    elements.append(Spacer(1, 14))

    # Limitations & Legal Disclaimer
    elements.append(Paragraph("3. Scope Limitations & Assessment Methodology", section_h1))
    disclaimer_text = (
        "<b>Defensive Assessment Notice:</b> RISK CHECKER performs non-destructive configuration analysis strictly "
        "evaluating publicly exposed response headers, cryptographic certificate properties, and standard TCP service banners. "
        "Missing security headers and service accessibility flags represent configuration baselines and do not automatically prove "
        "exploitable vulnerability. This automated report does not substitute for authenticated code review or authorized manual penetration testing."
    )
    elements.append(Paragraph(disclaimer_text, ParagraphStyle("Disclaimer", parent=styles["Normal"], fontSize=8, leading=11, textColor=colors.HexColor("#64748b"))))

    # Build PDF
    doc.build(elements)
    return output_path
