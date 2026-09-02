from __future__ import annotations

import html
import json
import ipaddress
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from flask import Blueprint, jsonify, request, send_file

import settings
from models.database import get_db_connection
from services.geolocation import lookup_ioc_geolocation
from services.threat_intel import ThreatIntelAggregator


intelligence_reporting_bp = Blueprint(
    "intelligence_reporting_bp",
    __name__,
)


def _base_dir() -> Path:
    return Path(getattr(settings, "BASE_DIR", Path.cwd()))


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _table_exists(conn, table_name: str) -> bool:
    row = conn.execute(
        """
        SELECT name
        FROM sqlite_master
        WHERE type = 'table' AND name = ?
        """,
        (table_name,),
    ).fetchone()
    return row is not None


def _incident_record(incident_id: int) -> dict[str, Any] | None:
    conn = get_db_connection()
    try:
        row = conn.execute(
            "SELECT * FROM incidents WHERE id = ?",
            (incident_id,),
        ).fetchone()
        if not row:
            return None

        incident = dict(row)
        timeline: list[dict[str, Any]] = []
        comments: list[dict[str, Any]] = []
        executions: list[dict[str, Any]] = []

        if _table_exists(conn, "timeline_events"):
            timeline = [
                dict(item)
                for item in conn.execute(
                    """
                    SELECT *
                    FROM timeline_events
                    WHERE incident_id = ?
                    ORDER BY id ASC
                    """,
                    (incident_id,),
                ).fetchall()
            ]

        if _table_exists(conn, "comments"):
            comments = [
                dict(item)
                for item in conn.execute(
                    """
                    SELECT *
                    FROM comments
                    WHERE incident_id = ?
                    ORDER BY id ASC
                    """,
                    (incident_id,),
                ).fetchall()
            ]

        if _table_exists(conn, "playbook_executions"):
            executions = [
                dict(item)
                for item in conn.execute(
                    """
                    SELECT *
                    FROM playbook_executions
                    WHERE incident_id = ?
                    ORDER BY id DESC
                    """,
                    (incident_id,),
                ).fetchall()
            ]

        return {
            "incident": incident,
            "timeline": timeline,
            "comments": comments,
            "playbook_executions": executions,
        }
    finally:
        conn.close()


def _safe_analysis(value: str, ioc_type: str) -> dict[str, Any]:
    try:
        result = ThreatIntelAggregator.analyze_all(value, ioc_type)
        if isinstance(result, dict):
            return result
    except Exception as exc:
        return {
            "risk_score": 0,
            "severity": "UNKNOWN",
            "overall_status": "ERROR",
            "evidence_mode": "NONE",
            "coverage": 0,
            "recommendation": (
                "Threat-intelligence refresh failed during report generation."
            ),
            "sources": {},
            "report_error": f"{type(exc).__name__}: {exc}",
        }
    return {
        "risk_score": 0,
        "severity": "UNKNOWN",
        "overall_status": "UNAVAILABLE",
        "evidence_mode": "NONE",
        "coverage": 0,
        "recommendation": "No threat-intelligence result was available.",
        "sources": {},
    }



CHAT_IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
CHAT_DOMAIN_PATTERN = re.compile(
    r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,63}\b"
)
CHAT_HASH_PATTERN = re.compile(
    r"\b(?:[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})\b"
)


def _extract_chat_geolocation_target(message: str) -> tuple[str, str] | None:
    text = str(message or "").strip()
    if not text:
        return None

    for candidate in CHAT_IP_PATTERN.findall(text):
        try:
            parsed = ipaddress.ip_address(candidate)
        except ValueError:
            continue
        if parsed.version == 4:
            return candidate, "IP"

    for candidate in CHAT_DOMAIN_PATTERN.findall(text):
        try:
            ipaddress.ip_address(candidate)
            continue
        except ValueError:
            return candidate.lower().rstrip("."), "DOMAIN"

    if CHAT_HASH_PATTERN.search(text):
        return None

    return None


def _format_chat_geolocation(geolocation: dict[str, Any]) -> str:
    status = str(geolocation.get("status") or "UNAVAILABLE")
    ioc_type = str(geolocation.get("ioc_type") or "IOC")
    ioc_value = str(geolocation.get("ioc_value") or "-")
    locations = geolocation.get("locations") or []

    lines = [
        "🌍 **Geolocation & Network Context:**",
        f"• **Target:** `{ioc_value}` ({ioc_type})",
        f"• **Status:** {status}",
    ]

    usable = [
        item
        for item in locations
        if item.get("status") in {"LIVE", "CACHED"}
    ]

    if usable:
        for item in usable[:3]:
            place = ", ".join(
                str(part)
                for part in [
                    item.get("city"),
                    item.get("region"),
                    item.get("country"),
                ]
                if part
            ) or "Location not supplied"
            asn = item.get("asn")
            owner = item.get("organisation") or item.get("isp")
            network = " / ".join(
                part
                for part in [
                    f"AS{asn}" if asn else "",
                    str(owner or ""),
                ]
                if part
            ) or "Network owner not supplied"
            lines.append(
                f"• `{item.get('ip_address', '-')}` — {place} — {network} "
                f"[{item.get('status', '-')}]"
            )
    else:
        lines.append(
            f"• **Result:** {geolocation.get('message') or 'No approximate location was available.'}"
        )

    if ioc_type == "DOMAIN" and geolocation.get("resolved_ips"):
        lines.append(
            "• **Resolved public IPv4:** "
            + ", ".join(str(item) for item in geolocation["resolved_ips"][:3])
        )
        lines.append(
            "• **Domain note:** These are current hosting/CDN locations, not the "
            "registrant's physical location."
        )

    lines.append(
        "• **Accuracy note:** Approximate public-network infrastructure only; "
        "not person-level attribution or a street address."
    )
    return "\n".join(lines)


@intelligence_reporting_bp.after_app_request
def append_geolocation_to_analyst_chat(response):
    """Append scoped geolocation context to successful analyst-chat answers."""
    if request.path != "/api/chat" or request.method != "POST":
        return response
    if response.status_code >= 400 or not response.is_json:
        return response

    request_data = request.get_json(silent=True) or {}
    target = _extract_chat_geolocation_target(request_data.get("message", ""))
    if not target:
        return response

    value, ioc_type = target
    geolocation = lookup_ioc_geolocation(value, ioc_type)
    formatted = _format_chat_geolocation(geolocation)

    response_data = response.get_json(silent=True)
    if not isinstance(response_data, dict):
        return response

    existing = str(
        response_data.get("response")
        or response_data.get("reply")
        or response_data.get("message")
        or ""
    ).strip()

    if "Geolocation & Network Context" not in existing:
        response_data["response"] = (
            f"{existing}\n\n{formatted}" if existing else formatted
        )
    response_data["geolocation"] = geolocation

    response.set_data(json.dumps(response_data, default=str))
    response.headers["Content-Type"] = "application/json"
    response.headers["Content-Length"] = str(len(response.get_data()))
    return response

def _source_items(analysis: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    sources = analysis.get("sources") or analysis.get("provider_results") or {}
    if isinstance(sources, list):
        output = []
        for index, item in enumerate(sources):
            if not isinstance(item, dict):
                continue
            name = str(item.get("source") or item.get("name") or f"Source {index + 1}")
            output.append((name, item))
        return output
    if isinstance(sources, dict):
        return [
            (str(name), value if isinstance(value, dict) else {"value": value})
            for name, value in sources.items()
        ]
    return []


def _paragraph_text(value: Any) -> str:
    return html.escape(str(value if value is not None else "-"))


def _short_json(value: Any, limit: int = 1800) -> str:
    try:
        text = json.dumps(value, indent=2, sort_keys=True, default=str)
    except TypeError:
        text = str(value)
    if len(text) > limit:
        return text[:limit] + "\n... output truncated ..."
    return text


def _comment_text(comment: dict[str, Any]) -> str:
    return str(
        comment.get("comment")
        or comment.get("comment_text")
        or comment.get("content")
        or ""
    )


def _executive_summary(
    incident: dict[str, Any],
    analysis: dict[str, Any],
    geolocation: dict[str, Any],
) -> str:
    ioc_type = str(incident.get("ioc_type") or "UNKNOWN").upper()
    ioc_value = str(incident.get("ioc_value") or "-")
    status = str(incident.get("status") or "UNKNOWN")
    severity = str(analysis.get("severity") or incident.get("severity") or "UNKNOWN")
    risk = analysis.get("risk_score", incident.get("risk_score", 0))
    evidence = str(analysis.get("evidence_mode") or "NONE")
    geo_status = str(geolocation.get("status") or "NOT_APPLICABLE")

    return (
        f"Incident #{incident.get('id')} concerns the {ioc_type} indicator "
        f"{ioc_value}. The incident is currently {status}. Current intelligence "
        f"assessment assigns severity {severity} with an aggregated risk score "
        f"of {risk}/100 and evidence mode {evidence}. Geolocation status is "
        f"{geo_status}. Geolocation describes approximate network infrastructure "
        f"only and is not person-level attribution."
    )


def _recommendations(
    incident: dict[str, Any],
    analysis: dict[str, Any],
) -> list[str]:
    ioc_type = str(incident.get("ioc_type") or "").upper()
    severity = str(analysis.get("severity") or incident.get("severity") or "LOW").upper()
    items: list[str] = []

    supplied = str(analysis.get("recommendation") or "").strip()
    if supplied:
        items.append(supplied)

    if ioc_type == "IP":
        if severity in {"HIGH", "CRITICAL"}:
            items.append(
                "Review analyst approval and apply UFW containment only when the "
                "IP is validated, not allow-listed, and operational impact is acceptable."
            )
        else:
            items.append(
                "Continue monitoring and enrich the IP before containment unless "
                "additional incident evidence justifies escalation."
            )
    elif ioc_type == "DOMAIN":
        items.append(
            "Review resolved addresses, DNS history and shared-hosting risk before "
            "any network-level response. Prefer DNS or proxy controls for domain policy."
        )
    elif ioc_type == "HASH":
        items.append(
            "Use endpoint detection, quarantine and file-removal controls. UFW "
            "cannot enforce a cryptographic file hash."
        )

    items.append(
        "Preserve provider status, analyst decisions, timeline events and "
        "containment outcomes as auditable incident evidence."
    )
    return items


def _generate_report(
    incident_id: int,
    *,
    threat_analysis: dict[str, Any] | None = None,
    geolocation: dict[str, Any] | None = None,
) -> Path:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        BaseDocTemplate,
        Frame,
        PageBreak,
        PageTemplate,
        Paragraph,
        Spacer,
        Table,
        TableStyle,
    )
    from reportlab.platypus.tableofcontents import TableOfContents

    record = _incident_record(incident_id)
    if not record:
        raise ValueError(f"Incident #{incident_id} was not found.")

    incident = record["incident"]
    ioc_value = str(incident.get("ioc_value") or "")
    ioc_type = str(incident.get("ioc_type") or "UNKNOWN").upper()
    analysis = threat_analysis or _safe_analysis(ioc_value, ioc_type)
    geo = geolocation or lookup_ioc_geolocation(ioc_value, ioc_type)

    report_dir = _base_dir() / "reports"
    report_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    path = report_dir / (
        f"SOAR_Incident_Intelligence_Response_{incident_id}_{timestamp}.pdf"
    )

    styles = getSampleStyleSheet()
    styles.add(
        ParagraphStyle(
            name="ReportTitle",
            parent=styles["Title"],
            fontName="Helvetica-Bold",
            fontSize=23,
            leading=29,
            textColor=colors.HexColor("#0f2942"),
            alignment=TA_CENTER,
            spaceAfter=12,
        )
    )
    styles.add(
        ParagraphStyle(
            name="ReportSubtitle",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=11,
            leading=16,
            textColor=colors.HexColor("#355b75"),
            alignment=TA_CENTER,
            spaceAfter=8,
        )
    )
    styles.add(
        ParagraphStyle(
            name="SectionHeading",
            parent=styles["Heading1"],
            fontName="Helvetica-Bold",
            fontSize=15,
            leading=19,
            textColor=colors.HexColor("#164e6f"),
            spaceBefore=14,
            spaceAfter=8,
            keepWithNext=True,
        )
    )
    styles.add(
        ParagraphStyle(
            name="SubHeading",
            parent=styles["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=11,
            leading=14,
            textColor=colors.HexColor("#245b78"),
            spaceBefore=9,
            spaceAfter=5,
            keepWithNext=True,
        )
    )
    styles.add(
        ParagraphStyle(
            name="ReportBody",
            parent=styles["BodyText"],
            fontName="Helvetica",
            fontSize=8.8,
            leading=12.5,
            textColor=colors.HexColor("#253746"),
            spaceAfter=6,
        )
    )
    styles.add(
        ParagraphStyle(
            name="Small",
            parent=styles["BodyText"],
            fontName="Helvetica",
            fontSize=7.4,
            leading=10,
            textColor=colors.HexColor("#475569"),
        )
    )
    styles.add(
        ParagraphStyle(
            name="Mono",
            parent=styles["Code"],
            fontName="Courier",
            fontSize=7.0,
            leading=9.0,
            textColor=colors.HexColor("#1e293b"),
            wordWrap="CJK",
        )
    )
    styles.add(
        ParagraphStyle(
            name="Notice",
            parent=styles["BodyText"],
            fontName="Helvetica",
            fontSize=8.5,
            leading=12,
            textColor=colors.HexColor("#7f1d1d"),
            backColor=colors.HexColor("#fff1f2"),
            borderColor=colors.HexColor("#fecdd3"),
            borderWidth=0.7,
            borderPadding=8,
            spaceAfter=8,
        )
    )

    class ReportDocTemplate(BaseDocTemplate):
        def __init__(self, filename: str):
            super().__init__(
                filename,
                pagesize=A4,
                rightMargin=16 * mm,
                leftMargin=16 * mm,
                topMargin=18 * mm,
                bottomMargin=16 * mm,
                title="SOAR Incident Intelligence and Response Report",
                author="Intent-Based SOAR Prototype",
                subject=f"Incident #{incident_id}",
            )
            frame = Frame(
                self.leftMargin,
                self.bottomMargin,
                self.width,
                self.height,
                id="normal",
            )
            self.addPageTemplates(
                [
                    PageTemplate(
                        id="content",
                        frames=frame,
                        onPage=self._draw_page,
                    )
                ]
            )

        def _draw_page(self, canvas, doc):
            canvas.saveState()
            page_number = canvas.getPageNumber()
            canvas.setStrokeColor(colors.HexColor("#cbd5e1"))
            canvas.setLineWidth(0.45)
            canvas.line(
                16 * mm,
                A4[1] - 12 * mm,
                A4[0] - 16 * mm,
                A4[1] - 12 * mm,
            )
            canvas.setFont("Helvetica", 7)
            canvas.setFillColor(colors.HexColor("#64748b"))
            canvas.drawString(
                16 * mm,
                9 * mm,
                "CONFIDENTIAL - MSc SOAR research prototype",
            )
            canvas.drawRightString(
                A4[0] - 16 * mm,
                9 * mm,
                f"Page {page_number}",
            )
            canvas.restoreState()

        def afterFlowable(self, flowable):
            if isinstance(flowable, Paragraph):
                style_name = flowable.style.name
                if style_name in {"SectionHeading", "SubHeading"}:
                    level = 0 if style_name == "SectionHeading" else 1
                    text = flowable.getPlainText()
                    key = f"heading-{level}-{self.page}-{abs(hash(text))}"
                    self.canv.bookmarkPage(key)
                    self.canv.addOutlineEntry(text, key, level=level, closed=False)
                    self.notify("TOCEntry", (level, text, self.page, key))

    doc = ReportDocTemplate(str(path))

    def P(text: Any, style: str = "ReportBody") -> Paragraph:
        return Paragraph(_paragraph_text(text), styles[style])

    def heading(text: str) -> Paragraph:
        return Paragraph(text, styles["SectionHeading"])

    def subheading(text: str) -> Paragraph:
        return Paragraph(text, styles["SubHeading"])

    def json_paragraph(value: Any, limit: int) -> Paragraph:
        encoded = html.escape(_short_json(value, limit)).replace("\n", "<br/>")
        return Paragraph(encoded, styles["Mono"])

    def table(
        rows: list[list[Any]],
        widths: list[float] | None = None,
        repeat_rows: int = 1,
    ) -> Table:
        converted: list[list[Any]] = []
        for row in rows:
            converted_row = []
            for cell in row:
                if isinstance(cell, Paragraph):
                    converted_row.append(cell)
                else:
                    converted_row.append(P(cell, "Small"))
            converted.append(converted_row)

        result = Table(
            converted,
            colWidths=widths,
            repeatRows=repeat_rows,
            hAlign="LEFT",
        )
        result.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#164e6f")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#cbd5e1")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [
                        colors.white,
                        colors.HexColor("#f8fafc"),
                    ]),
                    ("LEFTPADDING", (0, 0), (-1, -1), 5),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ]
            )
        )
        return result

    story: list[Any] = []

    story.extend(
        [
            Spacer(1, 36 * mm),
            Paragraph(
                "SOAR Incident Intelligence and Response Report",
                styles["ReportTitle"],
            ),
            Paragraph(
                "Intent-Based Analysis, Threat-Intelligence Enrichment, "
                "Geolocation Context, Analyst-Approved Playbooks and UFW Response",
                styles["ReportSubtitle"],
            ),
            Spacer(1, 12 * mm),
            table(
                [
                    ["Report field", "Value"],
                    ["Incident ID", incident_id],
                    ["Incident title", incident.get("title", "-")],
                    ["Indicator", ioc_value or "-"],
                    ["Indicator type", ioc_type],
                    ["Classification", "CONFIDENTIAL - Research and assessment use"],
                    ["Generated", _utc_now()],
                ],
                [48 * mm, 122 * mm],
            ),
            Spacer(1, 14 * mm),
            Paragraph(
                "This document is generated by the Intent-Based SOAR Prototype "
                "Using Rasa NLP for Intelligent Incident Response.",
                styles["ReportSubtitle"],
            ),
            PageBreak(),
        ]
    )

    story.extend(
        [
            heading("1. Confidentiality and Usage Notice"),
            Paragraph(
                "This report contains security-operational information generated "
                "for authorised research, assessment and incident-response use. "
                "Threat-intelligence results may be incomplete, unavailable, "
                "rate-limited or time-sensitive. Do not treat the document as "
                "legal attribution or as proof of a person's identity or location.",
                styles["Notice"],
            ),
            heading("2. Table of Contents"),
        ]
    )

    toc = TableOfContents()
    toc.levelStyles = [
        ParagraphStyle(
            name="TOCLevel1",
            fontName="Helvetica-Bold",
            fontSize=10,
            leading=14,
            leftIndent=0,
            firstLineIndent=0,
            textColor=colors.HexColor("#164e6f"),
            spaceBefore=3,
        ),
        ParagraphStyle(
            name="TOCLevel2",
            fontName="Helvetica",
            fontSize=9,
            leading=12,
            leftIndent=13,
            firstLineIndent=0,
            textColor=colors.HexColor("#355b75"),
        ),
    ]
    story.extend([toc, PageBreak()])

    story.extend(
        [
            heading("3. Executive Summary"),
            P(_executive_summary(incident, analysis, geo)),
            subheading("3.1 Primary assessment"),
            P(
                analysis.get("recommendation")
                or "No provider-generated recommendation was available."
            ),
            heading("4. Incident and IOC Profile"),
            subheading("4.1 Incident details"),
            table(
                [
                    ["Field", "Value", "Field", "Value"],
                    ["Incident ID", incident.get("id"), "Status", incident.get("status")],
                    ["Title", incident.get("title"), "Severity", incident.get("severity")],
                    ["IOC", ioc_value or "-", "IOC type", ioc_type],
                    [
                        "Risk score",
                        incident.get("risk_score"),
                        "Assigned analyst",
                        incident.get("assigned_analyst", "ANALYST"),
                    ],
                    [
                        "Created",
                        incident.get("created_at", "-"),
                        "Updated",
                        incident.get("updated_at", "-"),
                    ],
                ],
                [30 * mm, 57 * mm, 30 * mm, 57 * mm],
            ),
            subheading("4.2 Description and detection source"),
            P(incident.get("description") or "No incident description was recorded."),
            P(
                "Detection/assignment source: "
                + str(incident.get("assigned_analyst") or "ANALYST")
            ),
            heading("5. Threat Intelligence Assessment"),
            subheading("5.1 Aggregated assessment"),
            table(
                [
                    ["Metric", "Value"],
                    ["Overall status", analysis.get("overall_status", "UNAVAILABLE")],
                    ["Evidence mode", analysis.get("evidence_mode", "NONE")],
                    ["Provider coverage", analysis.get("coverage", 0)],
                    [
                        "Risk score",
                        analysis.get("risk_score", incident.get("risk_score", 0)),
                    ],
                    [
                        "Severity",
                        analysis.get("severity", incident.get("severity", "UNKNOWN")),
                    ],
                ],
                [58 * mm, 112 * mm],
            ),
            subheading("5.2 Provider coverage and detection results"),
        ]
    )

    provider_rows = [["Provider", "Status", "Verdict / score", "Important evidence"]]
    source_items = _source_items(analysis)
    for name, source in source_items:
        status = source.get("status") or source.get("source_status") or "-"
        verdict = (
            source.get("verdict")
            or source.get("risk_score")
            or source.get("score")
            or "-"
        )
        evidence = (
            source.get("message")
            or source.get("summary")
            or source.get("details")
            or source.get("data")
            or source
        )
        provider_rows.append(
            [
                name,
                status,
                verdict,
                Paragraph(
                    html.escape(_short_json(evidence, 650)).replace("\n", "<br/>"),
                    styles["Small"],
                ),
            ]
        )
    if len(provider_rows) == 1:
        provider_rows.append(
            ["No provider data", "-", "-", "No source results were available."]
        )
    story.append(
        table(
            provider_rows,
            [31 * mm, 26 * mm, 31 * mm, 86 * mm],
        )
    )

    if ioc_type != "IP":
        story.extend(
            [
                subheading("5.3 AbuseIPDB applicability"),
                P(
                    "AbuseIPDB is an IP-reputation source. It is not applicable "
                    f"to this {ioc_type} indicator unless a separate resolved IP "
                    "is investigated."
                ),
            ]
        )

    story.extend(
        [
            heading("6. Geolocation, ASN and Hosting Assessment"),
            Paragraph(
                str(geo.get("accuracy_notice") or ""),
                styles["Notice"],
            ),
            P(geo.get("message") or "No geolocation message was available."),
        ]
    )

    geo_rows = [
        [
            "IP",
            "Status",
            "Country",
            "Region / city",
            "ASN",
            "Organisation / ISP",
            "Coordinates",
        ]
    ]
    for location in geo.get("locations", []):
        coordinates = "-"
        if location.get("latitude") is not None and location.get("longitude") is not None:
            coordinates = f"{location.get('latitude')}, {location.get('longitude')}"
        geo_rows.append(
            [
                location.get("ip_address", "-"),
                location.get("status", "-"),
                " / ".join(
                    part
                    for part in [
                        str(location.get("country") or ""),
                        str(location.get("country_code") or ""),
                    ]
                    if part
                )
                or "-",
                " / ".join(
                    part
                    for part in [
                        str(location.get("region") or ""),
                        str(location.get("city") or ""),
                    ]
                    if part
                )
                or "-",
                location.get("asn") or "-",
                location.get("organisation") or location.get("isp") or "-",
                coordinates,
            ]
        )
    if len(geo_rows) == 1:
        geo_rows.append(
            [
                ioc_value or "-",
                geo.get("status", "NOT_APPLICABLE"),
                "-",
                "-",
                "-",
                "-",
                "-",
            ]
        )
    story.append(
        table(
            geo_rows,
            [
                27 * mm,
                21 * mm,
                28 * mm,
                34 * mm,
                18 * mm,
                35 * mm,
                26 * mm,
            ],
        )
    )

    if ioc_type == "DOMAIN":
        story.extend(
            [
                subheading("6.1 Domain infrastructure interpretation"),
                P(
                    "The reported locations correspond to the domain's currently "
                    "resolved public IPv4 addresses. CDN, anycast, shared hosting, "
                    "load balancing and DNS changes can produce multiple or changing "
                    "locations. These results do not establish the domain owner's "
                    "physical location."
                ),
            ]
        )
    elif ioc_type == "HASH":
        story.extend(
            [
                subheading("6.1 Applicability"),
                P(
                    "A cryptographic hash does not identify a network endpoint, so "
                    "geolocation and ASN data are not applicable."
                ),
            ]
        )

    source_counts = analysis.get("source_status_counts") or {}
    story.extend(
        [
            heading("7. Assessment Confidence and Evidence Quality"),
            table(
                [
                    ["Confidence factor", "Observed value"],
                    ["Threat-intelligence evidence mode", analysis.get("evidence_mode", "NONE")],
                    ["Threat-intelligence overall status", analysis.get("overall_status", "UNAVAILABLE")],
                    ["Responding-source coverage", analysis.get("coverage", 0)],
                    ["Source status counts", _short_json(source_counts, 400)],
                    ["Geolocation status", geo.get("status", "NOT_APPLICABLE")],
                    ["Geolocation lookup time", geo.get("retrieved_at", "-")],
                ],
                [65 * mm, 105 * mm],
            ),
            P(
                "Confidence is reduced when providers are unavailable, return errors, "
                "use simulation data, or do not support the IOC type. Geolocation is "
                "contextual infrastructure evidence and is not used as standalone "
                "proof of maliciousness."
            ),
            heading("8. Risk Classification and Scoring"),
            table(
                [
                    ["Risk field", "Value"],
                    [
                        "Aggregated intelligence score",
                        analysis.get("risk_score", incident.get("risk_score", 0)),
                    ],
                    [
                        "Aggregated severity",
                        analysis.get("severity", incident.get("severity", "UNKNOWN")),
                    ],
                    ["Stored incident score", incident.get("risk_score", 0)],
                    ["Stored incident severity", incident.get("severity", "UNKNOWN")],
                ],
                [72 * mm, 98 * mm],
            ),
            subheading("8.1 Decision-support interpretation"),
            P(
                analysis.get("recommendation")
                or "Analyst review is required before response."
            ),
            heading("9. Incident Investigation Timeline"),
        ]
    )

    timeline_rows = [["Time", "Actor", "Event"]]
    for event in record["timeline"]:
        timeline_rows.append(
            [
                event.get("timestamp", "-"),
                event.get("action_by", "-"),
                event.get("action_description", "-"),
            ]
        )
    if len(timeline_rows) == 1:
        timeline_rows.append(["-", "-", "No timeline events were recorded."])
    story.append(
        table(
            timeline_rows,
            [34 * mm, 31 * mm, 105 * mm],
        )
    )

    story.append(subheading("9.1 Analyst comments"))
    comment_rows = [["Time", "Author", "Comment"]]
    for comment in record["comments"]:
        comment_rows.append(
            [
                comment.get("created_at", "-"),
                comment.get("comment_by")
                or comment.get("author")
                or comment.get("username")
                or "ANALYST",
                _comment_text(comment),
            ]
        )
    if len(comment_rows) == 1:
        comment_rows.append(["-", "-", "No analyst comments were recorded."])
    story.append(
        table(
            comment_rows,
            [34 * mm, 31 * mm, 105 * mm],
        )
    )

    story.append(heading("10. Playbook Execution and Containment"))
    execution_rows = [
        [
            "ID",
            "Status",
            "Mode",
            "Approval",
            "Containment",
            "Risk",
            "Completed",
        ]
    ]
    for execution in record["playbook_executions"]:
        execution_rows.append(
            [
                execution.get("id", "-"),
                execution.get("status", "-"),
                execution.get("execution_mode", "-"),
                execution.get("approval_status", "-"),
                execution.get("containment_status", "-"),
                execution.get("risk_score", "-"),
                execution.get("completed_at", "-"),
            ]
        )
    if len(execution_rows) == 1:
        execution_rows.append(
            ["-", "-", "-", "-", "No execution recorded", "-", "-"]
        )
    story.append(
        table(
            execution_rows,
            [
                12 * mm,
                22 * mm,
                22 * mm,
                26 * mm,
                31 * mm,
                17 * mm,
                40 * mm,
            ],
        )
    )
    story.extend(
        [
            subheading("10.1 Containment scope"),
            P(
                "UFW containment is applicable to validated IPv4 indicators. "
                "Domain controls require DNS and shared-infrastructure review. "
                "File hashes require endpoint security controls rather than a "
                "Layer 3/4 firewall."
            ),
            heading("11. Infrastructure and IOC Summary"),
            table(
                [
                    ["Infrastructure field", "Value"],
                    ["IOC", ioc_value or "-"],
                    ["IOC type", ioc_type],
                    ["Current resolved public IPs", ", ".join(geo.get("resolved_ips", [])) or "-"],
                    [
                        "Observed ASN(s)",
                        ", ".join(
                            str(item.get("asn"))
                            for item in geo.get("locations", [])
                            if item.get("asn")
                        )
                        or "-",
                    ],
                    [
                        "Observed organisation(s)",
                        ", ".join(
                            str(item.get("organisation") or item.get("isp"))
                            for item in geo.get("locations", [])
                            if item.get("organisation") or item.get("isp")
                        )
                        or "-",
                    ],
                ],
                [67 * mm, 103 * mm],
            ),
            heading("12. Recommended Actions and Escalation"),
        ]
    )

    for item in _recommendations(incident, analysis):
        story.append(P(f"- {item}"))

    story.extend(
        [
            heading("13. Security Governance and Audit Evidence"),
            P(
                "The prototype separates investigation from containment, records "
                "analyst approval or rejection, validates IOC type and policy, and "
                "records significant actions in incident timelines and audit logs. "
                "Live UFW actions must be explicitly confirmed."
            ),
            table(
                [
                    ["Governance control", "Report evidence"],
                    [
                        "Human approval",
                        "Playbook approval status and execution history",
                    ],
                    [
                        "Traceability",
                        "Incident timeline, comments and generated timestamp",
                    ],
                    [
                        "Containment verification",
                        "UFW execution and containment status",
                    ],
                    [
                        "Evidence transparency",
                        "LIVE, SIMULATED, UNAVAILABLE and ERROR source states",
                    ],
                    [
                        "Geolocation safety",
                        "Approximate infrastructure context; no person-level attribution",
                    ],
                ],
                [62 * mm, 108 * mm],
            ),
            heading("14. Technical Appendix"),
            subheading("14.1 Raw threat-intelligence summary"),
            json_paragraph(analysis, 6000),
            subheading("14.2 Raw geolocation summary"),
            json_paragraph(geo, 5000),
            subheading("14.3 System and report metadata"),
            table(
                [
                    ["Metadata", "Value"],
                    ["Generated", _utc_now()],
                    ["Threat-intelligence mode", analysis.get("evidence_mode", "NONE")],
                    ["Geolocation source", "IPWhois.io free endpoint where applicable"],
                    ["Report generator", "ReportLab structured incident report v2"],
                    ["Project", "Intent-Based SOAR Prototype Using Rasa NLP"],
                ],
                [61 * mm, 109 * mm],
            ),
            heading("15. Conclusion"),
            P(
                f"Incident #{incident_id} has been documented with its IOC profile, "
                "current threat-intelligence assessment, approximate infrastructure "
                "geolocation where applicable, risk classification, analyst activity, "
                "playbook history and containment evidence. The report supports "
                "decision-making and auditability but does not replace analyst "
                "verification, provider-specific investigation or legal attribution."
            ),
        ]
    )

    doc.multiBuild(story)
    return path


@intelligence_reporting_bp.route(
    "/api/intelligence/geolocation",
    methods=["GET"],
)
def geolocation_lookup():
    value = str(request.args.get("value") or "").strip()
    ioc_type = str(request.args.get("ioc_type") or "AUTO").upper().strip()
    force = str(request.args.get("force") or "").lower() in {"1", "true", "yes"}

    if not value:
        return jsonify(
            {"status": "error", "message": "An IOC value is required."}
        ), 400

    if ioc_type == "AUTO":
        try:
            import ipaddress
            ipaddress.ip_address(value)
            ioc_type = "IP"
        except ValueError:
            if "." in value and " " not in value:
                ioc_type = "DOMAIN"
            else:
                ioc_type = "HASH"

    result = lookup_ioc_geolocation(
        value,
        ioc_type,
        force_refresh=force,
    )
    return jsonify({"status": "success", "geolocation": result})


@intelligence_reporting_bp.route(
    "/api/intelligence/incidents/<int:incident_id>/geolocation",
    methods=["GET"],
)
def incident_geolocation(incident_id: int):
    record = _incident_record(incident_id)
    if not record:
        return jsonify(
            {
                "status": "error",
                "message": f"Incident #{incident_id} was not found.",
            }
        ), 404

    incident = record["incident"]
    result = lookup_ioc_geolocation(
        str(incident.get("ioc_value") or ""),
        str(incident.get("ioc_type") or "UNKNOWN"),
        force_refresh=str(request.args.get("force") or "").lower()
        in {"1", "true", "yes"},
    )
    return jsonify(
        {
            "status": "success",
            "incident_id": incident_id,
            "geolocation": result,
        }
    )


@intelligence_reporting_bp.route(
    "/api/intelligence/incidents/<int:incident_id>/report-preview",
    methods=["GET"],
)
def report_preview(incident_id: int):
    record = _incident_record(incident_id)
    if not record:
        return jsonify(
            {
                "status": "error",
                "message": f"Incident #{incident_id} was not found.",
            }
        ), 404

    incident = record["incident"]
    analysis = _safe_analysis(
        str(incident.get("ioc_value") or ""),
        str(incident.get("ioc_type") or "UNKNOWN"),
    )
    geo = lookup_ioc_geolocation(
        str(incident.get("ioc_value") or ""),
        str(incident.get("ioc_type") or "UNKNOWN"),
    )
    return jsonify(
        {
            "status": "success",
            "incident": incident,
            "threat_intelligence": analysis,
            "geolocation": geo,
            "sections": [
                "Confidentiality and Usage Notice",
                "Table of Contents",
                "Executive Summary",
                "Incident and IOC Profile",
                "Threat Intelligence Assessment",
                "Geolocation, ASN and Hosting Assessment",
                "Assessment Confidence and Evidence Quality",
                "Risk Classification and Scoring",
                "Incident Investigation Timeline",
                "Playbook Execution and Containment",
                "Infrastructure and IOC Summary",
                "Recommended Actions and Escalation",
                "Security Governance and Audit Evidence",
                "Technical Appendix",
                "Conclusion",
            ],
        }
    )


@intelligence_reporting_bp.route(
    "/api/intelligence/reports/incident/<int:incident_id>",
    methods=["GET"],
)
def download_intelligence_incident_report(incident_id: int):
    try:
        path = _generate_report(incident_id)
    except ValueError as exc:
        return jsonify({"status": "error", "message": str(exc)}), 404
    except Exception as exc:
        return jsonify(
            {
                "status": "error",
                "message": (
                    "The structured incident report could not be generated: "
                    f"{type(exc).__name__}: {exc}"
                ),
            }
        ), 500

    return send_file(
        path,
        as_attachment=True,
        download_name=path.name,
        mimetype="application/pdf",
        max_age=0,
    )
