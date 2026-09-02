from __future__ import annotations

import ipaddress
import json
import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests
from flask import Blueprint, current_app, jsonify, request, send_file, render_template

import audit_logger
import settings
from models.database import get_db_connection
from services.threat_intel import ThreatIntelAggregator
from soar_engine import execute_kernel_block, execute_kernel_unblock


supervisor_demo_bp = Blueprint("supervisor_demo_bp", __name__)

VALID_IOC_TYPES = {"IP", "DOMAIN", "HASH"}
VALID_INCIDENT_STATUSES = {"OPEN", "INVESTIGATING", "CONTAINED", "CLOSED"}
VALID_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
HASH_LENGTHS = {32, 40, 64}
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,63}$"
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _base_dir() -> Path:
    value = getattr(settings, "BASE_DIR", Path.cwd())
    return Path(value)


def _json_error(message: str, status_code: int = 400):
    return jsonify({"status": "error", "message": message}), status_code


def _table_columns(conn, table_name: str) -> set[str]:
    try:
        rows = conn.execute(f"PRAGMA table_info({table_name})").fetchall()
    except Exception:
        return set()
    return {row["name"] for row in rows}


def _table_exists(conn, table_name: str) -> bool:
    row = conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?",
        (table_name,),
    ).fetchone()
    return row is not None


def _insert_dynamic(conn, table_name: str, values: dict[str, Any]) -> int:
    columns = _table_columns(conn, table_name)
    filtered = {key: value for key, value in values.items() if key in columns}
    if not filtered:
        raise RuntimeError(f"No compatible columns found for {table_name}.")
    names = list(filtered)
    placeholders = ", ".join("?" for _ in names)
    sql = f"INSERT INTO {table_name} ({', '.join(names)}) VALUES ({placeholders})"
    cursor = conn.execute(sql, tuple(filtered[name] for name in names))
    return int(cursor.lastrowid)


def _add_timeline(conn, incident_id: int, description: str, actor: str = "ANALYST") -> None:
    if not _table_exists(conn, "timeline_events"):
        return
    _insert_dynamic(
        conn,
        "timeline_events",
        {
            "incident_id": incident_id,
            "action_by": actor,
            "action_description": description,
            "timestamp": _utc_now(),
        },
    )


def _detect_ioc_type(value: str) -> str:
    candidate = value.strip()
    try:
        ipaddress.ip_address(candidate)
        return "IP"
    except ValueError:
        pass

    compact = candidate.lower()
    if len(compact) in HASH_LENGTHS and re.fullmatch(r"[a-f0-9]+", compact):
        return "HASH"
    if DOMAIN_RE.fullmatch(candidate):
        return "DOMAIN"
    return "UNKNOWN"


def _normalise_ioc(value: str, requested_type: str = "AUTO") -> tuple[str, str]:
    candidate = str(value or "").strip()
    if not candidate:
        raise ValueError("An IOC value is required.")

    ioc_type = requested_type.upper().strip() if requested_type else "AUTO"
    if ioc_type == "AUTO":
        ioc_type = _detect_ioc_type(candidate)
    if ioc_type not in VALID_IOC_TYPES:
        raise ValueError("The value is not a valid IP address, domain, or supported hash.")

    if ioc_type == "IP":
        try:
            parsed = ipaddress.ip_address(candidate)
        except ValueError as exc:
            raise ValueError("The IP address is invalid.") from exc
        if parsed.version != 4:
            raise ValueError("This prototype currently supports IPv4 containment only.")
        candidate = str(parsed)
    elif ioc_type == "HASH":
        candidate = candidate.lower()
        if len(candidate) not in HASH_LENGTHS or not re.fullmatch(r"[a-f0-9]+", candidate):
            raise ValueError("The hash must be MD5, SHA-1, or SHA-256 hexadecimal text.")
    elif ioc_type == "DOMAIN":
        candidate = candidate.lower().rstrip(".")
        if not DOMAIN_RE.fullmatch(candidate):
            raise ValueError("The domain name is invalid.")

    return candidate, ioc_type


def _containment_capability(ioc_type: str) -> dict[str, str | bool]:
    if ioc_type == "IP":
        return {
            "supported": True,
            "control": "UFW IPv4 deny rule",
            "message": "The incident can be contained directly after explicit analyst approval.",
        }
    if ioc_type == "DOMAIN":
        return {
            "supported": False,
            "control": "DNS resolution review required",
            "message": "Direct dashboard containment is restricted because domains may resolve to shared or changing IP addresses.",
        }
    return {
        "supported": False,
        "control": "Endpoint control required",
        "message": "A file hash cannot be enforced by a Layer 3/4 network firewall.",
    }


def _provider_configuration() -> dict[str, bool]:
    return {
        "virustotal": bool(getattr(settings, "VIRUSTOTAL_API_KEY", "")),
        "abuseipdb": bool(getattr(settings, "ABUSEIPDB_API_KEY", "")),
        "alienvault_otx": bool(getattr(settings, "ALIENVAULT_OTX_API_KEY", "")),
        "threatfox": True,
    }


def _rasa_base_url() -> str:
    configured = str(
        getattr(settings, "RASA_REST_URL", "http://127.0.0.1:5005/webhooks/rest/webhook")
    )
    if "/webhooks/" in configured:
        return configured.split("/webhooks/", 1)[0]
    return configured.rstrip("/")


def _http_health(url: str, timeout: float = 1.5) -> dict[str, Any]:
    try:
        response = requests.get(url, timeout=timeout)
        return {
            "ok": response.status_code < 500,
            "status_code": response.status_code,
            "message": "reachable" if response.status_code < 500 else "server error",
        }
    except Exception as exc:
        return {"ok": False, "status_code": None, "message": str(exc)}


def _ufw_status() -> dict[str, Any]:
    ufw_path = shutil.which("ufw")
    if not ufw_path:
        return {"ok": False, "output": "The ufw executable was not found.", "returncode": None}

    commands = [
        ["sudo", "-n", ufw_path, "status", "numbered"],
        [ufw_path, "status", "numbered"],
    ]
    last_error = "UFW status could not be read."
    for command in commands:
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
        except Exception as exc:
            last_error = str(exc)
            continue
        output = (result.stdout or result.stderr or "").strip()
        if result.returncode == 0:
            return {"ok": True, "output": output, "returncode": result.returncode}
        last_error = output or f"Command returned {result.returncode}."

    return {"ok": False, "output": last_error, "returncode": None}


def _latest_evaluation_files() -> dict[str, Path]:
    root = _base_dir()
    candidates: list[Path] = []
    for folder_name in ("evaluations", "results"):
        folder = root / folder_name
        if folder.is_dir():
            candidates.extend(folder.rglob("intent_report.json"))
            candidates.extend(folder.rglob("DIETClassifier_report.json"))

    if not candidates:
        return {}

    report_path = max(candidates, key=lambda item: item.stat().st_mtime)
    directory = report_path.parent

    def first_existing(*names: str) -> Path | None:
        for name in names:
            path = directory / name
            if path.is_file():
                return path
        return None

    mapping: dict[str, Path] = {"report": report_path}
    optional = {
        "confusion": first_existing("intent_confusion_matrix.png", "DIETClassifier_confusion_matrix.png"),
        "histogram": first_existing("intent_histogram.png", "DIETClassifier_histogram.png"),
        "errors": first_existing("intent_errors.json", "DIETClassifier_errors.json"),
    }
    mapping.update({key: value for key, value in optional.items() if value is not None})
    return mapping


def _read_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def _evaluation_payload() -> dict[str, Any]:
    files = _latest_evaluation_files()
    if not files:
        return {
            "available": False,
            "message": "No saved Rasa evaluation report was found in evaluations/ or results/.",
            "metrics": {},
            "artifacts": {},
        }

    report = _read_json(files["report"], {})
    macro = report.get("macro avg", {}) if isinstance(report, dict) else {}
    weighted = report.get("weighted avg", {}) if isinstance(report, dict) else {}
    accuracy_value = report.get("accuracy") if isinstance(report, dict) else None
    if isinstance(accuracy_value, dict):
        accuracy_value = accuracy_value.get("f1-score") or accuracy_value.get("precision")

    errors = _read_json(files.get("errors"), []) if files.get("errors") else []
    error_count = len(errors) if isinstance(errors, list) else 0

    support = None
    if isinstance(weighted, dict):
        support = weighted.get("support")

    return {
        "available": True,
        "message": "Saved evaluation results loaded successfully.",
        "source_directory": str(files["report"].parent.relative_to(_base_dir())),
        "metrics": {
            "accuracy": accuracy_value,
            "macro_precision": macro.get("precision") if isinstance(macro, dict) else None,
            "macro_recall": macro.get("recall") if isinstance(macro, dict) else None,
            "macro_f1": macro.get("f1-score") if isinstance(macro, dict) else None,
            "weighted_precision": weighted.get("precision") if isinstance(weighted, dict) else None,
            "weighted_recall": weighted.get("recall") if isinstance(weighted, dict) else None,
            "weighted_f1": weighted.get("f1-score") if isinstance(weighted, dict) else None,
            "test_examples": support,
            "error_examples": error_count,
        },
        "artifacts": {
            kind: f"/api/demo/evaluation/artifact/{kind}"
            for kind in files
        },
    }


def _get_incident_record(incident_id: int) -> dict[str, Any] | None:
    conn = get_db_connection()
    try:
        row = conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
        if not row:
            return None
        incident = dict(row)
        timeline = []
        comments = []
        executions = []
        if _table_exists(conn, "timeline_events"):
            timeline = [
                dict(item)
                for item in conn.execute(
                    "SELECT * FROM timeline_events WHERE incident_id = ? ORDER BY id ASC",
                    (incident_id,),
                ).fetchall()
            ]
        if _table_exists(conn, "comments"):
            comments = [
                dict(item)
                for item in conn.execute(
                    "SELECT * FROM comments WHERE incident_id = ? ORDER BY id ASC",
                    (incident_id,),
                ).fetchall()
            ]
        if _table_exists(conn, "playbook_executions"):
            executions = [
                dict(item)
                for item in conn.execute(
                    "SELECT * FROM playbook_executions WHERE incident_id = ? ORDER BY id DESC",
                    (incident_id,),
                ).fetchall()
            ]
        return {
            "incident": incident,
            "timeline": timeline,
            "comments": comments,
            "playbook_executions": executions,
            "containment_capability": _containment_capability(str(incident.get("ioc_type", "")).upper()),
        }
    finally:
        conn.close()


def _report_styles():
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

    styles = getSampleStyleSheet()
    styles.add(
        ParagraphStyle(
            name="SOARSmall",
            parent=styles["BodyText"],
            fontSize=8,
            leading=10,
            textColor=colors.HexColor("#334155"),
        )
    )
    return styles


def _generate_incident_report(incident_id: int) -> Path:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.units import mm
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

    record = _get_incident_record(incident_id)
    if not record:
        raise ValueError(f"Incident #{incident_id} was not found.")

    report_dir = _base_dir() / "reports"
    report_dir.mkdir(parents=True, exist_ok=True)
    path = report_dir / f"incident_{incident_id}_{datetime.now().strftime('%Y%m%d-%H%M%S')}.pdf"
    styles = _report_styles()
    incident = record["incident"]

    doc = SimpleDocTemplate(
        str(path),
        pagesize=landscape(A4),
        rightMargin=12 * mm,
        leftMargin=12 * mm,
        topMargin=12 * mm,
        bottomMargin=12 * mm,
    )
    story = [
        Paragraph("SOAR Incident Investigation Report", styles["Title"]),
        Paragraph(f"Generated: {_utc_now()} UTC", styles["SOARSmall"]),
        Spacer(1, 8),
    ]

    details = [
        ["Incident ID", str(incident.get("id", "")), "Status", str(incident.get("status", ""))],
        ["Title", str(incident.get("title", "")), "Severity", str(incident.get("severity", ""))],
        ["IOC", str(incident.get("ioc_value", "")), "IOC Type", str(incident.get("ioc_type", ""))],
        ["Risk Score", str(incident.get("risk_score", "")), "Analyst", str(incident.get("assigned_analyst", "ANALYST"))],
        ["Description", Paragraph(str(incident.get("description", "")), styles["SOARSmall"]), "Created", str(incident.get("created_at", ""))],
    ]
    table = Table(details, colWidths=[28 * mm, 93 * mm, 28 * mm, 93 * mm])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
                ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#94a3b8")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTNAME", (2, 0), (2, -1), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("PADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    story.extend([table, Spacer(1, 10)])

    story.append(Paragraph("Incident Timeline", styles["Heading2"]))
    timeline_data = [["Time", "Actor", "Event"]]
    for event in record["timeline"]:
        timeline_data.append(
            [
                str(event.get("timestamp", "")),
                str(event.get("action_by", "")),
                Paragraph(str(event.get("action_description", "")), styles["SOARSmall"]),
            ]
        )
    if len(timeline_data) == 1:
        timeline_data.append(["-", "-", "No timeline events recorded."])
    timeline_table = Table(timeline_data, colWidths=[42 * mm, 38 * mm, 164 * mm], repeatRows=1)
    timeline_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#94a3b8")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("PADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    story.extend([timeline_table, Spacer(1, 10)])

    story.append(Paragraph("Playbook Executions", styles["Heading2"]))
    execution_data = [["ID", "Status", "Mode", "Approval", "Containment", "Risk", "Completed"]]
    for execution in record["playbook_executions"]:
        execution_data.append(
            [
                str(execution.get("id", "")),
                str(execution.get("status", "")),
                str(execution.get("execution_mode", "")),
                str(execution.get("approval_status", "")),
                str(execution.get("containment_status", "")),
                str(execution.get("risk_score", "")),
                str(execution.get("completed_at", "")),
            ]
        )
    if len(execution_data) == 1:
        execution_data.append(["-", "-", "-", "-", "-", "-", "No executions recorded."])
    execution_table = Table(execution_data, repeatRows=1)
    execution_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#94a3b8")),
                ("FONTSIZE", (0, 0), (-1, -1), 7.5),
                ("PADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    story.append(execution_table)
    doc.build(story)
    return path


def _generate_executive_report() -> Path:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.units import mm
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

    conn = get_db_connection()
    try:
        total = conn.execute("SELECT COUNT(*) AS value FROM incidents").fetchone()["value"]
        statuses = [dict(row) for row in conn.execute("SELECT status, COUNT(*) AS count FROM incidents GROUP BY status").fetchall()]
        severities = [dict(row) for row in conn.execute("SELECT severity, COUNT(*) AS count FROM incidents GROUP BY severity").fetchall()]
        top_iocs = [
            dict(row)
            for row in conn.execute(
                "SELECT ioc_value, COUNT(*) AS count FROM incidents WHERE COALESCE(ioc_value, '') != '' GROUP BY ioc_value ORDER BY count DESC LIMIT 10"
            ).fetchall()
        ]
        playbook_count = 0
        if _table_exists(conn, "playbook_executions"):
            playbook_count = conn.execute("SELECT COUNT(*) AS value FROM playbook_executions").fetchone()["value"]
    finally:
        conn.close()

    report_dir = _base_dir() / "reports"
    report_dir.mkdir(parents=True, exist_ok=True)
    path = report_dir / f"executive_summary_{datetime.now().strftime('%Y%m%d-%H%M%S')}.pdf"
    styles = _report_styles()
    doc = SimpleDocTemplate(
        str(path),
        pagesize=landscape(A4),
        rightMargin=14 * mm,
        leftMargin=14 * mm,
        topMargin=14 * mm,
        bottomMargin=14 * mm,
    )
    story = [
        Paragraph("SOAR Executive Summary", styles["Title"]),
        Paragraph(f"Generated: {_utc_now()} UTC", styles["SOARSmall"]),
        Spacer(1, 10),
        Paragraph(f"Total incidents: {total}", styles["Heading2"]),
        Paragraph(f"Recorded playbook executions: {playbook_count}", styles["Heading2"]),
        Spacer(1, 8),
    ]

    summary_data = [["Category", "Value", "Count"]]
    summary_data.extend([["Status", item.get("status", ""), item.get("count", 0)] for item in statuses])
    summary_data.extend([["Severity", item.get("severity", ""), item.get("count", 0)] for item in severities])
    table = Table(summary_data, colWidths=[55 * mm, 75 * mm, 35 * mm], repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#94a3b8")),
                ("PADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    story.extend([table, Spacer(1, 12), Paragraph("Top recurring IOCs", styles["Heading2"])])

    ioc_data = [["IOC", "Incident count"]]
    ioc_data.extend([[item.get("ioc_value", ""), item.get("count", 0)] for item in top_iocs])
    if len(ioc_data) == 1:
        ioc_data.append(["No IOCs recorded", 0])
    ioc_table = Table(ioc_data, colWidths=[150 * mm, 45 * mm], repeatRows=1)
    ioc_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#94a3b8")),
                ("PADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    story.append(ioc_table)
    doc.build(story)
    return path




@supervisor_demo_bp.route("/operations-workspace", methods=["GET"])
def operations_workspace_page():
    # Dedicated operational interface using the existing Stage 7 APIs.
    return render_template("operations_workspace.html")


@supervisor_demo_bp.route("/api/demo/status", methods=["GET"])
def demo_status():
    database = {"ok": False, "message": "not checked"}
    try:
        conn = get_db_connection()
        conn.execute("SELECT 1").fetchone()
        conn.close()
        database = {"ok": True, "message": "SQLite connection successful"}
    except Exception as exc:
        database = {"ok": False, "message": str(exc)}

    rasa = _http_health(f"{_rasa_base_url()}/status")
    action_server = _http_health("http://127.0.0.1:5055/health")
    ufw = _ufw_status()

    return jsonify(
        {
            "status": "success",
            "system": {
                "flask": {"ok": True, "message": "dashboard API running"},
                "database": database,
                "rasa": rasa,
                "action_server": action_server,
                "ufw": {"ok": ufw["ok"], "message": ufw["output"]},
            },
            "modes": {
                "threat_intelligence": "SIMULATION" if bool(getattr(settings, "SOAR_SIMULATION_MODE", False)) else "LIVE",
                "playbook_containment": "SIMULATION" if bool(getattr(settings, "PLAYBOOK_SIMULATION_MODE", True)) else "LIVE",
            },
            "providers_configured": _provider_configuration(),
        }
    )


@supervisor_demo_bp.route("/api/demo/analyze-ioc", methods=["POST"])
def analyze_ioc():
    data = request.get_json(silent=True) or {}
    try:
        value, ioc_type = _normalise_ioc(data.get("value", ""), data.get("ioc_type", "AUTO"))
    except ValueError as exc:
        return _json_error(str(exc), 400)

    try:
        result = ThreatIntelAggregator.analyze_all(value, ioc_type)
    except Exception as exc:
        current_app.logger.exception("Dashboard IOC analysis failed")
        return _json_error(f"Threat-intelligence analysis failed: {exc}", 502)

    return jsonify(
        {
            "status": "success",
            "analysis": result,
            "ioc": {"value": value, "type": ioc_type},
            "containment_capability": _containment_capability(ioc_type),
        }
    )


@supervisor_demo_bp.route("/api/demo/ingest/suricata", methods=["POST"])
def ingest_demo_suricata_alert():
    data = request.get_json(silent=True) or {}
    try:
        source_ip, _ = _normalise_ioc(data.get("src_ip", ""), "IP")
    except ValueError as exc:
        return _json_error(str(exc), 400)

    destination_ip = str(data.get("dest_ip", "")).strip()
    if destination_ip:
        try:
            destination_ip, _ = _normalise_ioc(destination_ip, "IP")
        except ValueError as exc:
            return _json_error(f"Destination {exc}", 400)

    signature = str(data.get("signature") or "Controlled IDS demonstration alert").strip()
    category = str(data.get("category") or "Potentially malicious network activity").strip()
    try:
        ids_severity = int(data.get("ids_severity", 1))
    except (TypeError, ValueError):
        return _json_error("IDS severity must be numeric.", 400)

    if ids_severity <= 1:
        severity, risk_score = "CRITICAL", 90
    elif ids_severity == 2:
        severity, risk_score = "HIGH", 75
    else:
        severity, risk_score = "MEDIUM", 55

    description = (
        f"Controlled dashboard IDS ingestion. Signature: {signature}. "
        f"Category: {category}. Source: {source_ip}. "
        f"Destination: {destination_ip or 'not supplied'}. IDS severity: {ids_severity}."
    )

    values = {
        "title": f"IDS Alert: {signature}",
        "description": description,
        "ioc_value": source_ip,
        "ioc_type": "IP",
        "severity": severity,
        "risk_score": risk_score,
        "status": "OPEN",
        "assigned_analyst": "AUTOMATED_INGESTION",
        "created_at": _utc_now(),
        "updated_at": _utc_now(),
    }
    combined = f"{signature} {category}".lower()
    if "command and control" in combined or "c2" in combined or "beacon" in combined:
        values["mitre_tactic"] = "Command and Control"
        values["mitre_technique"] = "T1071.001 (Web Protocols)"

    conn = get_db_connection()
    try:
        incident_id = _insert_dynamic(conn, "incidents", values)
        _add_timeline(
            conn,
            incident_id,
            f"Controlled Suricata-style alert ingested from the dashboard. Source IOC {source_ip}; signature {signature}.",
            actor="AUTOMATED_INGESTION",
        )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

    return jsonify(
        {
            "status": "success",
            "incident_id": incident_id,
            "message": "Controlled IDS event ingested and incident created.",
            "severity": severity,
            "risk_score": risk_score,
            "ioc_value": source_ip,
        }
    ), 201


@supervisor_demo_bp.route("/api/demo/incidents", methods=["GET"])
def list_demo_incidents():
    limit = max(1, min(request.args.get("limit", default=100, type=int) or 100, 250))
    conn = get_db_connection()
    try:
        rows = conn.execute("SELECT * FROM incidents ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return jsonify({"status": "success", "incidents": [dict(row) for row in rows]})
    finally:
        conn.close()


@supervisor_demo_bp.route("/api/demo/incidents/from-analysis", methods=["POST"])
def create_incident_from_analysis():
    data = request.get_json(silent=True) or {}
    try:
        value, ioc_type = _normalise_ioc(data.get("ioc_value", ""), data.get("ioc_type", "AUTO"))
    except ValueError as exc:
        return _json_error(str(exc), 400)

    severity = str(data.get("severity", "MEDIUM")).upper()
    if severity not in VALID_SEVERITIES:
        return _json_error("Severity must be LOW, MEDIUM, HIGH, or CRITICAL.", 400)

    try:
        risk_score = int(data.get("risk_score", 0))
    except (TypeError, ValueError):
        return _json_error("Risk score must be numeric.", 400)
    risk_score = max(0, min(risk_score, 100))

    title = str(data.get("title") or f"Analyst investigation: {value}").strip()
    description = str(
        data.get("description")
        or "Incident manually created from the dashboard IOC analysis workbench."
    ).strip()

    conn = get_db_connection()
    try:
        incident_id = _insert_dynamic(
            conn,
            "incidents",
            {
                "title": title,
                "description": description,
                "ioc_value": value,
                "ioc_type": ioc_type,
                "severity": severity,
                "risk_score": risk_score,
                "status": "OPEN",
                "assigned_analyst": "ANALYST",
                "created_at": _utc_now(),
                "updated_at": _utc_now(),
            },
        )
        _add_timeline(
            conn,
            incident_id,
            f"Incident created from dashboard analysis for {ioc_type} IOC {value}. Initial risk {risk_score}/100 and severity {severity}.",
        )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

    return jsonify({"status": "success", "incident_id": incident_id, "message": "Incident created successfully."}), 201


@supervisor_demo_bp.route("/api/demo/incidents/<int:incident_id>", methods=["GET"])
def get_demo_incident(incident_id: int):
    record = _get_incident_record(incident_id)
    if not record:
        return _json_error(f"Incident #{incident_id} was not found.", 404)
    return jsonify({"status": "success", **record})


@supervisor_demo_bp.route("/api/demo/incidents/<int:incident_id>/status", methods=["PUT"])
def update_demo_incident_status(incident_id: int):
    data = request.get_json(silent=True) or {}
    status = str(data.get("status", "")).upper()
    if status not in VALID_INCIDENT_STATUSES:
        return _json_error("Status must be OPEN, INVESTIGATING, CONTAINED, or CLOSED.", 400)

    conn = get_db_connection()
    try:
        cursor = conn.execute(
            "UPDATE incidents SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
            (status, incident_id),
        )
        if cursor.rowcount == 0:
            conn.rollback()
            return _json_error(f"Incident #{incident_id} was not found.", 404)
        _add_timeline(conn, incident_id, f"Analyst changed incident status to {status}.")
        conn.commit()
    finally:
        conn.close()
    return jsonify({"status": "success", "incident_status": status})


@supervisor_demo_bp.route("/api/demo/incidents/<int:incident_id>/comments", methods=["POST"])
def add_demo_incident_comment(incident_id: int):
    data = request.get_json(silent=True) or {}
    comment = str(data.get("comment", "")).strip()
    if not comment:
        return _json_error("A comment is required.", 400)

    conn = get_db_connection()
    try:
        incident = conn.execute("SELECT id FROM incidents WHERE id = ?", (incident_id,)).fetchone()
        if not incident:
            return _json_error(f"Incident #{incident_id} was not found.", 404)
        if not _table_exists(conn, "comments"):
            return _json_error("The comments table is unavailable.", 500)
        _insert_dynamic(
            conn,
            "comments",
            {
                "incident_id": incident_id,
                "comment_by": "ANALYST",
                "author": "ANALYST",
                "username": "ANALYST",
                "comment": comment,
                "comment_text": comment,
                "content": comment,
                "created_at": _utc_now(),
            },
        )
        _add_timeline(conn, incident_id, "Analyst added an investigation comment.")
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
    return jsonify({"status": "success", "message": "Comment added."}), 201


@supervisor_demo_bp.route("/api/demo/incidents/<int:incident_id>/contain", methods=["POST"])
def live_contain_incident(incident_id: int):
    data = request.get_json(silent=True) or {}
    if data.get("confirm_live") is not True:
        return _json_error("Explicit live-containment confirmation is required.", 409)

    record = _get_incident_record(incident_id)
    if not record:
        return _json_error(f"Incident #{incident_id} was not found.", 404)
    incident = record["incident"]
    ioc_type = str(incident.get("ioc_type", "")).upper()
    value = str(incident.get("ioc_value", "")).strip()
    if ioc_type != "IP":
        return _json_error(_containment_capability(ioc_type)["message"], 409)

    try:
        value, _ = _normalise_ioc(value, "IP")
    except ValueError as exc:
        return _json_error(str(exc), 400)

    execution_status, notes = execute_kernel_block({"type": "IP", "value": value})
    conn = get_db_connection()
    try:
        if execution_status == "SUCCESS":
            conn.execute(
                "UPDATE incidents SET status = 'CONTAINED', updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                (incident_id,),
            )
        _add_timeline(
            conn,
            incident_id,
            f"Dashboard live UFW containment result: {execution_status}. {notes}",
            actor="UFW_AUTOMATION",
        )
        conn.commit()
    finally:
        conn.close()

    try:
        audit_logger.log_event("DASHBOARD LIVE UFW BLOCK", value, str(incident.get("severity", "HIGH")), str(notes), execution_status)
    except Exception:
        current_app.logger.exception("Audit logging failed after dashboard block")

    status_code = 200 if execution_status == "SUCCESS" else 409
    return jsonify({"status": "success" if status_code == 200 else "error", "execution_status": execution_status, "message": str(notes), "incident_status": "CONTAINED" if execution_status == "SUCCESS" else incident.get("status")}), status_code


@supervisor_demo_bp.route("/api/demo/incidents/<int:incident_id>/unblock", methods=["POST"])
def live_unblock_incident(incident_id: int):
    data = request.get_json(silent=True) or {}
    if data.get("confirm_live") is not True:
        return _json_error("Explicit live-unblock confirmation is required.", 409)

    record = _get_incident_record(incident_id)
    if not record:
        return _json_error(f"Incident #{incident_id} was not found.", 404)
    incident = record["incident"]
    ioc_type = str(incident.get("ioc_type", "")).upper()
    value = str(incident.get("ioc_value", "")).strip()
    if ioc_type != "IP":
        return _json_error("Only an IPv4 incident can be removed from UFW.", 409)

    execution_status, notes = execute_kernel_unblock({"type": "IP", "value": value})
    conn = get_db_connection()
    try:
        if execution_status == "SUCCESS":
            conn.execute(
                "UPDATE incidents SET status = 'INVESTIGATING', updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                (incident_id,),
            )
        _add_timeline(
            conn,
            incident_id,
            f"Dashboard live UFW unblock result: {execution_status}. {notes}",
            actor="UFW_AUTOMATION",
        )
        conn.commit()
    finally:
        conn.close()

    try:
        audit_logger.log_event("DASHBOARD LIVE UFW UNBLOCK", value, "INFORMATIONAL", str(notes), execution_status)
    except Exception:
        current_app.logger.exception("Audit logging failed after dashboard unblock")

    status_code = 200 if execution_status == "SUCCESS" else 409
    return jsonify({"status": "success" if status_code == 200 else "error", "execution_status": execution_status, "message": str(notes), "incident_status": "INVESTIGATING" if execution_status == "SUCCESS" else incident.get("status")}), status_code


@supervisor_demo_bp.route("/api/demo/ufw-rules", methods=["GET"])
def demo_ufw_rules():
    result = _ufw_status()
    return jsonify({"status": "success" if result["ok"] else "error", **result}), 200 if result["ok"] else 503


@supervisor_demo_bp.route("/api/demo/validation", methods=["GET"])
def run_demo_validation():
    checks: list[dict[str, Any]] = []

    def add(name: str, ok: bool, message: str, level: str = "PASS") -> None:
        checks.append({"name": name, "ok": bool(ok), "result": level if ok else "FAIL", "message": message})

    add("Flask API", True, "The dashboard validation endpoint is running.")

    try:
        conn = get_db_connection()
        conn.execute("SELECT 1").fetchone()
        required_tables = {"incidents", "timeline_events", "playbooks", "playbook_executions"}
        existing = {
            row["name"]
            for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'").fetchall()
        }
        conn.close()
        missing = sorted(required_tables - existing)
        add("Database", not missing, "Required SQLite tables are present." if not missing else f"Missing tables: {', '.join(missing)}")
    except Exception as exc:
        add("Database", False, str(exc))

    rasa = _http_health(f"{_rasa_base_url()}/status")
    add("Rasa server", rasa["ok"], rasa["message"])
    action_server = _http_health("http://127.0.0.1:5055/health")
    add("Rasa action server", action_server["ok"], action_server["message"])

    upload_dir = _base_dir() / "uploads"
    add("Upload directory", upload_dir.is_dir(), str(upload_dir))

    routes = {str(rule) for rule in current_app.url_map.iter_rules()}
    required_routes = {
        "/api/chat",
        "/api/incidents",
        "/api/playbooks",
        "/api/playbook-executions",
        "/api/logs/upload",
        "/api/ufw-rules",
    }
    missing_routes = sorted(required_routes - routes)
    add("Required API routes", not missing_routes, "All core routes registered." if not missing_routes else f"Missing routes: {', '.join(missing_routes)}")

    ufw = _ufw_status()
    add("UFW integration", ufw["ok"], ufw["output"][:300])

    configured = _provider_configuration()
    configured_count = sum(1 for value in configured.values() if value)
    add("Threat-intelligence configuration", configured_count >= 2, f"{configured_count}/4 providers are configured or publicly accessible.")

    evaluation = _evaluation_payload()
    add("Saved evaluation results", evaluation["available"], evaluation["message"])

    overall = "PASS" if all(item["ok"] for item in checks) else "WARNING"
    return jsonify(
        {
            "status": "success",
            "overall": overall,
            "checked_at": _utc_now(),
            "passed": sum(1 for item in checks if item["ok"]),
            "failed": sum(1 for item in checks if not item["ok"]),
            "checks": checks,
        }
    )


@supervisor_demo_bp.route("/api/demo/evaluation", methods=["GET"])
def demo_evaluation():
    return jsonify({"status": "success", "evaluation": _evaluation_payload()})


@supervisor_demo_bp.route("/api/demo/evaluation/artifact/<string:kind>", methods=["GET"])
def demo_evaluation_artifact(kind: str):
    files = _latest_evaluation_files()
    if kind not in {"report", "confusion", "histogram", "errors"} or kind not in files:
        return _json_error("The requested evaluation artefact is unavailable.", 404)
    path = files[kind]
    return send_file(path, as_attachment=path.suffix.lower() == ".json", download_name=path.name)


@supervisor_demo_bp.route("/api/demo/reports/audit", methods=["GET"])
def download_demo_audit_report():
    try:
        path = Path(audit_logger.generate_pdf_report())
        return send_file(path, as_attachment=True, download_name=path.name)
    except Exception as exc:
        return _json_error(f"Audit report generation failed: {exc}", 500)


@supervisor_demo_bp.route("/api/demo/reports/incident/<int:incident_id>", methods=["GET"])
def download_demo_incident_report(incident_id: int):
    try:
        path = _generate_incident_report(incident_id)
        return send_file(path, as_attachment=True, download_name=path.name)
    except ValueError as exc:
        return _json_error(str(exc), 404)
    except Exception as exc:
        current_app.logger.exception("Incident report generation failed")
        return _json_error(f"Incident report generation failed: {exc}", 500)


@supervisor_demo_bp.route("/api/demo/reports/executive", methods=["GET"])
def download_demo_executive_report():
    try:
        path = _generate_executive_report()
        return send_file(path, as_attachment=True, download_name=path.name)
    except Exception as exc:
        current_app.logger.exception("Executive report generation failed")
        return _json_error(f"Executive report generation failed: {exc}", 500)
