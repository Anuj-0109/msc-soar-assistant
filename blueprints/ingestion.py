from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from flask import Blueprint, jsonify, request
from werkzeug.utils import secure_filename

import audit_logger
import soar_engine
from constants import AUTOMATED_INGESTION_IDENTITY
from models.database import get_db_connection
from services.log_analysis import analyze_log_text
from settings import BASE_DIR


ingestion_bp = Blueprint(
    "ingestion",
    __name__,
)


UPLOAD_DIR = BASE_DIR / "uploads"

ALLOWED_LOG_EXTENSIONS = {
    ".log",
    ".txt",
    ".csv",
    ".json",
}

MAX_UPLOAD_BYTES = 2 * 1024 * 1024


def check_existing_active_incident(
    conn,
    ioc_value,
):
    return conn.execute(
        """
        SELECT id
        FROM incidents
        WHERE ioc_value = ?
          AND status IN ('OPEN', 'INVESTIGATING')
        ORDER BY id DESC
        LIMIT 1
        """,
        (ioc_value,),
    ).fetchone()


def _create_log_incidents(
    analysis,
    stored_filename,
):
    incident_ids = []

    suspicious_iocs = analysis.get(
        "suspicious_iocs",
        [],
    )

    if not suspicious_iocs:
        return incident_ids

    conn = get_db_connection()

    try:
        for item in suspicious_iocs[:10]:
            ip = item["value"]

            existing = check_existing_active_incident(
                conn,
                ip,
            )

            if existing:
                continue

            related_findings = [
                finding
                for finding in analysis.get(
                    "findings",
                    [],
                )
                if ip in finding.get("iocs", [])
            ]

            categories = sorted(
                {
                    finding.get(
                        "category",
                        "LOG_EVENT",
                    )
                    for finding in related_findings
                }
            )

            description = (
                f"Suspicious activity extracted from "
                f"uploaded log {stored_filename}. "
                f"Occurrences: {item['occurrences']}. "
                f"Categories: "
                f"{', '.join(categories) or 'LOG_EVENT'}."
            )

            cursor = conn.execute(
                """
                INSERT INTO incidents (
                    title,
                    description,
                    ioc_value,
                    ioc_type,
                    severity,
                    risk_score,
                    status,
                    assigned_analyst,
                    mitre_tactic,
                    mitre_technique
                )
                VALUES (
                    ?, ?, ?, 'IP', ?, ?, 'OPEN',
                    ?, ?, ?
                )
                """,
                (
                    f"[Log Upload] Suspicious IP {ip}",
                    description,
                    ip,
                    analysis["overall_severity"],
                    analysis["risk_score"],
                    AUTOMATED_INGESTION_IDENTITY,
                    "Credential Access",
                    "T1110 - Brute Force",
                ),
            )

            incident_id = cursor.lastrowid
            incident_ids.append(incident_id)

            conn.execute(
                """
                INSERT INTO timeline_events (
                    incident_id,
                    action_by,
                    action_description
                )
                VALUES (?, ?, ?)
                """,
                (
                    incident_id,
                    AUTOMATED_INGESTION_IDENTITY,
                    (
                        f"Incident created from uploaded "
                        f"log {stored_filename}. "
                        "No containment was executed."
                    ),
                ),
            )

        conn.commit()

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()

    return incident_ids


@ingestion_bp.route(
    "/api/logs/upload",
    methods=["POST"],
)
def upload_log_file():
    uploaded = request.files.get("file")

    if uploaded is None:
        return jsonify(
            {
                "status": "error",
                "message": "No file was supplied.",
            }
        ), 400

    original_name = secure_filename(
        uploaded.filename or ""
    )

    if not original_name:
        return jsonify(
            {
                "status": "error",
                "message": "The uploaded filename is invalid.",
            }
        ), 400

    extension = Path(
        original_name
    ).suffix.lower()

    if extension not in ALLOWED_LOG_EXTENSIONS:
        return jsonify(
            {
                "status": "error",
                "message": (
                    "Unsupported file type. Use .log, "
                    ".txt, .csv or .json."
                ),
            }
        ), 415

    content = uploaded.read(
        MAX_UPLOAD_BYTES + 1
    )

    if len(content) > MAX_UPLOAD_BYTES:
        return jsonify(
            {
                "status": "error",
                "message": (
                    "The file exceeds the 2 MB limit."
                ),
            }
        ), 413

    if not content:
        return jsonify(
            {
                "status": "error",
                "message": "The uploaded file is empty.",
            }
        ), 400

    UPLOAD_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    timestamp = datetime.now(
        timezone.utc
    ).strftime("%Y%m%dT%H%M%SZ")

    stored_filename = (
        f"{timestamp}_{uuid4().hex[:8]}_"
        f"{original_name}"
    )

    stored_path = UPLOAD_DIR / stored_filename
    stored_path.write_bytes(content)

    text = content.decode(
        "utf-8",
        errors="replace",
    )

    try:
        analysis = analyze_log_text(
            text,
            filename=stored_filename,
        )

        incident_ids = _create_log_incidents(
            analysis,
            stored_filename,
        )

    except Exception as exc:
        stored_path.unlink(
            missing_ok=True
        )

        return jsonify(
            {
                "status": "error",
                "message": (
                    "Log analysis failed: "
                    f"{type(exc).__name__}."
                ),
            }
        ), 500

    audit_logger.log_event(
        "LOG FILE ANALYSIS",
        stored_filename,
        analysis["overall_severity"],
        (
            f"Local deterministic analysis found "
            f"{analysis['finding_count']} findings. "
            f"Created {len(incident_ids)} incidents. "
            "No firewall action was executed."
        ),
        "SUCCESS",
    )

    return jsonify(
        {
            "status": "success",
            "message": (
                f"Analysed {analysis['line_count']} lines, "
                f"identified {analysis['finding_count']} "
                f"findings and created "
                f"{len(incident_ids)} incident(s)."
            ),
            "stored_file": stored_filename,
            "analysis": analysis,
            "incident_ids": incident_ids,
        }
    ), 201


@ingestion_bp.route(
    "/api/ingest/suricata",
    methods=["POST"],
)
def ingest_suricata_alert():
    payload = request.get_json(
        silent=True
    ) or {}

    alert_data = payload.get(
        "alert",
        {},
    )

    src_ip = (
        payload.get("src_ip")
        or payload.get("source_ip")
    )

    if not src_ip and isinstance(
        alert_data,
        dict,
    ):
        src_ip = alert_data.get("src_ip")

    if not src_ip:
        return jsonify(
            {
                "status": "error",
                "message": (
                    "No source IP was found in the alert."
                ),
            }
        ), 400

    conn = get_db_connection()

    try:
        existing = check_existing_active_incident(
            conn,
            src_ip,
        )

        if existing:
            return jsonify(
                {
                    "status": "ignored",
                    "message": (
                        f"Active incident "
                        f"#{existing['id']} already exists "
                        f"for IOC {src_ip}."
                    ),
                }
            ), 200

        signature = alert_data.get(
            "signature",
            "Suricata IDS Alert",
        )

        severity_map = {
            1: "CRITICAL",
            2: "HIGH",
            3: "MEDIUM",
        }

        severity = severity_map.get(
            alert_data.get("severity"),
            "MEDIUM",
        )

        cursor = conn.execute(
            """
            INSERT INTO incidents (
                title,
                description,
                ioc_value,
                ioc_type,
                severity,
                risk_score,
                status,
                assigned_analyst,
                mitre_tactic,
                mitre_technique
            )
            VALUES (
                ?, ?, ?, 'IP', ?, 85, 'OPEN',
                ?, 'Initial Access', 'T1190'
            )
            """,
            (
                f"[Suricata] {signature}",
                f"Alert on IP: {src_ip}",
                src_ip,
                severity,
                AUTOMATED_INGESTION_IDENTITY,
            ),
        )

        incident_id = cursor.lastrowid

        conn.execute(
            """
            INSERT INTO timeline_events (
                incident_id,
                action_by,
                action_description
            )
            VALUES (?, ?, ?)
            """,
            (
                incident_id,
                AUTOMATED_INGESTION_IDENTITY,
                (
                    "Incident created from a Suricata "
                    "alert. No containment was executed."
                ),
            ),
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
            "message": (
                "Suricata alert processed and "
                "incident logged."
            ),
            "incident_id": incident_id,
        }
    ), 201


@ingestion_bp.route(
    "/api/ingest/syslog",
    methods=["POST"],
)
def ingest_syslog_auth():
    payload = request.get_json(
        silent=True
    ) or {}

    raw_log = str(
        payload.get("log_entry", "")
    )

    ip_address = payload.get("source_ip")

    if not ip_address and raw_log:
        extracted = soar_engine.extract_ioc(
            raw_log
        )

        if (
            isinstance(extracted, dict)
            and extracted.get("type") == "IP"
        ):
            ip_address = extracted.get("value")

    if not ip_address:
        return jsonify(
            {
                "status": "error",
                "message": (
                    "No valid IP address was found "
                    "in the syslog payload."
                ),
            }
        ), 400

    conn = get_db_connection()

    try:
        existing = check_existing_active_incident(
            conn,
            ip_address,
        )

        if existing:
            return jsonify(
                {
                    "status": "ignored",
                    "message": (
                        f"Active incident "
                        f"#{existing['id']} already exists "
                        f"for IOC {ip_address}."
                    ),
                }
            ), 200

        cursor = conn.execute(
            """
            INSERT INTO incidents (
                title,
                description,
                ioc_value,
                ioc_type,
                severity,
                risk_score,
                status,
                assigned_analyst,
                mitre_tactic,
                mitre_technique
            )
            VALUES (
                ?, ?, ?, 'IP', 'HIGH', 80,
                'OPEN', ?, 'Credential Access',
                'T1110.001 - Password Guessing'
            )
            """,
            (
                (
                    "[Syslog Auth] SSH brute-force "
                    f"attempt from {ip_address}"
                ),
                f"Raw log: {raw_log[:500]}",
                ip_address,
                AUTOMATED_INGESTION_IDENTITY,
            ),
        )

        incident_id = cursor.lastrowid
        conn.commit()

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()

    return jsonify(
        {
            "status": "success",
            "message": (
                "Syslog entry processed successfully."
            ),
            "incident_id": incident_id,
            "ioc_detected": ip_address,
        }
    ), 201
