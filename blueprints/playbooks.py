import subprocess

import audit_logger
from flask import Blueprint, jsonify, request
from models.database import get_db_connection
from services.playbook_engine import (
    PlaybookError,
    approve_and_execute,
    get_execution,
    get_playbook,
    list_executions,
    list_playbooks,
    reject_execution,
    request_execution,
    set_playbook_enabled,
)
from soar_engine import execute_kernel_block

playbooks_bp = Blueprint('playbooks', __name__)

def get_ufw_status():
    """Retrieve active UFW rules or fallback to active database blocked IOCs."""
    rules = []
    try:
        output = subprocess.check_output(["sudo", "ufw", "status", "numbered"], text=True, stderr=subprocess.STDOUT)
        for line in output.splitlines():
            if "DENY" in line or "ALLOW" in line:
                rules.append(line.strip())
    except Exception:
        pass

    # Fetch blocked IOCs directly from database
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, ioc_value, status, created_at FROM incidents WHERE status IN ('CONTAINED', 'OPEN', 'INVESTIGATING') AND ioc_type='IP' ORDER BY id DESC LIMIT 10")
    db_incidents = cursor.fetchall()
    conn.close()

    db_rules = []
    for idx, row in enumerate(db_incidents, 1):
        action = "DENY IN" if row['status'] == 'CONTAINED' else "PENDING_BLOCK"
        db_rules.append({
            'rule_num': idx,
            'action': action,
            'source': row['ioc_value'],
            'status': row['status']
        })

    return db_rules

@playbooks_bp.route('/api/fw/rules', methods=['GET'])
def list_fw_rules():
    rules = get_ufw_status()
    return jsonify({'status': 'success', 'rules': rules})

@playbooks_bp.route("/api/fw/block", methods=["POST"])
def block_ip():
    data = request.get_json(silent=True) or {}
    ip = str(data.get("ip", "")).strip()

    if not ip:
        return jsonify(
            {
                "status": "error",
                "message": "No IP address was provided.",
            }
        ), 400

    execution_status, execution_notes = execute_kernel_block(
        {
            "type": "IP",
            "value": ip,
        }
    )

    audit_logger.log_event(
        "API UFW BLOCK",
        ip,
        "HIGH",
        execution_notes,
        execution_status,
    )

    if execution_status != "SUCCESS":
        http_status = (
            403
            if execution_status == "BLOCKED_BY_POLICY"
            else 500
        )

        return jsonify(
            {
                "status": "error",
                "execution_status": execution_status,
                "message": (
                    f"UFW containment was not confirmed for "
                    f"{ip}."
                ),
                "details": execution_notes,
                "recommendation": (
                    f"No incident was marked CONTAINED. "
                    f"Review the execution failure: "
                    f"{execution_notes}"
                ),
            }
        ), http_status

    conn = get_db_connection()

    try:
        existing = conn.execute(
            """
            SELECT id
            FROM incidents
            WHERE ioc_value = ?
              AND ioc_type = 'IP'
            ORDER BY id DESC
            LIMIT 1
            """,
            (ip,),
        ).fetchone()

        if existing:
            incident_id = existing["id"]

            conn.execute(
                """
                UPDATE incidents
                SET status = 'CONTAINED',
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                (incident_id,),
            )

        else:
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
                    assigned_analyst
                )
                VALUES (?, ?, ?, 'IP', 'HIGH', 85,
                        'CONTAINED', 'UFW_AUTOMATION')
                """,
                (
                    f"[UFW Block] Contained IP {ip}",
                    execution_notes,
                    ip,
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
                "UFW_AUTOMATION",
                f"UFW containment confirmed: {execution_notes}",
            ),
        )

        conn.commit()

    except Exception as exc:
        conn.rollback()

        return jsonify(
            {
                "status": "partial",
                "execution_status": "SUCCESS",
                "database_status": "FAILED",
                "message": (
                    f"UFW blocked {ip}, but the incident "
                    f"database update failed."
                ),
                "details": str(exc),
            }
        ), 500

    finally:
        conn.close()

    return jsonify(
        {
            "status": "success",
            "execution_status": "SUCCESS",
            "incident_id": incident_id,
            "ip": ip,
            "message": (
                f"UFW confirmed the deny rule for {ip}."
            ),
            "details": execution_notes,
            "recommendation": (
                f"Active containment confirmed. "
                f"Incident #{incident_id} is CONTAINED."
            ),
        }
    )


@playbooks_bp.route(
    "/api/playbooks",
    methods=["GET"],
)
def get_playbooks():
    return jsonify(
        {
            "status": "success",
            "playbooks": list_playbooks(),
        }
    ), 200


@playbooks_bp.route(
    "/api/playbooks/<int:playbook_id>",
    methods=["GET"],
)
def get_single_playbook(playbook_id):
    try:
        playbook = get_playbook(
            playbook_id
        )

    except PlaybookError as exc:
        return jsonify(
            {
                "status": "error",
                "message": exc.message,
            }
        ), exc.status_code

    return jsonify(
        {
            "status": "success",
            "playbook": playbook,
        }
    ), 200


@playbooks_bp.route(
    "/api/playbooks/<int:playbook_id>/enabled",
    methods=["PUT"],
)
def update_playbook_enabled(playbook_id):
    data = request.get_json(
        silent=True
    ) or {}

    if "enabled" not in data:
        return jsonify(
            {
                "status": "error",
                "message": (
                    "The enabled field is required."
                ),
            }
        ), 400

    enabled = data["enabled"]

    if not isinstance(enabled, bool):
        return jsonify(
            {
                "status": "error",
                "message": (
                    "The enabled field must be "
                    "true or false."
                ),
            }
        ), 400

    try:
        playbook = set_playbook_enabled(
            playbook_id,
            enabled,
        )

    except PlaybookError as exc:
        return jsonify(
            {
                "status": "error",
                "message": exc.message,
            }
        ), exc.status_code

    return jsonify(
        {
            "status": "success",
            "playbook": playbook,
        }
    ), 200


@playbooks_bp.route(
    "/api/playbooks/<int:playbook_id>/execute",
    methods=["POST"],
)
def create_playbook_execution(playbook_id):
    data = request.get_json(
        silent=True
    ) or {}

    incident_id = data.get(
        "incident_id"
    )

    if not isinstance(incident_id, int):
        return jsonify(
            {
                "status": "error",
                "message": (
                    "A numeric incident_id is required."
                ),
            }
        ), 400

    try:
        execution = request_execution(
            playbook_id,
            incident_id,
        )

    except PlaybookError as exc:
        return jsonify(
            {
                "status": "error",
                "message": exc.message,
            }
        ), exc.status_code

    return jsonify(
        {
            "status": "success",
            "message": (
                "Playbook execution requested. "
                "No firewall action has been executed."
            ),
            "execution": execution,
        }
    ), 202


@playbooks_bp.route(
    "/api/playbook-executions",
    methods=["GET"],
)
def get_playbook_executions():
    limit = request.args.get(
        "limit",
        50,
        type=int,
    )

    return jsonify(
        {
            "status": "success",
            "executions": list_executions(
                limit=limit
            ),
        }
    ), 200


@playbooks_bp.route(
    "/api/playbook-executions/<int:execution_id>",
    methods=["GET"],
)
def get_single_execution(execution_id):
    try:
        execution = get_execution(
            execution_id
        )

    except PlaybookError as exc:
        return jsonify(
            {
                "status": "error",
                "message": exc.message,
            }
        ), exc.status_code

    return jsonify(
        {
            "status": "success",
            "execution": execution,
        }
    ), 200


@playbooks_bp.route(
    (
        "/api/playbook-executions/"
        "<int:execution_id>/approve"
    ),
    methods=["POST"],
)
def approve_playbook_execution(execution_id):
    try:
        execution = approve_and_execute(
            execution_id
        )

    except PlaybookError as exc:
        return jsonify(
            {
                "status": "error",
                "message": exc.message,
            }
        ), exc.status_code

    return jsonify(
        {
            "status": "success",
            "message": (
                "Analyst approval recorded and "
                "playbook execution completed."
            ),
            "execution": execution,
        }
    ), 200


@playbooks_bp.route(
    (
        "/api/playbook-executions/"
        "<int:execution_id>/reject"
    ),
    methods=["POST"],
)
def reject_playbook_execution(execution_id):
    try:
        execution = reject_execution(
            execution_id
        )

    except PlaybookError as exc:
        return jsonify(
            {
                "status": "error",
                "message": exc.message,
            }
        ), exc.status_code

    return jsonify(
        {
            "status": "success",
            "message": (
                "Playbook execution rejected. "
                "No firewall action was executed."
            ),
            "execution": execution,
        }
    ), 200

