from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

import audit_logger
from constants import (
    ANALYST_IDENTITY,
    PLAYBOOK_ENGINE_IDENTITY,
)
from models.database import get_db_connection
from services.threat_intel import ThreatIntelAggregator
from settings import PLAYBOOK_SIMULATION_MODE
from soar_engine import execute_kernel_block


DEFAULT_PLAYBOOK_NAME = (
    "IOC Investigation and Containment"
)

DEFAULT_WORKFLOW = [
    {
        "step_id": "validate_ioc",
        "name": "Validate IOC",
        "action": "VALIDATE_IOC",
        "requires_approval": False,
    },
    {
        "step_id": "threat_intelligence",
        "name": "Threat-intelligence enrichment",
        "action": "THREAT_INTELLIGENCE",
        "requires_approval": False,
    },
    {
        "step_id": "update_incident",
        "name": "Update incident risk and severity",
        "action": "UPDATE_INCIDENT",
        "requires_approval": False,
    },
    {
        "step_id": "containment",
        "name": "UFW containment",
        "action": "UFW_BLOCK",
        "requires_approval": True,
    },
]


class PlaybookError(Exception):
    def __init__(
        self,
        message: str,
        status_code: int = 400,
    ):
        super().__init__(message)
        self.message = message
        self.status_code = status_code


def _utc_timestamp() -> str:
    return datetime.now(
        timezone.utc
    ).strftime("%Y-%m-%d %H:%M:%S")


def _table_columns(
    conn,
    table_name: str,
) -> set[str]:
    rows = conn.execute(
        f"PRAGMA table_info({table_name})"
    ).fetchall()

    return {
        row["name"]
        for row in rows
    }


def _add_column_if_missing(
    conn,
    table_name: str,
    column_definition: str,
) -> None:
    column_name = column_definition.split()[0]

    if column_name not in _table_columns(
        conn,
        table_name,
    ):
        conn.execute(
            f"""
            ALTER TABLE {table_name}
            ADD COLUMN {column_definition}
            """
        )


def ensure_playbook_schema() -> None:
    """
    Extend the original playbook tables without deleting
    existing rows.
    """
    conn = get_db_connection()

    try:
        _add_column_if_missing(
            conn,
            "playbooks",
            "description TEXT DEFAULT ''",
        )

        _add_column_if_missing(
            conn,
            "playbooks",
            "workflow_json TEXT DEFAULT '[]'",
        )

        _add_column_if_missing(
            conn,
            "playbooks",
            "requires_approval INTEGER DEFAULT 1",
        )

        _add_column_if_missing(
            conn,
            "playbooks",
            "created_at TEXT",
        )

        _add_column_if_missing(
            conn,
            "playbooks",
            "updated_at TEXT",
        )

        _add_column_if_missing(
            conn,
            "playbook_executions",
            (
                "requested_by TEXT "
                "DEFAULT 'ANALYST'"
            ),
        )

        _add_column_if_missing(
            conn,
            "playbook_executions",
            (
                "execution_mode TEXT "
                "DEFAULT 'SIMULATION'"
            ),
        )

        _add_column_if_missing(
            conn,
            "playbook_executions",
            (
                "approval_status TEXT "
                "DEFAULT 'PENDING'"
            ),
        )

        _add_column_if_missing(
            conn,
            "playbook_executions",
            "approved_by TEXT",
        )

        _add_column_if_missing(
            conn,
            "playbook_executions",
            "approved_at TEXT",
        )

        _add_column_if_missing(
            conn,
            "playbook_executions",
            "started_at TEXT",
        )

        _add_column_if_missing(
            conn,
            "playbook_executions",
            "completed_at TEXT",
        )

        _add_column_if_missing(
            conn,
            "playbook_executions",
            "step_results_json TEXT DEFAULT '[]'",
        )

        _add_column_if_missing(
            conn,
            "playbook_executions",
            "risk_score INTEGER DEFAULT 0",
        )

        _add_column_if_missing(
            conn,
            "playbook_executions",
            "severity TEXT DEFAULT 'LOW'",
        )

        _add_column_if_missing(
            conn,
            "playbook_executions",
            (
                "containment_requested INTEGER "
                "DEFAULT 0"
            ),
        )

        _add_column_if_missing(
            conn,
            "playbook_executions",
            (
                "containment_status TEXT "
                "DEFAULT 'NOT_REQUESTED'"
            ),
        )

        now = _utc_timestamp()
        workflow_json = json.dumps(
            DEFAULT_WORKFLOW
        )

        # Disable the original direct auto-block rule.
        conn.execute(
            """
            UPDATE playbooks
            SET enabled = 0,
                description = CASE
                    WHEN description IS NULL
                      OR description = ''
                    THEN
                        'Legacy direct auto-block playbook. Disabled after Stage 6 migration.'
                    ELSE description
                END,
                updated_at = ?
            WHERE name = 'Auto-Block Critical IOCs'
            """,
            (now,),
        )

        existing = conn.execute(
            """
            SELECT id
            FROM playbooks
            WHERE name = ?
            """,
            (DEFAULT_PLAYBOOK_NAME,),
        ).fetchone()

        if existing:
            conn.execute(
                """
                UPDATE playbooks
                SET description = ?,
                    trigger_condition = ?,
                    action_type = ?,
                    workflow_json = ?,
                    requires_approval = 1,
                    updated_at = ?
                WHERE id = ?
                """,
                (
                    (
                        "Investigates an incident IOC, enriches "
                        "it with threat intelligence, updates "
                        "risk and severity, then waits for "
                        "explicit analyst approval before "
                        "containment."
                    ),
                    "manual_analyst_execution",
                    "WORKFLOW",
                    workflow_json,
                    now,
                    existing["id"],
                ),
            )

        else:
            conn.execute(
                """
                INSERT INTO playbooks (
                    name,
                    description,
                    trigger_condition,
                    action_type,
                    workflow_json,
                    requires_approval,
                    enabled,
                    created_at,
                    updated_at
                )
                VALUES (?, ?, ?, ?, ?, 1, 1, ?, ?)
                """,
                (
                    DEFAULT_PLAYBOOK_NAME,
                    (
                        "Investigates an incident IOC, enriches "
                        "it with threat intelligence, updates "
                        "risk and severity, then waits for "
                        "explicit analyst approval before "
                        "containment."
                    ),
                    "manual_analyst_execution",
                    "WORKFLOW",
                    workflow_json,
                    now,
                    now,
                ),
            )

        conn.execute(
            """
            UPDATE playbooks
            SET created_at = COALESCE(
                    created_at,
                    ?
                ),
                updated_at = COALESCE(
                    updated_at,
                    ?
                )
            """,
            (now, now),
        )

        conn.commit()

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()


def _decode_json(
    value: str | None,
    default: Any,
) -> Any:
    if not value:
        return default

    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return default


def _serialise_playbook(row) -> dict[str, Any]:
    data = dict(row)

    data["enabled"] = bool(
        data.get("enabled")
    )

    data["requires_approval"] = bool(
        data.get("requires_approval")
    )

    data["workflow"] = _decode_json(
        data.pop("workflow_json", "[]"),
        [],
    )

    return data


def _serialise_execution(row) -> dict[str, Any]:
    data = dict(row)

    data["containment_requested"] = bool(
        data.get("containment_requested")
    )

    data["step_results"] = _decode_json(
        data.pop("step_results_json", "[]"),
        [],
    )

    return data


def list_playbooks() -> list[dict[str, Any]]:
    ensure_playbook_schema()
    conn = get_db_connection()

    try:
        rows = conn.execute(
            """
            SELECT *
            FROM playbooks
            ORDER BY enabled DESC, name ASC
            """
        ).fetchall()

        return [
            _serialise_playbook(row)
            for row in rows
        ]

    finally:
        conn.close()


def get_playbook(
    playbook_id: int,
) -> dict[str, Any]:
    ensure_playbook_schema()
    conn = get_db_connection()

    try:
        row = conn.execute(
            """
            SELECT *
            FROM playbooks
            WHERE id = ?
            """,
            (playbook_id,),
        ).fetchone()

        if not row:
            raise PlaybookError(
                f"Playbook #{playbook_id} was not found.",
                404,
            )

        return _serialise_playbook(row)

    finally:
        conn.close()


def set_playbook_enabled(
    playbook_id: int,
    enabled: bool,
) -> dict[str, Any]:
    ensure_playbook_schema()
    conn = get_db_connection()

    try:
        cursor = conn.execute(
            """
            UPDATE playbooks
            SET enabled = ?,
                updated_at = ?
            WHERE id = ?
            """,
            (
                1 if enabled else 0,
                _utc_timestamp(),
                playbook_id,
            ),
        )

        if cursor.rowcount == 0:
            raise PlaybookError(
                f"Playbook #{playbook_id} was not found.",
                404,
            )

        conn.commit()

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()

    return get_playbook(playbook_id)


def _add_timeline_event(
    incident_id: int,
    description: str,
) -> None:
    conn = get_db_connection()

    try:
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
                PLAYBOOK_ENGINE_IDENTITY,
                description,
            ),
        )

        conn.commit()

    finally:
        conn.close()


def get_execution(
    execution_id: int,
) -> dict[str, Any]:
    ensure_playbook_schema()
    conn = get_db_connection()

    try:
        row = conn.execute(
            """
            SELECT
                pe.*,
                p.name AS playbook_name,
                i.title AS incident_title,
                i.ioc_value AS incident_ioc,
                i.ioc_type AS incident_ioc_type
            FROM playbook_executions pe
            JOIN playbooks p
              ON p.id = pe.playbook_id
            JOIN incidents i
              ON i.id = pe.incident_id
            WHERE pe.id = ?
            """,
            (execution_id,),
        ).fetchone()

        if not row:
            raise PlaybookError(
                (
                    f"Playbook execution "
                    f"#{execution_id} was not found."
                ),
                404,
            )

        return _serialise_execution(row)

    finally:
        conn.close()


def list_executions(
    limit: int = 50,
) -> list[dict[str, Any]]:
    ensure_playbook_schema()

    safe_limit = max(
        1,
        min(int(limit), 200),
    )

    conn = get_db_connection()

    try:
        rows = conn.execute(
            """
            SELECT
                pe.*,
                p.name AS playbook_name,
                i.title AS incident_title,
                i.ioc_value AS incident_ioc,
                i.ioc_type AS incident_ioc_type
            FROM playbook_executions pe
            JOIN playbooks p
              ON p.id = pe.playbook_id
            JOIN incidents i
              ON i.id = pe.incident_id
            ORDER BY pe.id DESC
            LIMIT ?
            """,
            (safe_limit,),
        ).fetchall()

        return [
            _serialise_execution(row)
            for row in rows
        ]

    finally:
        conn.close()


def request_execution(
    playbook_id: int,
    incident_id: int,
) -> dict[str, Any]:
    """
    Create an execution request.

    No firewall action is performed here.
    """
    ensure_playbook_schema()
    conn = get_db_connection()

    try:
        playbook = conn.execute(
            """
            SELECT *
            FROM playbooks
            WHERE id = ?
            """,
            (playbook_id,),
        ).fetchone()

        if not playbook:
            raise PlaybookError(
                f"Playbook #{playbook_id} was not found.",
                404,
            )

        if not bool(playbook["enabled"]):
            raise PlaybookError(
                "The selected playbook is disabled.",
                409,
            )

        incident = conn.execute(
            """
            SELECT *
            FROM incidents
            WHERE id = ?
            """,
            (incident_id,),
        ).fetchone()

        if not incident:
            raise PlaybookError(
                f"Incident #{incident_id} was not found.",
                404,
            )

        if incident["status"] == "CLOSED":
            raise PlaybookError(
                (
                    "A playbook cannot be requested for "
                    "a closed incident."
                ),
                409,
            )

        if not str(
            incident["ioc_value"] or ""
        ).strip():
            raise PlaybookError(
                "The incident does not contain an IOC.",
                400,
            )

        execution_mode = (
            "SIMULATION"
            if PLAYBOOK_SIMULATION_MODE
            else "LIVE"
        )

        approval_status = (
            "PENDING"
            if bool(playbook["requires_approval"])
            else "APPROVED"
        )

        cursor = conn.execute(
            """
            INSERT INTO playbook_executions (
                playbook_id,
                incident_id,
                status,
                output_log,
                requested_by,
                execution_mode,
                approval_status,
                step_results_json,
                containment_requested,
                containment_status
            )
            VALUES (
                ?, ?, 'PENDING', ?, ?, ?, ?, '[]', 1,
                'AWAITING_APPROVAL'
            )
            """,
            (
                playbook_id,
                incident_id,
                (
                    "Execution requested. Awaiting explicit "
                    "analyst approval."
                ),
                ANALYST_IDENTITY,
                execution_mode,
                approval_status,
            ),
        )

        execution_id = cursor.lastrowid

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
                PLAYBOOK_ENGINE_IDENTITY,
                (
                    f"Playbook execution #{execution_id} "
                    f"requested in {execution_mode} mode. "
                    "No containment has been executed."
                ),
            ),
        )

        conn.commit()

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()

    if approval_status == "APPROVED":
        return approve_and_execute(
            execution_id
        )

    return get_execution(execution_id)


def _record_step(
    execution_id: int,
    incident_id: int,
    step_results: list[dict[str, Any]],
    *,
    step_id: str,
    name: str,
    status: str,
    message: str,
) -> None:
    result = {
        "step_id": step_id,
        "name": name,
        "status": status,
        "message": message,
        "timestamp": _utc_timestamp(),
    }

    step_results.append(result)

    _add_timeline_event(
        incident_id,
        (
            f"Playbook execution #{execution_id}: "
            f"{name} — {status}. {message}"
        ),
    )


def _mark_execution_failed(
    execution_id: int,
    incident_id: int,
    step_results: list[dict[str, Any]],
    message: str,
) -> dict[str, Any]:
    conn = get_db_connection()

    try:
        conn.execute(
            """
            UPDATE playbook_executions
            SET status = 'FAILED',
                completed_at = ?,
                output_log = ?,
                step_results_json = ?,
                containment_status = CASE
                    WHEN containment_status =
                         'AWAITING_APPROVAL'
                    THEN 'NOT_EXECUTED'
                    ELSE containment_status
                END
            WHERE id = ?
            """,
            (
                _utc_timestamp(),
                message,
                json.dumps(step_results),
                execution_id,
            ),
        )

        conn.commit()

    finally:
        conn.close()

    _add_timeline_event(
        incident_id,
        (
            f"Playbook execution #{execution_id} "
            f"failed. {message}"
        ),
    )

    audit_logger.log_event(
        "PLAYBOOK EXECUTION",
        str(incident_id),
        "HIGH",
        message,
        "FAILED",
    )

    return get_execution(execution_id)


def approve_and_execute(
    execution_id: int,
) -> dict[str, Any]:
    """
    Approve and execute a pending playbook request.

    In SIMULATION mode, UFW is never called.
    """
    ensure_playbook_schema()
    conn = get_db_connection()

    try:
        row = conn.execute(
            """
            SELECT
                pe.*,
                p.enabled AS playbook_enabled,
                p.workflow_json,
                p.name AS playbook_name,
                i.status AS incident_status,
                i.ioc_value,
                i.ioc_type
            FROM playbook_executions pe
            JOIN playbooks p
              ON p.id = pe.playbook_id
            JOIN incidents i
              ON i.id = pe.incident_id
            WHERE pe.id = ?
            """,
            (execution_id,),
        ).fetchone()

        if not row:
            raise PlaybookError(
                (
                    f"Playbook execution "
                    f"#{execution_id} was not found."
                ),
                404,
            )

        if row["status"] != "PENDING":
            raise PlaybookError(
                (
                    "Only a pending execution can be "
                    "approved."
                ),
                409,
            )

        if row["approval_status"] != "PENDING":
            raise PlaybookError(
                (
                    "This execution is no longer awaiting "
                    "approval."
                ),
                409,
            )

        if not bool(row["playbook_enabled"]):
            raise PlaybookError(
                (
                    "The playbook was disabled before "
                    "approval."
                ),
                409,
            )

        if row["incident_status"] == "CLOSED":
            raise PlaybookError(
                (
                    "The incident was closed before the "
                    "playbook was approved."
                ),
                409,
            )

        conn.execute(
            """
            UPDATE playbook_executions
            SET approval_status = 'APPROVED',
                approved_by = ?,
                approved_at = ?,
                started_at = ?,
                output_log = ?
            WHERE id = ?
            """,
            (
                ANALYST_IDENTITY,
                _utc_timestamp(),
                _utc_timestamp(),
                (
                    "Analyst approval recorded. "
                    "Execution started."
                ),
                execution_id,
            ),
        )

        conn.commit()

        execution_mode = row["execution_mode"]
        incident_id = row["incident_id"]
        ioc_value = str(
            row["ioc_value"] or ""
        ).strip()

        ioc_type = str(
            row["ioc_type"] or "UNKNOWN"
        ).upper()

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()

    step_results: list[dict[str, Any]] = []
    output_lines: list[str] = []

    try:
        # Step 1: IOC validation
        if (
            ioc_type not in {"IP", "DOMAIN", "HASH"}
            or not ioc_value
        ):
            _record_step(
                execution_id,
                incident_id,
                step_results,
                step_id="validate_ioc",
                name="Validate IOC",
                status="FAILED",
                message="The incident IOC is invalid.",
            )

            return _mark_execution_failed(
                execution_id,
                incident_id,
                step_results,
                "The incident IOC is invalid.",
            )

        validation_message = (
            f"Validated {ioc_type} IOC {ioc_value}."
        )

        _record_step(
            execution_id,
            incident_id,
            step_results,
            step_id="validate_ioc",
            name="Validate IOC",
            status="SUCCESS",
            message=validation_message,
        )

        output_lines.append(validation_message)

        # Step 2: threat intelligence
        intel = ThreatIntelAggregator.analyze_all(
            ioc_value,
            ioc_type,
        )

        if intel.get("input_error"):
            message = str(
                intel["input_error"]
            )

            _record_step(
                execution_id,
                incident_id,
                step_results,
                step_id="threat_intelligence",
                name="Threat-intelligence enrichment",
                status="FAILED",
                message=message,
            )

            return _mark_execution_failed(
                execution_id,
                incident_id,
                step_results,
                message,
            )

        risk_score = int(
            intel.get("risk_score", 0)
        )

        severity = str(
            intel.get("severity", "LOW")
        )

        intel_message = (
            f"Risk score {risk_score}/100; "
            f"severity {severity}; "
            f"evidence mode "
            f"{intel.get('evidence_mode', 'NONE')}; "
            f"overall status "
            f"{intel.get('overall_status', 'UNAVAILABLE')}."
        )

        _record_step(
            execution_id,
            incident_id,
            step_results,
            step_id="threat_intelligence",
            name="Threat-intelligence enrichment",
            status="SUCCESS",
            message=intel_message,
        )

        output_lines.append(intel_message)

        # Step 3: update incident
        conn = get_db_connection()

        try:
            conn.execute(
                """
                UPDATE incidents
                SET risk_score = ?,
                    severity = ?,
                    status = 'INVESTIGATING',
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                (
                    risk_score,
                    severity,
                    incident_id,
                ),
            )

            conn.commit()

        finally:
            conn.close()

        update_message = (
            "Incident updated to INVESTIGATING with "
            f"risk score {risk_score}/100 and severity "
            f"{severity}."
        )

        _record_step(
            execution_id,
            incident_id,
            step_results,
            step_id="update_incident",
            name="Update incident risk and severity",
            status="SUCCESS",
            message=update_message,
        )

        output_lines.append(update_message)

        # Step 4: containment
        if execution_mode == "SIMULATION":
            containment_status = "SIMULATED"

            containment_message = (
                "Simulation completed. The containment "
                "command was not sent to UFW, and the "
                "incident remains INVESTIGATING."
            )

            _record_step(
                execution_id,
                incident_id,
                step_results,
                step_id="containment",
                name="UFW containment",
                status="SIMULATED",
                message=containment_message,
            )

            output_lines.append(
                containment_message
            )

            final_status = "SUCCESS"

        else:
            execution_status, execution_notes = (
                execute_kernel_block(
                    {
                        "type": ioc_type,
                        "value": ioc_value,
                    }
                )
            )

            containment_status = execution_status

            if execution_status == "SUCCESS":
                conn = get_db_connection()

                try:
                    conn.execute(
                        """
                        UPDATE incidents
                        SET status = 'CONTAINED',
                            updated_at =
                                CURRENT_TIMESTAMP
                        WHERE id = ?
                        """,
                        (incident_id,),
                    )

                    conn.commit()

                finally:
                    conn.close()

                containment_message = (
                    "UFW containment confirmed. "
                    f"{execution_notes}"
                )

                _record_step(
                    execution_id,
                    incident_id,
                    step_results,
                    step_id="containment",
                    name="UFW containment",
                    status="SUCCESS",
                    message=containment_message,
                )

                final_status = "SUCCESS"

            else:
                containment_message = (
                    "UFW containment was not confirmed. "
                    f"Status: {execution_status}. "
                    f"Details: {execution_notes}"
                )

                _record_step(
                    execution_id,
                    incident_id,
                    step_results,
                    step_id="containment",
                    name="UFW containment",
                    status="FAILED",
                    message=containment_message,
                )

                final_status = "FAILED"

            output_lines.append(
                containment_message
            )

        output_log = "\n".join(
            output_lines
        )

        conn = get_db_connection()

        try:
            conn.execute(
                """
                UPDATE playbook_executions
                SET status = ?,
                    completed_at = ?,
                    output_log = ?,
                    step_results_json = ?,
                    risk_score = ?,
                    severity = ?,
                    containment_status = ?
                WHERE id = ?
                """,
                (
                    final_status,
                    _utc_timestamp(),
                    output_log,
                    json.dumps(step_results),
                    risk_score,
                    severity,
                    containment_status,
                    execution_id,
                ),
            )

            conn.commit()

        finally:
            conn.close()

        _add_timeline_event(
            incident_id,
            (
                f"Playbook execution #{execution_id} "
                f"completed with status {final_status}. "
                f"Containment status: "
                f"{containment_status}."
            ),
        )

        audit_logger.log_event(
            "PLAYBOOK EXECUTION",
            ioc_value,
            severity,
            output_log,
            final_status,
        )

        return get_execution(execution_id)

    except PlaybookError:
        raise

    except Exception as exc:
        return _mark_execution_failed(
            execution_id,
            incident_id,
            step_results,
            (
                "Unexpected playbook engine error: "
                f"{type(exc).__name__}: {exc}"
            ),
        )


def reject_execution(
    execution_id: int,
) -> dict[str, Any]:
    ensure_playbook_schema()
    conn = get_db_connection()

    try:
        execution = conn.execute(
            """
            SELECT *
            FROM playbook_executions
            WHERE id = ?
            """,
            (execution_id,),
        ).fetchone()

        if not execution:
            raise PlaybookError(
                (
                    f"Playbook execution "
                    f"#{execution_id} was not found."
                ),
                404,
            )

        if (
            execution["status"] != "PENDING"
            or execution["approval_status"]
            != "PENDING"
        ):
            raise PlaybookError(
                (
                    "Only a pending approval request "
                    "can be rejected."
                ),
                409,
            )

        message = (
            "Analyst rejected the containment request. "
            "No firewall action was executed."
        )

        conn.execute(
            """
            UPDATE playbook_executions
            SET status = 'FAILED',
                approval_status = 'REJECTED',
                approved_by = ?,
                approved_at = ?,
                completed_at = ?,
                output_log = ?,
                containment_status = 'NOT_EXECUTED'
            WHERE id = ?
            """,
            (
                ANALYST_IDENTITY,
                _utc_timestamp(),
                _utc_timestamp(),
                message,
                execution_id,
            ),
        )

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
                execution["incident_id"],
                PLAYBOOK_ENGINE_IDENTITY,
                (
                    f"Playbook execution #{execution_id} "
                    "was rejected by the analyst. "
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

    return get_execution(execution_id)
