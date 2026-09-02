import re

import requests
from flask import Blueprint, jsonify, request

import audit_logger
from models.database import get_db_connection
from services.threat_intel import ThreatIntelAggregator
from settings import RASA_REST_URL
from soar_engine import (
    execute_kernel_block,
    execute_kernel_unblock,
)


chat_bp = Blueprint("chat", __name__)


IP_PATTERN = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
DOMAIN_PATTERN = r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b"
HASH_PATTERN = r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{64}\b"

BLOCK_TERMS = ("block", "contain", "deny", "isolate")
UNBLOCK_TERMS = ("unblock", "allow")


def _contains_command(message, terms):
    message = message.lower()

    return any(
        re.search(rf"\b{re.escape(term)}\b", message)
        for term in terms
    )


def _severity_from_score(risk_score):
    if risk_score >= 75:
        return "CRITICAL"

    if risk_score >= 50:
        return "HIGH"

    if risk_score >= 25:
        return "MEDIUM"

    return "LOW"


def _get_verdict(intel, source):
    source_data = intel.get(source) or {}

    status = source_data.get(
        "status",
        "UNAVAILABLE",
    )

    verdict = source_data.get(
        "verdict",
        "UNAVAILABLE",
    )

    return f"[{status}] {verdict}"


def _create_incident(
    title,
    description,
    ioc_value,
    ioc_type,
    severity,
    risk_score,
    status,
    action_description,
):
    conn = get_db_connection()

    try:
        cursor = conn.cursor()

        cursor.execute(
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
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                title,
                description,
                ioc_value,
                ioc_type,
                severity,
                risk_score,
                status,
                "SOAR_ASSISTANT",
            ),
        )

        incident_id = cursor.lastrowid

        cursor.execute(
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
                "SOAR_ASSISTANT",
                action_description,
            ),
        )

        conn.commit()
        return incident_id

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()


def _query_rasa(user_message):
    try:
        response = requests.post(
            RASA_REST_URL,
            json={
                "sender": "supervisor_demo",
                "message": user_message,
            },
            timeout=4,
        )

        if response.status_code == 200:
            messages = response.json()

            rasa_text = "\n\n".join(
                message.get("text", "")
                for message in messages
                if message.get("text")
            )

            if rasa_text:
                return rasa_text

        return "Rasa returned no conversational response."

    except requests.RequestException:
        return (
            "Rasa service is unavailable. "
            "Local SOAR processing continued."
        )


@chat_bp.route("/api/chat", methods=["POST"])
def send_to_rasa():
    data = request.get_json(silent=True) or {}
    user_message = str(data.get("message", "")).strip()

    if not user_message:
        return jsonify(
            {
                "status": "error",
                "response": "Please enter a message.",
                "recommendation": "No action was performed.",
            }
        ), 400

    ips = re.findall(IP_PATTERN, user_message)

    domains = [
        domain
        for domain in re.findall(DOMAIN_PATTERN, user_message)
        if not re.fullmatch(IP_PATTERN, domain)
    ]

    hashes = re.findall(HASH_PATTERN, user_message)

    block_requested = _contains_command(
        user_message,
        BLOCK_TERMS,
    )

    unblock_requested = _contains_command(
        user_message,
        UNBLOCK_TERMS,
    )

    rasa_text = _query_rasa(user_message)

    ioc_type = None
    target = None
    risk_score = 0
    intel_summary = ""
    default_recommendation = (
        "No IOC was detected and no security action was performed."
    )

    if ips:
        ioc_type = "IP"
        target = ips[0]

    elif domains:
        ioc_type = "DOMAIN"
        target = domains[0]

    elif hashes:
        ioc_type = "HASH"
        target = hashes[0]

    if ioc_type in {"IP", "DOMAIN"}:
        try:
            intel = ThreatIntelAggregator.analyze_all(
                target,
                ioc_type,
            )

            risk_score = int(intel.get("risk_score", 0))

            evidence_mode = intel.get(
                "evidence_mode",
                "NONE",
            )

            overall_status = intel.get(
                "overall_status",
                "UNAVAILABLE",
            )

            intel_summary = (
                f"\n\nThreat-intelligence result "
                f"({evidence_mode}; overall status "
                f"{overall_status}):\n"
                f"- VirusTotal: "
                f"{_get_verdict(intel, 'virustotal')}\n"
                f"- AbuseIPDB: "
                f"{_get_verdict(intel, 'abuseipdb')}\n"
                f"- AlienVault OTX: "
                f"{_get_verdict(intel, 'alienvault')}\n"
                f"- ThreatFox: "
                f"{_get_verdict(intel, 'threatfox')}\n"
                f"- Composite risk score: {risk_score}/100"
            )

        except Exception as exc:
            intel_summary = (
                "\n\nThreat-intelligence lookup failed: "
                f"{type(exc).__name__}."
            )

    elif ioc_type == "HASH":
        intel_summary = (
            "\n\nA file hash was extracted. "
            "UFW cannot block file hashes."
        )

        default_recommendation = (
            "Investigate the hash using malware-analysis and "
            "endpoint-response controls."
        )

    containment = None
    incident_id = None
    severity = _severity_from_score(risk_score)

    if target and unblock_requested:
        execution_status, execution_notes = (
            execute_kernel_unblock(
                {
                    "type": ioc_type,
                    "value": target,
                }
            )
        )

        audit_logger.log_event(
            f"KERNEL UNBLOCK ({ioc_type})",
            target,
            severity,
            execution_notes,
            execution_status,
        )

        containment = {
            "action": "UNBLOCK",
            "status": execution_status,
            "notes": execution_notes,
        }

        if execution_status == "SUCCESS":
            recommendation = (
                f"UFW unblock confirmed for `{target}`. "
                f"Execution details: {execution_notes}"
            )
        else:
            recommendation = (
                f"UFW unblock was not confirmed for `{target}`. "
                f"Status: {execution_status}. "
                f"Details: {execution_notes}"
            )

    elif target and block_requested:
        execution_status, execution_notes = (
            execute_kernel_block(
                {
                    "type": ioc_type,
                    "value": target,
                }
            )
        )

        containment_confirmed = execution_status == "SUCCESS"

        incident_status = (
            "CONTAINED"
            if containment_confirmed
            else "OPEN"
        )

        incident_id = _create_incident(
            title=f"[Containment Request] {target}",
            description=(
                f"Explicit containment command received. "
                f"Execution result: {execution_status}. "
                f"{execution_notes}"
            ),
            ioc_value=target,
            ioc_type=ioc_type,
            severity=severity,
            risk_score=risk_score,
            status=incident_status,
            action_description=(
                f"Firewall containment status: "
                f"{execution_status}. {execution_notes}"
            ),
        )

        audit_logger.log_event(
            f"KERNEL BLOCK ({ioc_type})",
            target,
            severity,
            execution_notes,
            execution_status,
        )

        containment = {
            "action": "BLOCK",
            "status": execution_status,
            "notes": execution_notes,
        }

        if containment_confirmed:
            recommendation = (
                f"Containment confirmed for `{target}`. "
                f"Incident #{incident_id} was recorded as CONTAINED. "
                f"Execution details: {execution_notes}"
            )

        elif execution_status == "BLOCKED_BY_POLICY":
            recommendation = (
                f"Containment was denied by policy for `{target}`. "
                f"Incident #{incident_id} remains OPEN. "
                f"Details: {execution_notes}"
            )

        else:
            recommendation = (
                f"Containment was not confirmed for `{target}`. "
                f"Incident #{incident_id} remains OPEN. "
                f"Status: {execution_status}. "
                f"Details: {execution_notes}"
            )

    elif target and risk_score >= 50:
        incident_id = _create_incident(
            title=f"[Threat Alert] {target}",
            description=(
                f"High-risk IOC detected with score "
                f"{risk_score}/100. No automatic firewall "
                f"action was executed."
            ),
            ioc_value=target,
            ioc_type=ioc_type,
            severity=severity,
            risk_score=risk_score,
            status="OPEN",
            action_description=(
                "High-risk IOC detected. Awaiting explicit "
                "analyst containment approval."
            ),
        )

        audit_logger.log_event(
            "THREAT INTELLIGENCE ALERT",
            target,
            severity,
            (
                f"Risk score {risk_score}/100. "
                "No firewall action executed."
            ),
            "ANALYSIS_ONLY",
        )

        recommendation = (
            f"High-risk IOC `{target}` detected with score "
            f"{risk_score}/100. Incident #{incident_id} was "
            f"created as OPEN. No firewall rule was applied "
            f"because no explicit containment command was given."
        )

    elif target:
        recommendation = (
            f"Analysis completed for `{target}` with risk score "
            f"{risk_score}/100. No containment was executed."
        )

        audit_logger.log_event(
            "THREAT INTELLIGENCE QUERY",
            target,
            severity,
            f"Risk score {risk_score}/100.",
            "ANALYSIS_ONLY",
        )

    else:
        recommendation = default_recommendation

    if block_requested or unblock_requested:
        response_text = (
            "The command was processed through the verified "
            "local execution path."
            + intel_summary
        )
    else:
        response_text = rasa_text + intel_summary

    return jsonify(
        {
            "status": "success",
            "response": response_text,
            "recommendation": recommendation,
            "incident_id": incident_id,
            "containment": containment,
        }
    )
