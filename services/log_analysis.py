from __future__ import annotations

import ipaddress
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any


IP_PATTERN = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
)

AUTH_FAILURE_TERMS = (
    "failed password",
    "authentication failure",
    "invalid user",
    "failed login",
    "login failure",
    "maximum authentication attempts",
    "brute force",
)

MALWARE_TERMS = (
    "malware",
    "trojan",
    "ransomware",
    "command and control",
    "command-and-control",
    "c2 traffic",
    "exploit attempt",
    "shellcode",
    "reverse shell",
    "web shell",
)

SEVERITY_ORDER = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


def _valid_ips(text: str) -> list[str]:
    addresses: list[str] = []

    for candidate in IP_PATTERN.findall(text):
        try:
            normalised = str(
                ipaddress.ip_address(candidate)
            )
        except ValueError:
            continue

        if normalised not in addresses:
            addresses.append(normalised)

    return addresses


def _highest_severity(
    current: str,
    candidate: str,
) -> str:
    if (
        SEVERITY_ORDER[candidate]
        > SEVERITY_ORDER[current]
    ):
        return candidate

    return current


def _suricata_finding(
    payload: dict[str, Any],
    line_number: int,
) -> dict[str, Any] | None:
    alert = payload.get("alert")

    if not isinstance(alert, dict):
        return None

    source_ip = (
        payload.get("src_ip")
        or payload.get("source_ip")
        or alert.get("src_ip")
    )

    signature = str(
        alert.get(
            "signature",
            "Suricata IDS alert",
        )
    )

    try:
        numeric_severity = int(
            alert.get("severity", 3)
        )
    except (TypeError, ValueError):
        numeric_severity = 3

    severity_map = {
        1: "CRITICAL",
        2: "HIGH",
        3: "MEDIUM",
    }

    severity = severity_map.get(
        numeric_severity,
        "MEDIUM",
    )

    return {
        "line_number": line_number,
        "category": "SURICATA_ALERT",
        "severity": severity,
        "description": signature,
        "iocs": (
            _valid_ips(str(source_ip))
            if source_ip
            else []
        ),
    }


def analyze_log_text(
    text: str,
    filename: str = "uploaded.log",
) -> dict[str, Any]:
    """
    Analyse plain-text, syslog, CSV-like and Suricata
    JSON-line log content.

    The function performs deterministic local analysis only.
    It does not execute firewall actions and does not call
    external threat-intelligence providers.
    """
    lines = text.splitlines()

    findings: list[dict[str, Any]] = []
    all_iocs: Counter[str] = Counter()
    suspicious_iocs: Counter[str] = Counter()

    auth_failure_count = 0
    suricata_alert_count = 0
    malware_indicator_count = 0

    overall_severity = "LOW"

    for line_number, raw_line in enumerate(
        lines,
        start=1,
    ):
        line = raw_line.strip()

        if not line:
            continue

        line_ips = _valid_ips(line)

        for ip in line_ips:
            all_iocs[ip] += 1

        payload = None

        if line.startswith("{") and line.endswith("}"):
            try:
                decoded = json.loads(line)

                if isinstance(decoded, dict):
                    payload = decoded
            except json.JSONDecodeError:
                payload = None

        if payload is not None:
            finding = _suricata_finding(
                payload,
                line_number,
            )

            if finding:
                findings.append(finding)
                suricata_alert_count += 1

                overall_severity = _highest_severity(
                    overall_severity,
                    finding["severity"],
                )

                for ip in finding["iocs"]:
                    suspicious_iocs[ip] += 1

                continue

        lower_line = line.lower()

        if any(
            term in lower_line
            for term in AUTH_FAILURE_TERMS
        ):
            auth_failure_count += 1

            finding_severity = "MEDIUM"

            findings.append(
                {
                    "line_number": line_number,
                    "category": "AUTHENTICATION_FAILURE",
                    "severity": finding_severity,
                    "description": line[:300],
                    "iocs": line_ips,
                }
            )

            overall_severity = _highest_severity(
                overall_severity,
                finding_severity,
            )

            for ip in line_ips:
                suspicious_iocs[ip] += 1

        if any(
            term in lower_line
            for term in MALWARE_TERMS
        ):
            malware_indicator_count += 1

            finding_severity = "HIGH"

            findings.append(
                {
                    "line_number": line_number,
                    "category": "MALWARE_INDICATOR",
                    "severity": finding_severity,
                    "description": line[:300],
                    "iocs": line_ips,
                }
            )

            overall_severity = _highest_severity(
                overall_severity,
                finding_severity,
            )

            for ip in line_ips:
                suspicious_iocs[ip] += 1

    repeated_attackers = {
        ip: count
        for ip, count in suspicious_iocs.items()
        if count >= 3
    }

    if repeated_attackers:
        overall_severity = _highest_severity(
            overall_severity,
            (
                "HIGH"
                if max(repeated_attackers.values()) >= 5
                else "MEDIUM"
            ),
        )

    base_risk = {
        "LOW": 10,
        "MEDIUM": 45,
        "HIGH": 75,
        "CRITICAL": 90,
    }[overall_severity]

    risk_score = min(
        100,
        base_risk
        + min(auth_failure_count * 2, 10)
        + min(suricata_alert_count * 3, 10)
        + min(malware_indicator_count * 4, 10),
    )

    if not findings:
        risk_score = 0

    suspicious_list = [
        {
            "value": ip,
            "type": "IP",
            "occurrences": count,
        }
        for ip, count in suspicious_iocs.most_common(20)
    ]

    extracted_iocs = [
        {
            "value": ip,
            "type": "IP",
            "occurrences": count,
        }
        for ip, count in all_iocs.most_common(50)
    ]

    if overall_severity == "CRITICAL":
        recommendation = (
            "Escalate immediately. Review the critical IDS "
            "alerts, correlate the listed IP addresses with "
            "other telemetry and request explicit analyst "
            "approval before containment."
        )

    elif overall_severity == "HIGH":
        recommendation = (
            "Open or update incidents for the suspicious IP "
            "addresses, correlate repeated events and consider "
            "containment after analyst validation."
        )

    elif overall_severity == "MEDIUM":
        recommendation = (
            "Investigate the detected authentication or IDS "
            "events and correlate them with host and network "
            "telemetry."
        )

    else:
        recommendation = (
            "No significant malicious pattern was identified "
            "by the local parser. Continue monitoring."
        )

    return {
        "filename": filename,
        "line_count": len(lines),
        "finding_count": len(findings),
        "overall_severity": overall_severity,
        "risk_score": risk_score,
        "status": (
            "SUSPICIOUS"
            if findings
            else "NO_SIGNIFICANT_THREAT"
        ),
        "statistics": {
            "authentication_failures":
                auth_failure_count,
            "suricata_alerts":
                suricata_alert_count,
            "malware_indicators":
                malware_indicator_count,
            "unique_ips":
                len(all_iocs),
        },
        "extracted_iocs": extracted_iocs,
        "suspicious_iocs": suspicious_list,
        "findings": findings[:100],
        "recommendation": recommendation,
        "analysis_mode": "LOCAL_DETERMINISTIC",
    }


def analyze_log_file(
    path: Path,
) -> dict[str, Any]:
    raw_bytes = path.read_bytes()

    text = raw_bytes.decode(
        "utf-8",
        errors="replace",
    )

    return analyze_log_text(
        text,
        filename=path.name,
    )


def format_log_analysis(
    analysis: dict[str, Any],
) -> str:
    suspicious = analysis.get(
        "suspicious_iocs",
        [],
    )

    if suspicious:
        ioc_text = ", ".join(
            (
                f"{item['value']} "
                f"({item['occurrences']} events)"
            )
            for item in suspicious[:10]
        )
    else:
        ioc_text = "None"

    statistics = analysis.get(
        "statistics",
        {},
    )

    return (
        "LOG ANALYSIS RESULT\n"
        f"- File: {analysis.get('filename')}\n"
        f"- Mode: {analysis.get('analysis_mode')}\n"
        f"- Lines analysed: "
        f"{analysis.get('line_count', 0)}\n"
        f"- Findings: "
        f"{analysis.get('finding_count', 0)}\n"
        f"- Severity: "
        f"{analysis.get('overall_severity')}\n"
        f"- Risk score: "
        f"{analysis.get('risk_score', 0)}/100\n"
        f"- Authentication failures: "
        f"{statistics.get('authentication_failures', 0)}\n"
        f"- Suricata alerts: "
        f"{statistics.get('suricata_alerts', 0)}\n"
        f"- Malware indicators: "
        f"{statistics.get('malware_indicators', 0)}\n"
        f"- Suspicious IPs: {ioc_text}\n\n"
        "RECOMMENDATION\n"
        f"{analysis.get('recommendation')}"
    )
