import ipaddress
import re
import socket
import sqlite3
import subprocess
from services.threat_intel import ThreatIntelAggregator



ALLOW_LIST = ["127.0.0.1", "8.8.8.8", "8.8.4.4", "1.1.1.1", "localhost"]

# -------------------------------------------------------------
# 1. IOC EXTRACTION (Regex)
# -------------------------------------------------------------
def extract_ioc(text):
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    domain_pattern = r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b'
    hash_pattern = r'\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{64}\b'

    ips = re.findall(ip_pattern, text)
    if ips:
        return {"type": "IP", "value": ips[0]}

    hashes = re.findall(hash_pattern, text)
    if hashes:
        return {"type": "HASH", "value": hashes[0]}

    domains = re.findall(domain_pattern, text)
    valid_domains = [d for d in domains if not d.endswith(('.py', '.html', '.json', '.txt', '.js', '.css'))]
    if valid_domains:
        return {"type": "DOMAIN", "value": valid_domains[0]}

    return {"type": "UNKNOWN", "value": "N/A"}

# -------------------------------------------------------------
# 2. THREAT INTEL BROAD SCAN APIS
# -------------------------------------------------------------
def aggregate_threat_intel(ioc):
    """
    Compatibility wrapper around the central intelligence
    service.

    Returns the original three-value structure expected by
    older application components:
        severity, source_summary, recommendation
    """
    ioc_type = str(
        ioc.get("type", "UNKNOWN")
    ).upper()

    ioc_value = str(
        ioc.get("value", "")
    ).strip()

    if ioc_type == "UNKNOWN":
        return (
            "INFORMATIONAL",
            "No valid IOC was supplied.",
            "No threat-intelligence action was performed.",
        )

    result = ThreatIntelAggregator.analyze_all(
        ioc_value,
        ioc_type,
    )

    source_summary = "; ".join(
        (
            f"{source_name}: "
            f"[{source['status']}] "
            f"{source['verdict']}"
        )
        for source_name, source
        in result["sources"].items()
    )

    return (
        result["severity"],
        source_summary,
        result["recommendation"],
    )

# -------------------------------------------------------------
# 3. KERNEL FIREWALL & SINKHOLE ORCHESTRATION
# -------------------------------------------------------------
def _resolve_firewall_targets(ioc):
    """Validate an IOC and return IP addresses suitable for UFW."""
    target = str(ioc.get("value", "")).strip()
    ioc_type = str(ioc.get("type", "UNKNOWN")).upper().strip()

    if not target or ioc_type == "UNKNOWN":
        return "FAILED", [], "No valid IOC was supplied."

    if target in ALLOW_LIST:
        return (
            "BLOCKED_BY_POLICY",
            [],
            f"Policy denied the action because {target} is allow-listed.",
        )

    if ioc_type == "IP":
        try:
            ipaddress.ip_address(target)
        except ValueError:
            return "FAILED", [], f"Invalid IP address: {target}"

        return "READY", [target], f"Validated IP address {target}."

    if ioc_type == "DOMAIN":
        try:
            resolved_ip = socket.gethostbyname(target)
            ipaddress.ip_address(resolved_ip)
        except (socket.gaierror, ValueError):
            return (
                "FAILED",
                [],
                f"DNS resolution failed for domain {target}.",
            )

        return (
            "READY",
            [resolved_ip],
            f"Resolved {target} to {resolved_ip}.",
        )

    if ioc_type == "HASH":
        return (
            "UNSUPPORTED",
            [],
            "File hashes cannot be blocked using UFW.",
        )

    return (
        "UNSUPPORTED",
        [],
        f"IOC type {ioc_type} is not supported by UFW.",
    )


def execute_kernel_block(ioc):
    """Apply a UFW deny rule and return the real execution result."""
    validation_status, target_ips, validation_note = (
        _resolve_firewall_targets(ioc)
    )

    if validation_status != "READY":
        return validation_status, validation_note

    successful = []
    failed = []

    for ip in target_ips:
        try:
            result = subprocess.run(
                ["sudo", "ufw", "deny", "from", ip],
                capture_output=True,
                text=True,
                timeout=8,
                check=False,
            )

            command_output = (
                result.stdout.strip()
                or result.stderr.strip()
                or "No command output returned."
            )

            if result.returncode == 0:
                successful.append(f"{ip}: {command_output}")
            else:
                failed.append(
                    f"{ip}: UFW exited with code "
                    f"{result.returncode}: {command_output}"
                )

        except subprocess.TimeoutExpired:
            failed.append(f"{ip}: UFW command timed out.")

        except Exception as exc:
            failed.append(f"{ip}: execution error: {exc}")

    if successful and not failed:
        return "SUCCESS", " | ".join(successful)

    if successful and failed:
        return (
            "PARTIAL",
            "Successful: "
            + " | ".join(successful)
            + " ; Failed: "
            + " | ".join(failed),
        )

    return "FAILED", " | ".join(failed)


def execute_kernel_unblock(ioc):
    """Remove a UFW deny rule and return the real execution result."""
    validation_status, target_ips, validation_note = (
        _resolve_firewall_targets(ioc)
    )

    if validation_status == "BLOCKED_BY_POLICY":
        # Allow-listed targets do not need the block-policy restriction
        # when a deny rule is being removed.
        target = str(ioc.get("value", "")).strip()
        ioc_type = str(ioc.get("type", "UNKNOWN")).upper().strip()

        if ioc_type == "IP":
            target_ips = [target]
            validation_status = "READY"

        elif ioc_type == "DOMAIN":
            try:
                target_ips = [socket.gethostbyname(target)]
                validation_status = "READY"
            except socket.gaierror:
                return (
                    "FAILED",
                    f"DNS resolution failed for domain {target}.",
                )

    if validation_status != "READY":
        return validation_status, validation_note

    successful = []
    failed = []

    for ip in target_ips:
        try:
            result = subprocess.run(
                ["sudo", "ufw", "delete", "deny", "from", ip],
                capture_output=True,
                text=True,
                timeout=8,
                check=False,
            )

            command_output = (
                result.stdout.strip()
                or result.stderr.strip()
                or "No command output returned."
            )

            if result.returncode == 0:
                successful.append(f"{ip}: {command_output}")
            else:
                failed.append(
                    f"{ip}: UFW exited with code "
                    f"{result.returncode}: {command_output}"
                )

        except subprocess.TimeoutExpired:
            failed.append(f"{ip}: UFW command timed out.")

        except Exception as exc:
            failed.append(f"{ip}: execution error: {exc}")

    if successful and not failed:
        return "SUCCESS", " | ".join(successful)

    if successful and failed:
        return (
            "PARTIAL",
            "Successful: "
            + " | ".join(successful)
            + " ; Failed: "
            + " | ".join(failed),
        )

    return "FAILED", " | ".join(failed)
