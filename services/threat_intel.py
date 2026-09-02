from __future__ import annotations

import hashlib
import ipaddress
import re
from datetime import datetime, timezone
from typing import Any

import requests

from settings import (
    ABUSEIPDB_API_KEY,
    ALIENVAULT_OTX_API_KEY,
    SOAR_SIMULATION_MODE,
    VIRUSTOTAL_API_KEY,
)


SOURCE_STATUSES = {
    "LIVE",
    "SIMULATED",
    "UNAVAILABLE",
    "ERROR",
}

SOURCE_WEIGHTS = {
    "virustotal": 0.40,
    "abuseipdb": 0.30,
    "alienvault": 0.15,
    "threatfox": 0.15,
}


class ThreatIntelAggregator:
    """
    Central threat-intelligence service.

    Every source result has one explicit status:

    LIVE
        Data came from the real provider.

    SIMULATED
        Synthetic data was generated for controlled testing.

    UNAVAILABLE
        The source was not configured or was not applicable.

    ERROR
        A live provider request failed.
    """

    TIMEOUT_SECONDS = 5

    @classmethod
    def analyze_all(
        cls,
        ioc_value: str,
        ioc_type: str = "IP",
    ) -> dict[str, Any]:
        value, kind, validation_error = cls._normalise_ioc(
            ioc_value,
            ioc_type,
        )

        if validation_error:
            sources = {
                source: cls._result(
                    status="UNAVAILABLE",
                    verdict="INVALID_INPUT",
                    risk=0,
                    contribution=0,
                    message=validation_error,
                )
                for source in SOURCE_WEIGHTS
            }

            return cls._build_response(
                value,
                kind,
                sources,
                forced_status="ERROR",
                input_error=validation_error,
            )

        sources = {
            "virustotal": cls._check_virustotal(
                value,
                kind,
            ),
            "abuseipdb": cls._check_abuseipdb(
                value,
                kind,
            ),
            "alienvault": cls._check_alienvault(
                value,
                kind,
            ),
            "threatfox": cls._check_threatfox(
                value,
                kind,
            ),
        }

        return cls._build_response(
            value,
            kind,
            sources,
        )

    @classmethod
    def _build_response(
        cls,
        ioc_value: str,
        ioc_type: str,
        sources: dict[str, dict[str, Any]],
        forced_status: str | None = None,
        input_error: str | None = None,
    ) -> dict[str, Any]:
        risk_score = min(
            100,
            sum(
                int(source.get("contribution", 0))
                for source in sources.values()
            ),
        )

        severity = cls._severity_from_score(risk_score)

        status_counts = {
            status: sum(
                1
                for source in sources.values()
                if source.get("status") == status
            )
            for status in sorted(SOURCE_STATUSES)
        }

        live_count = status_counts["LIVE"]
        simulated_count = status_counts["SIMULATED"]
        error_count = status_counts["ERROR"]

        if forced_status:
            overall_status = forced_status
        elif live_count:
            overall_status = "LIVE"
        elif simulated_count:
            overall_status = "SIMULATED"
        elif error_count:
            overall_status = "ERROR"
        else:
            overall_status = "UNAVAILABLE"

        if live_count and simulated_count:
            evidence_mode = "MIXED"
        elif live_count:
            evidence_mode = "LIVE_ONLY"
        elif simulated_count:
            evidence_mode = "SIMULATION_ONLY"
        else:
            evidence_mode = "NONE"

        coverage = live_count + simulated_count

        recommendation = cls._recommendation(
            ioc_value,
            ioc_type,
            risk_score,
            severity,
            evidence_mode,
            coverage,
        )

        result = {
            "ioc_value": ioc_value,
            "ioc_type": ioc_type,
            "risk_score": risk_score,
            "severity": severity,
            "overall_status": overall_status,
            "evidence_mode": evidence_mode,
            "coverage": coverage,
            "source_status_counts": status_counts,
            "input_error": input_error,
            "recommendation": recommendation,
            "generated_at": datetime.now(
                timezone.utc
            ).isoformat(),
            "sources": sources,
        }

        # Compatibility aliases for existing Flask code.
        result.update(sources)

        return result

    @staticmethod
    def _normalise_ioc(
        ioc_value: str,
        ioc_type: str,
    ) -> tuple[str, str, str | None]:
        value = str(ioc_value or "").strip()
        kind = str(ioc_type or "").upper().strip()

        if kind not in {"IP", "DOMAIN", "HASH"}:
            return (
                value,
                kind or "UNKNOWN",
                "Unsupported IOC type.",
            )

        if not value:
            return value, kind, "IOC value is empty."

        if kind == "IP":
            try:
                return (
                    str(ipaddress.ip_address(value)),
                    kind,
                    None,
                )
            except ValueError:
                return value, kind, "Invalid IP address."

        if kind == "DOMAIN":
            value = value.lower().rstrip(".")

            domain_pattern = re.compile(
                r"(?=^.{1,253}$)"
                r"(?:[a-z0-9]"
                r"(?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
                r"[a-z]{2,63}$"
            )

            if not domain_pattern.fullmatch(value):
                return (
                    value,
                    kind,
                    "Invalid domain name.",
                )

            return value, kind, None

        value = value.lower()

        hash_pattern = (
            r"[a-f0-9]{32}|"
            r"[a-f0-9]{40}|"
            r"[a-f0-9]{64}"
        )

        if not re.fullmatch(hash_pattern, value):
            return (
                value,
                kind,
                "Invalid MD5, SHA-1 or SHA-256 hash.",
            )

        return value, kind, None

    @staticmethod
    def _severity_from_score(score: int) -> str:
        if score >= 75:
            return "CRITICAL"

        if score >= 50:
            return "HIGH"

        if score >= 25:
            return "MEDIUM"

        return "LOW"

    @staticmethod
    def _recommendation(
        value: str,
        ioc_type: str,
        score: int,
        severity: str,
        evidence_mode: str,
        coverage: int,
    ) -> str:
        if severity == "CRITICAL":
            action = (
                "Escalate immediately, validate the evidence "
                "and request explicit analyst approval before "
                "containment."
            )

        elif severity == "HIGH":
            action = (
                "Open or update an incident, inspect related "
                "telemetry and consider containment after "
                "analyst validation."
            )

        elif severity == "MEDIUM":
            action = (
                "Continue investigation and correlate the IOC "
                "with local security logs."
            )

        else:
            action = (
                "No automatic containment is recommended. "
                "Continue monitoring."
            )

        return (
            f"{ioc_type} {value} received a risk score of "
            f"{score}/100 ({severity}). {action} "
            f"Evidence mode: {evidence_mode}; "
            f"available sources: {coverage}/4."
        )

    @staticmethod
    def _result(
        *,
        status: str,
        verdict: str,
        risk: int,
        contribution: int,
        message: str,
        evidence: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if status not in SOURCE_STATUSES:
            raise ValueError(
                f"Invalid source status: {status}"
            )

        return {
            "status": status,
            "verdict": verdict,
            "risk": max(0, min(100, int(risk))),
            "contribution": max(
                0,
                int(contribution),
            ),
            "message": message,
            "evidence": evidence or {},
        }

    @classmethod
    def _simulated_result(
        cls,
        source: str,
        ioc_value: str,
    ) -> dict[str, Any]:
        digest = hashlib.sha256(
            f"{source}:{ioc_value}".encode("utf-8")
        ).digest()

        simulated_risk = (
            10,
            35,
            65,
            85,
        )[digest[0] % 4]

        if simulated_risk >= 75:
            verdict = "MALICIOUS"
        elif simulated_risk >= 50:
            verdict = "SUSPICIOUS"
        else:
            verdict = "NO_MATCH"

        contribution = round(
            simulated_risk * SOURCE_WEIGHTS[source]
        )

        return cls._result(
            status="SIMULATED",
            verdict=verdict,
            risk=simulated_risk,
            contribution=contribution,
            message=(
                "Deterministic simulated result for "
                "controlled demonstration and offline testing."
            ),
            evidence={
                "simulation": True,
            },
        )

    @classmethod
    def _unavailable_or_simulated(
        cls,
        source: str,
        ioc_value: str,
        reason: str,
    ) -> dict[str, Any]:
        if SOAR_SIMULATION_MODE:
            result = cls._simulated_result(
                source,
                ioc_value,
            )

            result["message"] = (
                f"{result['message']} Reason: {reason}"
            )

            return result

        return cls._result(
            status="UNAVAILABLE",
            verdict="UNAVAILABLE",
            risk=0,
            contribution=0,
            message=reason,
        )

    @classmethod
    def _error_or_simulated(
        cls,
        source: str,
        ioc_value: str,
        reason: str,
    ) -> dict[str, Any]:
        if SOAR_SIMULATION_MODE:
            result = cls._simulated_result(
                source,
                ioc_value,
            )

            result["message"] = (
                f"{result['message']} "
                f"Live provider error: {reason}"
            )

            return result

        return cls._result(
            status="ERROR",
            verdict="ERROR",
            risk=0,
            contribution=0,
            message=reason,
        )

    @classmethod
    def _check_virustotal(
        cls,
        ioc_value: str,
        ioc_type: str,
    ) -> dict[str, Any]:
        if not VIRUSTOTAL_API_KEY:
            return cls._unavailable_or_simulated(
                "virustotal",
                ioc_value,
                "VirusTotal API key is not configured.",
            )

        endpoint_map = {
            "IP": "ip_addresses",
            "DOMAIN": "domains",
            "HASH": "files",
        }

        endpoint = endpoint_map[ioc_type]

        url = (
            "https://www.virustotal.com/api/v3/"
            f"{endpoint}/{ioc_value}"
        )

        try:
            response = requests.get(
                url,
                headers={
                    "x-apikey": VIRUSTOTAL_API_KEY,
                },
                timeout=cls.TIMEOUT_SECONDS,
            )

        except requests.RequestException as exc:
            return cls._error_or_simulated(
                "virustotal",
                ioc_value,
                (
                    "VirusTotal request failed: "
                    f"{type(exc).__name__}."
                ),
            )

        if response.status_code == 404:
            return cls._result(
                status="LIVE",
                verdict="NO_MATCH",
                risk=0,
                contribution=0,
                message=(
                    "VirusTotal has no record for this IOC."
                ),
            )

        if response.status_code != 200:
            return cls._error_or_simulated(
                "virustotal",
                ioc_value,
                (
                    "VirusTotal returned HTTP "
                    f"{response.status_code}."
                ),
            )

        try:
            stats = (
                response.json()
                .get("data", {})
                .get("attributes", {})
                .get("last_analysis_stats", {})
            )

            malicious = int(
                stats.get("malicious", 0)
            )

            suspicious = int(
                stats.get("suspicious", 0)
            )

            total = sum(
                int(value)
                for value in stats.values()
            )

        except (TypeError, ValueError):
            return cls._error_or_simulated(
                "virustotal",
                ioc_value,
                (
                    "VirusTotal returned an unexpected "
                    "response format."
                ),
            )

        source_risk = min(
            100,
            malicious * 10 + suspicious * 5,
        )

        contribution = round(
            source_risk
            * SOURCE_WEIGHTS["virustotal"]
        )

        if malicious >= 3 or source_risk >= 50:
            verdict = "MALICIOUS"
        elif malicious or suspicious:
            verdict = "SUSPICIOUS"
        else:
            verdict = "CLEAN"

        return cls._result(
            status="LIVE",
            verdict=verdict,
            risk=source_risk,
            contribution=contribution,
            message=(
                f"VirusTotal analysis: {malicious} malicious "
                f"and {suspicious} suspicious detections "
                f"out of {total}."
            ),
            evidence={
                "malicious": malicious,
                "suspicious": suspicious,
                "total": total,
            },
        )

    @classmethod
    def _check_abuseipdb(
        cls,
        ioc_value: str,
        ioc_type: str,
    ) -> dict[str, Any]:
        if ioc_type != "IP":
            return cls._result(
                status="UNAVAILABLE",
                verdict="NOT_APPLICABLE",
                risk=0,
                contribution=0,
                message=(
                    "AbuseIPDB supports IP addresses only."
                ),
            )

        if not ABUSEIPDB_API_KEY:
            return cls._unavailable_or_simulated(
                "abuseipdb",
                ioc_value,
                "AbuseIPDB API key is not configured.",
            )

        try:
            response = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={
                    "Key": ABUSEIPDB_API_KEY,
                    "Accept": "application/json",
                },
                params={
                    "ipAddress": ioc_value,
                    "maxAgeInDays": 90,
                },
                timeout=cls.TIMEOUT_SECONDS,
            )

        except requests.RequestException as exc:
            return cls._error_or_simulated(
                "abuseipdb",
                ioc_value,
                (
                    "AbuseIPDB request failed: "
                    f"{type(exc).__name__}."
                ),
            )

        if response.status_code != 200:
            return cls._error_or_simulated(
                "abuseipdb",
                ioc_value,
                (
                    "AbuseIPDB returned HTTP "
                    f"{response.status_code}."
                ),
            )

        try:
            data = response.json().get("data", {})

            confidence = int(
                data.get("abuseConfidenceScore", 0)
            )

            reports = int(
                data.get("totalReports", 0)
            )

        except (TypeError, ValueError):
            return cls._error_or_simulated(
                "abuseipdb",
                ioc_value,
                (
                    "AbuseIPDB returned an unexpected "
                    "response format."
                ),
            )

        contribution = round(
            confidence
            * SOURCE_WEIGHTS["abuseipdb"]
        )

        if confidence >= 75:
            verdict = "MALICIOUS"
        elif confidence >= 25:
            verdict = "SUSPICIOUS"
        else:
            verdict = "CLEAN"

        return cls._result(
            status="LIVE",
            verdict=verdict,
            risk=confidence,
            contribution=contribution,
            message=(
                f"AbuseIPDB confidence is {confidence}% "
                f"from {reports} reports."
            ),
            evidence={
                "abuse_confidence": confidence,
                "total_reports": reports,
            },
        )

    @classmethod
    def _check_alienvault(
        cls,
        ioc_value: str,
        ioc_type: str,
    ) -> dict[str, Any]:
        if not ALIENVAULT_OTX_API_KEY:
            return cls._unavailable_or_simulated(
                "alienvault",
                ioc_value,
                (
                    "AlienVault OTX API key is not "
                    "configured."
                ),
            )

        type_map = {
            "IP": "IPv4",
            "DOMAIN": "domain",
            "HASH": "file",
        }

        indicator_type = type_map[ioc_type]

        url = (
            "https://otx.alienvault.com/api/v1/"
            f"indicators/{indicator_type}/"
            f"{ioc_value}/general"
        )

        try:
            response = requests.get(
                url,
                headers={
                    "X-OTX-API-KEY":
                        ALIENVAULT_OTX_API_KEY,
                },
                timeout=cls.TIMEOUT_SECONDS,
            )

        except requests.RequestException as exc:
            return cls._error_or_simulated(
                "alienvault",
                ioc_value,
                (
                    "AlienVault OTX request failed: "
                    f"{type(exc).__name__}."
                ),
            )

        if response.status_code == 404:
            return cls._result(
                status="LIVE",
                verdict="NO_MATCH",
                risk=0,
                contribution=0,
                message=(
                    "AlienVault OTX has no record "
                    "for this IOC."
                ),
            )

        if response.status_code != 200:
            return cls._error_or_simulated(
                "alienvault",
                ioc_value,
                (
                    "AlienVault OTX returned HTTP "
                    f"{response.status_code}."
                ),
            )

        try:
            pulse_count = int(
                response.json()
                .get("pulse_info", {})
                .get("count", 0)
            )

        except (TypeError, ValueError):
            return cls._error_or_simulated(
                "alienvault",
                ioc_value,
                (
                    "AlienVault OTX returned an unexpected "
                    "response format."
                ),
            )

        source_risk = min(
            100,
            pulse_count * 15,
        )

        contribution = round(
            source_risk
            * SOURCE_WEIGHTS["alienvault"]
        )

        if pulse_count >= 3:
            verdict = "MALICIOUS"
        elif pulse_count:
            verdict = "SUSPICIOUS"
        else:
            verdict = "NO_MATCH"

        return cls._result(
            status="LIVE",
            verdict=verdict,
            risk=source_risk,
            contribution=contribution,
            message=(
                "AlienVault OTX pulse matches: "
                f"{pulse_count}."
            ),
            evidence={
                "pulse_count": pulse_count,
            },
        )

    @classmethod
    def _check_threatfox(
        cls,
        ioc_value: str,
        ioc_type: str,
    ) -> dict[str, Any]:
        try:
            response = requests.post(
                "https://threatfox-api.abuse.ch/api/v1/",
                json={
                    "query": "search_ioc",
                    "search_term": ioc_value,
                },
                timeout=cls.TIMEOUT_SECONDS,
            )

        except requests.RequestException as exc:
            return cls._error_or_simulated(
                "threatfox",
                ioc_value,
                (
                    "ThreatFox request failed: "
                    f"{type(exc).__name__}."
                ),
            )

        if response.status_code != 200:
            return cls._error_or_simulated(
                "threatfox",
                ioc_value,
                (
                    "ThreatFox returned HTTP "
                    f"{response.status_code}."
                ),
            )

        try:
            payload = response.json()

            query_status = payload.get(
                "query_status"
            )

            matches = payload.get("data") or []

        except ValueError:
            return cls._error_or_simulated(
                "threatfox",
                ioc_value,
                "ThreatFox returned invalid JSON.",
            )

        if query_status in {
            "no_result",
            "no_results",
        }:
            return cls._result(
                status="LIVE",
                verdict="NO_MATCH",
                risk=0,
                contribution=0,
                message=(
                    "ThreatFox returned no active "
                    "IOC matches."
                ),
            )

        if query_status != "ok":
            return cls._error_or_simulated(
                "threatfox",
                ioc_value,
                (
                    "ThreatFox query status was "
                    f"{query_status!r}."
                ),
            )

        match_count = len(matches)
        malware = "Unknown"

        if matches and isinstance(matches[0], dict):
            malware = matches[0].get(
                "malware_printable",
                "Unknown",
            )

        source_risk = (
            100 if match_count else 0
        )

        contribution = round(
            source_risk
            * SOURCE_WEIGHTS["threatfox"]
        )

        return cls._result(
            status="LIVE",
            verdict=(
                "MALICIOUS"
                if match_count
                else "NO_MATCH"
            ),
            risk=source_risk,
            contribution=contribution,
            message=(
                f"ThreatFox matches: {match_count}; "
                f"malware family: {malware}."
            ),
            evidence={
                "match_count": match_count,
                "malware": malware,
                "ioc_type": ioc_type,
            },
        )
