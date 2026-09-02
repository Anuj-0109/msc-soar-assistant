import os
from pathlib import Path
import subprocess
from datetime import datetime
from typing import Any, Text, Dict, List
from rasa_sdk import Action, Tracker
from rasa_sdk.executor import CollectingDispatcher
from rasa_sdk.events import SlotSet
from soar_engine import (
    execute_kernel_block,
    execute_kernel_unblock,
)
from settings import BASE_DIR
from services.log_analysis import (
    analyze_log_file,
    format_log_analysis,
)
import audit_logger
from services.threat_intel import ThreatIntelAggregator

def _format_threat_source(source_name, source):
    display_names = {
        "virustotal": "VirusTotal",
        "abuseipdb": "AbuseIPDB",
        "alienvault": "AlienVault OTX",
        "threatfox": "ThreatFox",
    }

    display_name = display_names.get(
        source_name,
        source_name,
    )

    status = source.get(
        "status",
        "UNAVAILABLE",
    )

    verdict = source.get(
        "verdict",
        "UNAVAILABLE",
    )

    message = source.get(
        "message",
        "No details available.",
    )

    return (
        f"- {display_name}: "
        f"[{status}] {verdict} — {message}"
    )


class ActionAnalyzeThreat(Action):
    def name(self) -> Text:
        return "action_analyze_threat"

    def run(
        self,
        dispatcher: CollectingDispatcher,
        tracker: Tracker,
        domain: Dict[Text, Any],
    ) -> List[Dict[Text, Any]]:
        ip = (
            tracker.get_slot("ip")
            or tracker.get_slot("ip_address")
        )
        web_domain = tracker.get_slot("domain")
        file_hash = tracker.get_slot("file_hash")

        if ip:
            ioc_value = ip
            ioc_type = "IP"

        elif web_domain:
            ioc_value = web_domain
            ioc_type = "DOMAIN"

        elif file_hash:
            ioc_value = file_hash
            ioc_type = "HASH"

        else:
            dispatcher.utter_message(
                text=(
                    "No valid IP address, domain or file "
                    "hash was detected."
                )
            )

            return []

        result = ThreatIntelAggregator.analyze_all(
            ioc_value,
            ioc_type,
        )

        source_lines = [
            _format_threat_source(
                source_name,
                source,
            )
            for source_name, source
            in result["sources"].items()
        ]

        response_text = (
            "THREAT-INTELLIGENCE ANALYSIS\n"
            f"- IOC: {result['ioc_value']} "
            f"({result['ioc_type']})\n"
            f"- Risk score: "
            f"{result['risk_score']}/100\n"
            f"- Severity: {result['severity']}\n"
            f"- Overall status: "
            f"{result['overall_status']}\n"
            f"- Evidence mode: "
            f"{result['evidence_mode']}\n"
            f"- Source coverage: "
            f"{result['coverage']}/4\n\n"
            "SOURCE RESULTS\n"
            + "\n".join(source_lines)
            + "\n\nRECOMMENDATION\n"
            + result["recommendation"]
        )

        dispatcher.utter_message(
            text=response_text
        )

        return [
            SlotSet("ip", None),
            SlotSet("ip_address", None),
            SlotSet("domain", None),
            SlotSet("file_hash", None),
        ]


class ActionQueryThreatIntel(ActionAnalyzeThreat):
    def name(self) -> Text:
        return "action_query_threat_intel"

BLOCKLIST_PATH = BASE_DIR / "blocklist.txt"
UPLOADS_ROOT = (BASE_DIR / "uploads").resolve()

ALLOWED_LOG_EXTENSIONS = {
    ".log",
    ".txt",
    ".csv",
    ".json",
}

MAX_RASA_LOG_BYTES = 2 * 1024 * 1024


def _tracker_ioc(tracker):
    ip = (
        tracker.get_slot("ip")
        or tracker.get_slot("ip_address")
    )

    web_domain = tracker.get_slot("domain")
    file_hash = tracker.get_slot("file_hash")

    if ip:
        return {
            "type": "IP",
            "value": str(ip).strip(),
        }

    if web_domain:
        return {
            "type": "DOMAIN",
            "value": str(web_domain).strip(),
        }

    if file_hash:
        return {
            "type": "HASH",
            "value": str(file_hash).strip(),
        }

    return None


def _clear_ioc_slots():
    return [
        SlotSet("ip", None),
        SlotSet("ip_address", None),
        SlotSet("domain", None),
        SlotSet("file_hash", None),
    ]


def _update_blocklist(
    indicator,
    add_indicator,
):
    existing = []

    if BLOCKLIST_PATH.exists():
        existing = [
            line.strip()
            for line in BLOCKLIST_PATH.read_text().splitlines()
            if line.strip()
        ]

    if add_indicator:
        if indicator not in existing:
            existing.append(indicator)

    else:
        existing = [
            item
            for item in existing
            if item != indicator
        ]

    content = ""

    if existing:
        content = "\n".join(existing) + "\n"

    BLOCKLIST_PATH.write_text(content)


def _safe_uploaded_log_path(raw_path):
    value = str(raw_path or "").strip()

    if not value:
        return None, "No uploaded log path was supplied."

    relative_path = Path(value)

    if relative_path.is_absolute():
        return (
            None,
            "Absolute file paths are not permitted.",
        )

    if ".." in relative_path.parts:
        return (
            None,
            "Parent-directory traversal is not permitted.",
        )

    if (
        relative_path.parts
        and relative_path.parts[0] == "uploads"
    ):
        candidate = (
            BASE_DIR / relative_path
        ).resolve()

    elif len(relative_path.parts) == 1:
        candidate = (
            UPLOADS_ROOT / relative_path
        ).resolve()

    else:
        return (
            None,
            "Rasa can analyse files only from the uploads "
            "directory.",
        )

    if UPLOADS_ROOT not in candidate.parents:
        return (
            None,
            "The requested path is outside the uploads "
            "directory.",
        )

    if candidate.suffix.lower() not in ALLOWED_LOG_EXTENSIONS:
        return (
            None,
            "Unsupported log file type.",
        )

    if not candidate.is_file():
        return (
            None,
            "The requested uploaded log file was not found.",
        )

    if candidate.stat().st_size > MAX_RASA_LOG_BYTES:
        return (
            None,
            "The uploaded log exceeds the 2 MB analysis "
            "limit.",
        )

    return candidate, None


class ActionParseAndAnalyzeLog(Action):
    def name(self) -> Text:
        return "action_parse_and_analyze_log"

    def run(
        self,
        dispatcher: CollectingDispatcher,
        tracker: Tracker,
        domain: Dict[Text, Any],
    ) -> List[Dict[Text, Any]]:
        log_path = tracker.get_slot("log_path")

        safe_path, error = _safe_uploaded_log_path(
            log_path
        )

        if error:
            dispatcher.utter_message(
                text=(
                    "Log analysis request rejected: "
                    f"{error}"
                )
            )

            return [
                SlotSet("log_path", None),
            ]

        try:
            analysis = analyze_log_file(
                safe_path
            )

        except Exception as exc:
            dispatcher.utter_message(
                text=(
                    "Log analysis failed safely: "
                    f"{type(exc).__name__}."
                )
            )

            return [
                SlotSet("log_path", None),
            ]

        audit_logger.log_event(
            "RASA LOG ANALYSIS",
            safe_path.name,
            analysis["overall_severity"],
            (
                f"Analysed {analysis['line_count']} lines "
                f"and found "
                f"{analysis['finding_count']} findings. "
                "No firewall action was executed."
            ),
            "SUCCESS",
        )

        dispatcher.utter_message(
            text=format_log_analysis(analysis)
        )

        return [
            SlotSet("log_path", None),
        ]


class ActionEnforceFirewallRule(Action):
    def name(self) -> Text:
        return "action_enforce_firewall_rule"

    def run(
        self,
        dispatcher: CollectingDispatcher,
        tracker: Tracker,
        domain: Dict[Text, Any],
    ) -> List[Dict[Text, Any]]:
        ioc = _tracker_ioc(tracker)

        if not ioc:
            dispatcher.utter_message(
                text=(
                    "Containment was not attempted because "
                    "no valid IOC was supplied."
                )
            )

            return _clear_ioc_slots()

        execution_status, execution_notes = (
            execute_kernel_block(ioc)
        )

        audit_logger.log_event(
            "RASA FIREWALL BLOCK",
            ioc["value"],
            "HIGH",
            execution_notes,
            execution_status,
        )

        if execution_status == "SUCCESS":
            _update_blocklist(
                ioc["value"],
                add_indicator=True,
            )

            message = (
                f"Containment confirmed for "
                f"{ioc['value']}. UFW returned SUCCESS. "
                f"Details: {execution_notes}"
            )

        elif execution_status == "BLOCKED_BY_POLICY":
            message = (
                f"Containment was denied by policy for "
                f"{ioc['value']}. No firewall rule was "
                f"created. Details: {execution_notes}"
            )

        else:
            message = (
                f"Containment was not confirmed for "
                f"{ioc['value']}. Status: "
                f"{execution_status}. "
                f"Details: {execution_notes}"
            )

        dispatcher.utter_message(
            text=message
        )

        return _clear_ioc_slots()


class ActionBlockThreat(ActionEnforceFirewallRule):
    def name(self) -> Text:
        return "action_block_threat"


class ActionUnblockThreat(Action):
    def name(self) -> Text:
        return "action_unblock_threat"

    def run(
        self,
        dispatcher: CollectingDispatcher,
        tracker: Tracker,
        domain: Dict[Text, Any],
    ) -> List[Dict[Text, Any]]:
        ioc = _tracker_ioc(tracker)

        if not ioc:
            dispatcher.utter_message(
                text=(
                    "Containment removal was not attempted "
                    "because no valid IOC was supplied."
                )
            )

            return _clear_ioc_slots()

        execution_status, execution_notes = (
            execute_kernel_unblock(ioc)
        )

        audit_logger.log_event(
            "RASA FIREWALL UNBLOCK",
            ioc["value"],
            "INFORMATIONAL",
            execution_notes,
            execution_status,
        )

        if execution_status == "SUCCESS":
            _update_blocklist(
                ioc["value"],
                add_indicator=False,
            )

            message = (
                f"UFW unblock confirmed for "
                f"{ioc['value']}. "
                f"Details: {execution_notes}"
            )

        else:
            message = (
                f"UFW unblock was not confirmed for "
                f"{ioc['value']}. Status: "
                f"{execution_status}. "
                f"Details: {execution_notes}"
            )

        dispatcher.utter_message(
            text=message
        )

        return _clear_ioc_slots()


class ActionGenerateReport(Action):
    def name(self) -> Text:
        return "action_generate_report"

    def run(self, dispatcher: CollectingDispatcher, tracker: Tracker, domain: Dict[Text, Any]) -> List[Dict[Text, Any]]:
        output_dir = "reports"
        os.makedirs(output_dir, exist_ok=True)
        now = datetime.now()
        report_file = f"incident_report_{now.strftime('%Y%m%d_%H%M%S')}.txt"
        report_path = os.path.join(output_dir, report_file)
        blocklist_file = "blocklist.txt"
        contained_elements = []
        if os.path.exists(blocklist_file):
            with open(blocklist_file, "r") as f:
                contained_elements = [line.strip() for line in f.readlines() if line.strip()]
        
        report_content = (
            f"==========================================================\n"
            f"          INCIDENT RESPONSE REMEDIATION AUDIT LOG        \n"
            f"==========================================================\n"
            f"Generated On          : {now.strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"File Asset ID         : {report_file}\n"
            f"----------------------------------------------------------\n\n"
            f"1. MITIGATION AND CONTAINMENT METRICS\n"
        )
        if contained_elements:
            for index, item in enumerate(contained_elements, 1):
                report_content += f"     - Indicator #{index}: {item} [Firewall Dropped]\n"
        else:
            report_content += "     - No containment indicators active in local configurations.\n"
            
        with open(report_path, "w") as f:
            f.write(report_content)
            
        dispatcher.utter_message(text=f"SUCCESS: Verification log available at isolated location: {report_path}")
        return []


class ActionShowLatestReport(Action):
    def name(self) -> Text:
        return "action_show_latest_report"

    def run(self, dispatcher: CollectingDispatcher, tracker: Tracker, domain: Dict[Text, Any]) -> List[Dict[Text, Any]]:
        # Define directory path locally if not set globally
        REPORTS_DIR = "reports"

        if not os.path.exists(REPORTS_DIR) or not os.listdir(REPORTS_DIR):
            dispatcher.utter_message(text="ℹ️ No incident reports found in the system.")
            return []

        reports = [os.path.join(REPORTS_DIR, f) for f in os.listdir(REPORTS_DIR) if f.endswith(".txt")]

        if not reports:
            dispatcher.utter_message(text="ℹ️ No text reports found in the reports directory.")
            return []

        latest_report = max(reports, key=os.path.getctime)

        with open(latest_report, "r") as f:
            content = f.read()

        filename = os.path.basename(latest_report)
        dispatcher.utter_message(
            text=f"📄 **Latest Incident Report (`{filename}`):**\n\n```text\n{content}\n```"
        )

        return []
