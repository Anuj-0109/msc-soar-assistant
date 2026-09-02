import unittest
from pathlib import Path
from unittest.mock import patch

from actions.actions import (
    ActionEnforceFirewallRule,
    ActionParseAndAnalyzeLog,
    ActionQueryThreatIntel,
)
from settings import BASE_DIR


class FakeTracker:
    def __init__(self, **slots):
        self.slots = slots

    def get_slot(self, name):
        return self.slots.get(name)


class FakeDispatcher:
    def __init__(self):
        self.messages = []

    def utter_message(self, **kwargs):
        self.messages.append(
            kwargs.get("text", "")
        )


class RasaActionTests(unittest.TestCase):
    def setUp(self):
        self.uploads = BASE_DIR / "uploads"
        self.uploads.mkdir(
            parents=True,
            exist_ok=True,
        )

    def test_log_analysis_action(self):
        test_file = (
            self.uploads
            / "stage5-rasa-auth.log"
        )

        test_file.write_text(
            "\n".join(
                [
                    (
                        "Failed password for root from "
                        "203.0.113.80 port 22 ssh2"
                    )
                    for _ in range(3)
                ]
            )
        )

        dispatcher = FakeDispatcher()

        try:
            events = (
                ActionParseAndAnalyzeLog()
                .run(
                    dispatcher,
                    FakeTracker(
                        log_path=(
                            "uploads/"
                            "stage5-rasa-auth.log"
                        )
                    ),
                    {},
                )
            )

            message = dispatcher.messages[-1]

            self.assertIn(
                "LOG ANALYSIS RESULT",
                message,
            )

            self.assertIn(
                "203.0.113.80",
                message,
            )

            self.assertEqual(
                len(events),
                1,
            )

        finally:
            test_file.unlink(
                missing_ok=True
            )

    def test_log_path_traversal_is_rejected(self):
        dispatcher = FakeDispatcher()

        ActionParseAndAnalyzeLog().run(
            dispatcher,
            FakeTracker(
                log_path="../.env"
            ),
            {},
        )

        message = dispatcher.messages[-1].lower()

        self.assertIn(
            "rejected",
            message,
        )

        self.assertIn(
            "traversal",
            message,
        )

    def test_allowlisted_ip_is_not_blocked(self):
        dispatcher = FakeDispatcher()

        ActionEnforceFirewallRule().run(
            dispatcher,
            FakeTracker(
                ip_address="127.0.0.1"
            ),
            {},
        )

        message = dispatcher.messages[-1].lower()

        self.assertIn(
            "denied by policy",
            message,
        )

        self.assertIn(
            "no firewall rule was created",
            message,
        )

        self.assertNotIn(
            "containment confirmed",
            message,
        )

    def test_ip_address_slot_uses_central_intel(self):
        dispatcher = FakeDispatcher()

        mock_result = {
            "ioc_value": "203.0.113.90",
            "ioc_type": "IP",
            "risk_score": 30,
            "severity": "MEDIUM",
            "overall_status": "SIMULATED",
            "evidence_mode": "SIMULATION_ONLY",
            "coverage": 4,
            "recommendation":
                "Controlled recommendation.",
            "sources": {
                "virustotal": {
                    "status": "SIMULATED",
                    "verdict": "NO_MATCH",
                    "message": "Controlled test.",
                },
                "abuseipdb": {
                    "status": "SIMULATED",
                    "verdict": "SUSPICIOUS",
                    "message": "Controlled test.",
                },
                "alienvault": {
                    "status": "SIMULATED",
                    "verdict": "NO_MATCH",
                    "message": "Controlled test.",
                },
                "threatfox": {
                    "status": "SIMULATED",
                    "verdict": "NO_MATCH",
                    "message": "Controlled test.",
                },
            },
        }

        with patch(
            "actions.actions."
            "ThreatIntelAggregator.analyze_all",
            return_value=mock_result,
        ):
            ActionQueryThreatIntel().run(
                dispatcher,
                FakeTracker(
                    ip_address="203.0.113.90"
                ),
                {},
            )

        message = dispatcher.messages[-1]

        self.assertIn(
            "30/100",
            message,
        )

        self.assertIn(
            "SIMULATION_ONLY",
            message,
        )


if __name__ == "__main__":
    unittest.main()
