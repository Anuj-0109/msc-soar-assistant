import unittest
from unittest.mock import patch

import requests

import services.threat_intel as threat_intel


class ThreatIntelServiceTests(unittest.TestCase):
    def test_invalid_ip_is_rejected(self):
        result = (
            threat_intel
            .ThreatIntelAggregator
            .analyze_all(
                "999.999.999.999",
                "IP",
            )
        )

        self.assertEqual(
            result["overall_status"],
            "ERROR",
        )

        self.assertEqual(
            result["risk_score"],
            0,
        )

        self.assertEqual(
            result["input_error"],
            "Invalid IP address.",
        )

    def test_simulation_is_labelled_and_deterministic(self):
        with patch.object(
            threat_intel,
            "VIRUSTOTAL_API_KEY",
            "",
        ), patch.object(
            threat_intel,
            "ABUSEIPDB_API_KEY",
            "",
        ), patch.object(
            threat_intel,
            "ALIENVAULT_OTX_API_KEY",
            "",
        ), patch.object(
            threat_intel,
            "SOAR_SIMULATION_MODE",
            True,
        ), patch(
            "services.threat_intel.requests.post",
            side_effect=requests.ConnectionError(
                "Offline test",
            ),
        ):
            first = (
                threat_intel
                .ThreatIntelAggregator
                .analyze_all(
                    "203.0.113.10",
                    "IP",
                )
            )

            second = (
                threat_intel
                .ThreatIntelAggregator
                .analyze_all(
                    "203.0.113.10",
                    "IP",
                )
            )

        self.assertEqual(
            first["overall_status"],
            "SIMULATED",
        )

        self.assertEqual(
            first["evidence_mode"],
            "SIMULATION_ONLY",
        )

        self.assertEqual(
            first["risk_score"],
            second["risk_score"],
        )

        for source in first["sources"].values():
            self.assertEqual(
                source["status"],
                "SIMULATED",
            )

            self.assertIn(
                "simulat",
                source["message"].lower(),
            )

    def test_simulation_disabled_never_generates_fake_data(
        self,
    ):
        with patch.object(
            threat_intel,
            "VIRUSTOTAL_API_KEY",
            "test-key",
        ), patch.object(
            threat_intel,
            "ABUSEIPDB_API_KEY",
            "test-key",
        ), patch.object(
            threat_intel,
            "ALIENVAULT_OTX_API_KEY",
            "test-key",
        ), patch.object(
            threat_intel,
            "SOAR_SIMULATION_MODE",
            False,
        ), patch(
            "services.threat_intel.requests.get",
            side_effect=requests.ConnectionError(
                "Offline test",
            ),
        ), patch(
            "services.threat_intel.requests.post",
            side_effect=requests.ConnectionError(
                "Offline test",
            ),
        ):
            result = (
                threat_intel
                .ThreatIntelAggregator
                .analyze_all(
                    "203.0.113.10",
                    "IP",
                )
            )

        statuses = {
            source["status"]
            for source in result["sources"].values()
        }

        self.assertNotIn(
            "SIMULATED",
            statuses,
        )

        self.assertEqual(
            statuses,
            {"ERROR"},
        )

        self.assertEqual(
            result["risk_score"],
            0,
        )

        self.assertEqual(
            result["evidence_mode"],
            "NONE",
        )

    def test_hash_is_not_sent_to_abuseipdb(self):
        test_hash = (
            "e3b0c44298fc1c149afbf4c8996fb924"
            "27ae41e4649b934ca495991b7852b855"
        )

        with patch.object(
            threat_intel,
            "VIRUSTOTAL_API_KEY",
            "",
        ), patch.object(
            threat_intel,
            "ALIENVAULT_OTX_API_KEY",
            "",
        ), patch.object(
            threat_intel,
            "SOAR_SIMULATION_MODE",
            False,
        ), patch(
            "services.threat_intel.requests.post",
            side_effect=requests.ConnectionError(
                "Offline test",
            ),
        ):
            result = (
                threat_intel
                .ThreatIntelAggregator
                .analyze_all(
                    test_hash,
                    "HASH",
                )
            )

        abuse_result = result["sources"]["abuseipdb"]

        self.assertEqual(
            abuse_result["status"],
            "UNAVAILABLE",
        )

        self.assertEqual(
            abuse_result["verdict"],
            "NOT_APPLICABLE",
        )


if __name__ == "__main__":
    unittest.main()
