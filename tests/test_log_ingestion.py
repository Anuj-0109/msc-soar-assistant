import io
import unittest

from app import app
from services.log_analysis import analyze_log_text
from settings import BASE_DIR


class LogAnalysisTests(unittest.TestCase):
    def test_repeated_authentication_failures(self):
        text = "\n".join(
            [
                (
                    "Failed password for invalid user root "
                    "from 203.0.113.50 port 22 ssh2"
                )
                for _ in range(5)
            ]
        )

        result = analyze_log_text(
            text,
            "auth.log",
        )

        self.assertEqual(
            result["overall_severity"],
            "HIGH",
        )

        self.assertEqual(
            result["statistics"]
            ["authentication_failures"],
            5,
        )

        self.assertEqual(
            result["suspicious_iocs"][0]["value"],
            "203.0.113.50",
        )

    def test_suricata_critical_alert(self):
        text = (
            '{"event_type":"alert",'
            '"src_ip":"198.51.100.20",'
            '"alert":{"signature":"ET MALWARE Test",'
            '"severity":1}}'
        )

        result = analyze_log_text(
            text,
            "eve.json",
        )

        self.assertEqual(
            result["overall_severity"],
            "CRITICAL",
        )

        self.assertEqual(
            result["statistics"]
            ["suricata_alerts"],
            1,
        )

    def test_benign_log(self):
        result = analyze_log_text(
            "System service started successfully.",
            "system.log",
        )

        self.assertEqual(
            result["finding_count"],
            0,
        )

        self.assertEqual(
            result["risk_score"],
            0,
        )

    def test_upload_endpoint(self):
        with app.test_client() as client:
            response = client.post(
                "/api/logs/upload",
                data={
                    "file": (
                        io.BytesIO(
                            b"System service started normally."
                        ),
                        "benign.log",
                    )
                },
                content_type="multipart/form-data",
            )

        data = response.get_json(
            silent=True
        ) or {}

        self.assertEqual(
            response.status_code,
            201,
        )

        self.assertEqual(
            data.get("status"),
            "success",
        )

        stored_file = data.get("stored_file")

        if stored_file:
            upload_path = (
                BASE_DIR
                / "uploads"
                / stored_file
            )

            upload_path.unlink(
                missing_ok=True
            )

    def test_rejects_executable_extension(self):
        with app.test_client() as client:
            response = client.post(
                "/api/logs/upload",
                data={
                    "file": (
                        io.BytesIO(b"test"),
                        "malware.exe",
                    )
                },
                content_type="multipart/form-data",
            )

        self.assertEqual(
            response.status_code,
            415,
        )


if __name__ == "__main__":
    unittest.main()
