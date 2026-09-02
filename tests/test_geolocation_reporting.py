import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from app import app
from blueprints.intelligence_reporting import (
    _extract_chat_geolocation_target,
    _format_chat_geolocation,
)
from services.geolocation import lookup_ioc_geolocation, lookup_public_ip


class ChatReportGeolocationTests(unittest.TestCase):
    def test_chat_target_extracts_ip_and_domain(self):
        self.assertEqual(
            _extract_chat_geolocation_target("analyse IP 9.9.9.9"),
            ("9.9.9.9", "IP"),
        )
        self.assertEqual(
            _extract_chat_geolocation_target("check example.com"),
            ("example.com", "DOMAIN"),
        )

    def test_hash_does_not_request_geolocation(self):
        self.assertIsNone(
            _extract_chat_geolocation_target("analyse " + "a" * 64)
        )
        result = lookup_ioc_geolocation("a" * 64, "HASH")
        self.assertEqual(result["status"], "NOT_APPLICABLE")

    def test_reserved_ip_is_not_sent_external(self):
        with patch("services.geolocation.requests.get") as request_mock:
            result = lookup_public_ip("203.0.113.77", force_refresh=True)
        request_mock.assert_not_called()
        self.assertEqual(result["status"], "NOT_APPLICABLE")

    def test_public_ip_is_normalised(self):
        response = Mock()
        response.raise_for_status.return_value = None
        response.json.return_value = {
            "success": True,
            "ip": "9.9.9.9",
            "country": "United States",
            "country_code": "US",
            "region": "California",
            "city": "Berkeley",
            "latitude": 37.87,
            "longitude": -122.27,
            "connection": {
                "asn": 19281,
                "org": "Quad9",
                "isp": "Quad9",
                "domain": "quad9.net",
            },
            "timezone": {},
        }
        with patch(
            "services.geolocation.requests.get",
            return_value=response,
        ), patch("services.geolocation._write_cache"):
            result = lookup_public_ip("9.9.9.9", force_refresh=True)
        self.assertEqual(result["status"], "LIVE")
        self.assertEqual(result["asn"], 19281)

    def test_chat_format_contains_network_context(self):
        text = _format_chat_geolocation(
            {
                "status": "LIVE",
                "ioc_type": "IP",
                "ioc_value": "9.9.9.9",
                "locations": [
                    {
                        "status": "LIVE",
                        "ip_address": "9.9.9.9",
                        "city": "Berkeley",
                        "region": "California",
                        "country": "United States",
                        "asn": 19281,
                        "organisation": "Quad9",
                    }
                ],
            }
        )
        self.assertIn("Geolocation & Network Context", text)
        self.assertIn("AS19281", text)
        self.assertIn("not person-level attribution", text)

    def test_routes_and_report_sections_exist(self):
        routes = {str(rule) for rule in app.url_map.iter_rules()}
        self.assertIn(
            "/api/intelligence/reports/incident/<int:incident_id>",
            routes,
        )
        source = Path("blueprints/intelligence_reporting.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("TableOfContents", source)
        self.assertIn("Geolocation, ASN and Hosting Assessment", source)
        self.assertIn("append_geolocation_to_analyst_chat", source)

    def test_workspace_has_no_separate_geolocation_box(self):
        template = Path("templates/operations_workspace.html").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("css/geolocation_reporting.css", template)
        self.assertNotIn("js/geolocation_reporting.js", template)
        self.assertNotIn("demoGeoAnalysisResult", template)

    def test_report_button_uses_structured_report(self):
        javascript = Path("static/js/supervisor_demo.js").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "/api/intelligence/reports/incident/${incidentId}",
            javascript,
        )


if __name__ == "__main__":
    unittest.main()
