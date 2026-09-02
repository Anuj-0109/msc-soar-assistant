import unittest
from unittest.mock import patch

from app import app


class SupervisorDemoTests(unittest.TestCase):
    def test_dashboard_contains_stage7_interface(self):
        with app.test_client() as client:
            response = client.get("/operations-workspace")
        html = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn('id="supervisorDemoSection"', html)
        self.assertIn('id="demoIocValue"', html)
        self.assertIn('id="demoIncidentSelect"', html)
        self.assertIn('id="demoValidationChecks"', html)
        self.assertIn("css/supervisor_demo.css", html)
        self.assertIn("js/supervisor_demo.js", html)

    def test_required_stage7_routes_exist(self):
        routes = {str(rule) for rule in app.url_map.iter_rules()}
        required = {
            "/api/demo/status",
            "/api/demo/analyze-ioc",
            "/api/demo/ingest/suricata",
            "/api/demo/incidents",
            "/api/demo/incidents/from-analysis",
            "/api/demo/incidents/<int:incident_id>",
            "/api/demo/incidents/<int:incident_id>/status",
            "/api/demo/incidents/<int:incident_id>/comments",
            "/api/demo/incidents/<int:incident_id>/contain",
            "/api/demo/incidents/<int:incident_id>/unblock",
            "/api/demo/ufw-rules",
            "/api/demo/validation",
            "/api/demo/evaluation",
            "/api/demo/evaluation/artifact/<string:kind>",
            "/api/demo/reports/audit",
            "/api/demo/reports/incident/<int:incident_id>",
            "/api/demo/reports/executive",
        }
        self.assertTrue(required.issubset(routes))

    def test_invalid_ioc_is_rejected(self):
        with app.test_client() as client:
            response = client.post(
                "/api/demo/analyze-ioc",
                json={"ioc_type": "IP", "value": "999.999.999.999"},
            )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["status"], "error")

    @patch("blueprints.supervisor_demo.ThreatIntelAggregator.analyze_all")
    def test_valid_ioc_analysis(self, analyse_all):
        analyse_all.return_value = {
            "risk_score": 20,
            "severity": "LOW",
            "overall_status": "LIVE",
            "evidence_mode": "LIVE_ONLY",
            "recommendation": "Monitor.",
            "sources": {},
        }
        with app.test_client() as client:
            response = client.post(
                "/api/demo/analyze-ioc",
                json={"ioc_type": "IP", "value": "203.0.113.77"},
            )
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload["status"], "success")
        self.assertTrue(payload["containment_capability"]["supported"])

    def test_evaluation_endpoint_is_safe(self):
        with app.test_client() as client:
            response = client.get("/api/demo/evaluation")
        self.assertEqual(response.status_code, 200)
        self.assertIn("evaluation", response.get_json())


if __name__ == "__main__":
    unittest.main()
