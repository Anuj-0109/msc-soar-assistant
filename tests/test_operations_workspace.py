import unittest

from app import app


class OperationsWorkspaceTests(unittest.TestCase):
    def test_workspace_route_is_registered(self):
        routes = {str(rule) for rule in app.url_map.iter_rules()}
        self.assertIn("/operations-workspace", routes)

    def test_main_dashboard_links_to_workspace(self):
        with app.test_client() as client:
            response = client.get("/")

        html = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn('href="/operations-workspace"', html)
        self.assertIn("SOAR Operations Workspace", html)
        self.assertNotIn('id="supervisorDemoSection"', html)

    def test_workspace_contains_operational_interface(self):
        with app.test_client() as client:
            response = client.get("/operations-workspace")

        html = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn("<title>SOAR Operations Workspace</title>", html)
        self.assertIn('id="supervisorDemoSection"', html)
        self.assertIn('id="demoIocValue"', html)
        self.assertIn('id="demoIncidentSelect"', html)
        self.assertIn('id="demoValidationChecks"', html)
        self.assertIn('href="/"', html)
        self.assertIn("css/supervisor_demo.css", html)
        self.assertIn("css/operations_workspace.css", html)
        self.assertIn("js/supervisor_demo.js", html)

    def test_workspace_and_main_platform_share_demo_apis(self):
        routes = {str(rule) for rule in app.url_map.iter_rules()}
        required = {
            "/api/demo/analyze-ioc",
            "/api/demo/incidents",
            "/api/demo/incidents/from-analysis",
            "/api/demo/incidents/<int:incident_id>/contain",
            "/api/demo/incidents/<int:incident_id>/unblock",
            "/api/demo/ufw-rules",
            "/api/demo/validation",
            "/api/demo/evaluation",
        }
        self.assertTrue(required.issubset(routes))


if __name__ == "__main__":
    unittest.main()
