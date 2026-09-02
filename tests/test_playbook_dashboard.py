import unittest
from pathlib import Path

from app import app
from settings import BASE_DIR


class PlaybookDashboardTests(unittest.TestCase):
    def test_dashboard_contains_playbook_interface(self):
        with app.test_client() as client:
            response = client.get("/")

        html = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn('id="playbookSelect"', html)
        self.assertIn('id="pendingPlaybookTable"', html)
        self.assertIn('id="playbookHistoryTable"', html)
        self.assertIn("static/css/playbooks.css", html)
        self.assertIn("static/js/playbooks.js", html)

    def test_playbook_assets_exist(self):
        css_path = BASE_DIR / "static" / "css" / "playbooks.css"
        js_path = BASE_DIR / "static" / "js" / "playbooks.js"

        self.assertTrue(css_path.is_file())
        self.assertTrue(js_path.is_file())

        js = js_path.read_text(encoding="utf-8")
        self.assertIn("/api/playbooks", js)
        self.assertIn("/api/playbook-executions", js)
        self.assertIn("refreshPlaybookPanel", js)

    def test_required_playbook_routes_exist(self):
        routes = {str(rule) for rule in app.url_map.iter_rules()}

        required = {
            "/api/playbooks",
            "/api/playbooks/<int:playbook_id>",
            "/api/playbooks/<int:playbook_id>/enabled",
            "/api/playbooks/<int:playbook_id>/execute",
            "/api/playbook-executions",
            "/api/playbook-executions/<int:execution_id>",
            "/api/playbook-executions/<int:execution_id>/approve",
            "/api/playbook-executions/<int:execution_id>/reject",
        }

        self.assertTrue(required.issubset(routes))


if __name__ == "__main__":
    unittest.main()
