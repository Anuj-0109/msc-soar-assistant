import unittest
from pathlib import Path


class UfwWorkspaceUiTests(unittest.TestCase):
    def test_native_confirmation_is_not_used(self):
        text = Path("static/js/supervisor_demo.js").read_text(encoding="utf-8")
        self.assertIn("requestWorkspaceUfwConfirmation", text)
        self.assertIn("demoUfwConfirmationOverlay", text)
        self.assertNotIn(
            "const confirmed = window.confirm(`LIVE UFW ACTION",
            text,
        )

    def test_backend_errors_are_shown_inline(self):
        text = Path("static/js/supervisor_demo.js").read_text(encoding="utf-8")
        self.assertIn("showWorkspaceActionNotice", text)
        self.assertIn("UFW NOT READY", text)
        self.assertIn("non-interactive sudo authorisation", text)

    def test_confirmation_styles_exist(self):
        text = Path("static/css/supervisor_demo.css").read_text(encoding="utf-8")
        self.assertIn(".demo-confirm-overlay", text)
        self.assertIn(".demo-action-error", text)


if __name__ == "__main__":
    unittest.main()
