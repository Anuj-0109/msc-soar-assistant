import os
from pathlib import Path

from dotenv import load_dotenv


BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")


VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "").strip()
ALIENVAULT_OTX_API_KEY = os.getenv(
    "ALIENVAULT_OTX_API_KEY", ""
).strip()

JWT_SECRET = os.getenv("JWT_SECRET", "").strip()

DEFAULT_ADMIN_USERNAME = os.getenv(
    "DEFAULT_ADMIN_USERNAME", "admin"
).strip()

DEFAULT_ADMIN_PASSWORD = os.getenv(
    "DEFAULT_ADMIN_PASSWORD", ""
).strip()

RASA_REST_URL = os.getenv(
    "RASA_REST_URL",
    "http://127.0.0.1:5005/webhooks/rest/webhook",
).strip()

SOAR_SIMULATION_MODE = (
    os.getenv("SOAR_SIMULATION_MODE", "true").lower() == "true"
)


if not JWT_SECRET:
    raise RuntimeError(
        "JWT_SECRET is missing. Add it to the .env file."
    )


PLAYBOOK_SIMULATION_MODE = (
    os.getenv(
        "PLAYBOOK_SIMULATION_MODE",
        "true",
    ).lower() == "true"
)
