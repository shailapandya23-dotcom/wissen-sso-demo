import os

COMPANY_NAME = "Wissen Technology"

ALLOWED_EMAIL_DOMAIN = "wissen.com"

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "employees.db")

CLIENTS = {
    "demo-client": {
        "client_secret": "demo-secret",
        "redirect_uris": ["http://localhost:8001/callback"],
        "grant_types": ["authorization_code"],
        "response_types": ["code"],
    },
}

AUTH_CODE_EXPIRY_SECONDS = 300

ACCESS_TOKEN_EXPIRY_SECONDS = 3600

ID_TOKEN_EXPIRY_SECONDS = 3600
