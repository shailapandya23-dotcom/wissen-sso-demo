# Wissen Technology SSO Demo

A single sign-on (SSO) demo built with Flask and OpenID Connect, featuring
an SSO Provider and a Client Portal with employee authentication.

## Architecture

```
SSO Provider  (port 8000)  -  Handles login, consent, token & userinfo endpoints
Client Portal (port 8001)  -  Protects app resources via OIDC authorization code flow
```

## Setup

```bash
pip install -r requirements.txt
```

## How to Run

**Both servers** (recommended):
```
start.bat
```

**Individually:**
```
start-sso.bat    # SSO Provider on http://localhost:8000
start-client.bat # Client Portal on http://localhost:8001
```

Open `http://localhost:8001` in your browser.

## Default Employees

The database is auto-seeded on first run with these test accounts:

| Name | Email | Password |
|---|---|---|
| Shaila Pandya | shaila.pandya@wissen.com | shaila123 |
| Rahul Pandey | rahul.pandey@wissen.com | rahul456 |
| Nandini Sharma | nandini.sharma@wissen.com | nandini000 |
| Krishna Kaushik | krishna.kaushik@wissen.com | krishna444 |
| Aadya Billore | aadya.billore@wissen.com | aadya888 |

Only `@wissen.com` email addresses are allowed.

## Tech Stack

- **Flask** — Web framework
- **PyJWT** — JWT encoding / decoding
- **Cryptography** — RSA key generation and JWKS
- **SQLite** — Employee database
- **OpenID Connect** — Authorization code flow
