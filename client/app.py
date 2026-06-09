import os
import secrets
from urllib.parse import urlencode

import requests
from flask import Flask, redirect, request, render_template, session, url_for
import jwt

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(32))

CLIENT_PORT = int(os.environ.get("FLASK_PORT", 8001))
CLIENT_PUBLIC_URL = os.environ.get("CLIENT_PUBLIC_URL", f"http://localhost:{CLIENT_PORT}").strip()

SSO_PUBLIC_URL = os.environ.get("SSO_PUBLIC_URL", "http://localhost:8080").strip()
SSO_INTERNAL_URL = os.environ.get("SSO_INTERNAL_URL", "http://localhost:8080").strip()

CLIENT_ID = "demo-client"
CLIENT_SECRET = "demo-secret"

SCOPES = "openid profile email"

APPS = [
    {"id": "zoho", "name": "Zoho Workplace", "color": "#e65100", "url": "https://www.zoho.com/workplace/"},
    {"id": "teams", "name": "Microsoft Teams", "color": "#6264a7", "url": "https://teams.microsoft.com/"},
    {"id": "slack", "name": "Slack", "color": "#4a154b", "url": "https://slack.com/"},
]


@app.route("/")
def home():
    if "user" in session:
        return render_template("home.html",
            company_name="Wissen Technology",
            user=session["user"],
            apps=APPS,
            authenticated=True)
    return render_template("home.html",
        company_name="Wissen Technology",
        apps=APPS,
        authenticated=False)


@app.route("/login")
def login():
    app_id = request.args.get("app")
    if not app_id or not any(a["id"] == app_id for a in APPS):
        app_id = "zoho"

    if "user" in session:
        return redirect(url_for("launch_app", app_id=app_id))

    session["pending_app"] = app_id

    state = secrets.token_urlsafe(16)
    nonce = secrets.token_urlsafe(16)
    session["oauth_state"] = state
    session["oauth_nonce"] = nonce

    params = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": f"{CLIENT_PUBLIC_URL}/callback",
        "scope": SCOPES,
        "state": state,
        "nonce": nonce,
    }
    qs = urlencode(params)
    return redirect(f"{SSO_PUBLIC_URL}/authorize?{qs}")


@app.route("/callback")
def callback():
    code = request.args.get("code")
    state = request.args.get("state")
    error = request.args.get("error")

    if error:
        return f"Authorization denied: {error}", 400

    if not code:
        return "No authorization code received", 400

    saved_state = session.pop("oauth_state", None)
    if state and saved_state and state != saved_state:
        return "State mismatch - possible CSRF", 400

    nonce = session.pop("oauth_nonce", None)

    resp = requests.post(f"{SSO_INTERNAL_URL}/token", timeout=10, data={
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": f"{CLIENT_PUBLIC_URL}/callback",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
    })

    if resp.status_code != 200:
        return f"Token exchange failed ({resp.status_code}): {resp.text}", 400

    tokens = resp.json()
    id_token = tokens["id_token"]

    verification_note = None
    try:
        jwks_resp = requests.get(f"{SSO_INTERNAL_URL}/jwks.json", timeout=10)
        jwks = jwks_resp.json()
        unverified_headers = jwt.get_unverified_header(id_token)
        kid = unverified_headers.get("kid")

        signing_key = None
        for key_data in jwks.get("keys", []):
            if kid and key_data.get("kid") != kid:
                continue
            signing_key = jwt.PyJWK(key_data)
            break

        if not signing_key:
            signing_key = jwt.PyJWK(jwks["keys"][0])

        user_info = jwt.decode(
            id_token,
            signing_key.key,
            algorithms=["RS256"],
            audience=CLIENT_ID,
            issuer=SSO_PUBLIC_URL,
            options={"require": ["exp", "iss", "aud"]},
        )
    except Exception as e:
        user_info = jwt.decode(id_token, options={"verify_signature": False})
        verification_note = f"Signature verification skipped: {e}"

    user_info["_verification_note"] = (
        "Verified using RS256 signature from JWKS" if not verification_note else verification_note
    )

    session["user"] = user_info
    session["tokens"] = tokens

    pending_app = session.pop("pending_app", None)
    if pending_app:
        return redirect(url_for("launch_app", app_id=pending_app))
    return redirect(url_for("launch_app", app_id="zoho"))


@app.route("/apps/<app_id>")
def launch_app(app_id):
    user = session.get("user")
    if not user:
        return redirect(url_for("login", app=app_id))

    app_info = next((a for a in APPS if a["id"] == app_id), None)
    if not app_info:
        return "App not found", 404

    return render_template("app-landing.html",
        company_name="Wissen Technology",
        user=user,
        app=app_info)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


if __name__ == "__main__":
    debug_mode = os.environ.get("FLASK_DEBUG", "").lower() in ("1", "true", "yes")
    app.run(host="0.0.0.0", port=CLIENT_PORT, debug=debug_mode, threaded=True)
