import json
import os
import secrets
import sqlite3
import time
import base64
from urllib.parse import urlencode, quote

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from flask import Flask, request, redirect, render_template, session, jsonify, url_for
import jwt

# ── Configuration ──────────────────────────────────────────────────────────

COMPANY_NAME = "Wissen Technology"
ALLOWED_EMAIL_DOMAIN = "wissen.com"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "employees.db")
KEYS_DIR = os.path.join(BASE_DIR, "keys")
os.makedirs(KEYS_DIR, exist_ok=True)

PRIVATE_KEY_PATH = os.path.join(KEYS_DIR, "private_key.pem")
PUBLIC_KEY_PATH = os.path.join(KEYS_DIR, "public_key.pem")

_default_redirect_uris_env = os.environ.get("REDIRECT_URIS")
CLIENTS_REDIRECT_URIS = (
    json.loads(_default_redirect_uris_env)
    if _default_redirect_uris_env
    else ["http://localhost:8080/callback"]
)

CLIENTS = {
    "demo-client": {
        "client_secret": "demo-secret",
        "redirect_uris": CLIENTS_REDIRECT_URIS,
        "grant_types": ["authorization_code"],
        "response_types": ["code"],
    },
}

AUTH_CODE_EXPIRY_SECONDS = 300
ACCESS_TOKEN_EXPIRY_SECONDS = 3600
ID_TOKEN_EXPIRY_SECONDS = 3600

CLIENT_ID = "demo-client"
CLIENT_SECRET = "demo-secret"
SCOPES = "openid profile email"

APPS = [
    {"id": "zoho", "name": "Zoho Workplace", "color": "#e65100", "url": "https://www.zoho.com/workplace/"},
    {"id": "teams", "name": "Microsoft Teams", "color": "#6264a7", "url": "https://teams.microsoft.com/"},
    {"id": "slack", "name": "Slack", "color": "#4a154b", "url": "https://slack.com/"},
]

# ── Flask App ──────────────────────────────────────────────────────────────

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(32))

PORT = int(os.environ.get("FLASK_PORT", "8080").strip())
BASE_URL = os.environ.get("BASE_URL", f"http://localhost:{PORT}").strip()
ISSUER = BASE_URL

# ── RSA Keys ───────────────────────────────────────────────────────────────

def _base64url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def load_or_generate_keys():
    if os.path.exists(PRIVATE_KEY_PATH) and os.path.exists(PUBLIC_KEY_PATH):
        with open(PRIVATE_KEY_PATH, "rb") as f:
            priv = serialization.load_pem_private_key(f.read(), password=None)
        with open(PUBLIC_KEY_PATH, "rb") as f:
            pub = serialization.load_pem_public_key(f.read())
    else:
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pub = priv.public_key()
        with open(PRIVATE_KEY_PATH, "wb") as f:
            f.write(priv.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ))
        with open(PUBLIC_KEY_PATH, "wb") as f:
            f.write(pub.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ))
    return priv, pub


private_key, public_key = load_or_generate_keys()


def get_jwk():
    nums = public_key.public_numbers()
    n_bytes = nums.n.to_bytes((nums.n.bit_length() + 7) // 8, "big")
    e_bytes = nums.e.to_bytes((nums.e.bit_length() + 7) // 8, "big")
    return {
        "kty": "RSA",
        "n": _base64url_encode(n_bytes),
        "e": _base64url_encode(e_bytes),
        "alg": "RS256",
        "use": "sig",
        "kid": "wissen-sso-key-1",
    }


# ── In-memory auth code store ──────────────────────────────────────────────

auth_codes = {}


def generate_auth_code():
    return secrets.token_urlsafe(32)


# ── Database helpers ───────────────────────────────────────────────────────

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def get_employee(email):
    conn = get_db_connection()
    user = conn.execute(
        "SELECT name, email, password FROM employees WHERE email = ?",
        (email,),
    ).fetchone()
    conn.close()
    return user


def init_database():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS employees (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        )
    """)
    employees = [
        ("Shaila Pandya", "shaila.pandya@wissen.com", "shaila123"),
        ("Rahul Pandey", "rahul.pandey@wissen.com", "rahul456"),
        ("Nandini Sharma", "nandini.sharma@wissen.com", "nandini000"),
        ("Krishna Kaushik", "krishna.kaushik@wissen.com", "krishna444"),
        ("Aadya Billore", "aadya.billore@wissen.com", "aadya888"),
    ]
    existing = c.execute("SELECT COUNT(*) FROM employees").fetchone()[0]
    if existing == 0:
        c.executemany(
            "INSERT INTO employees (name, email, password) VALUES (?, ?, ?)",
            employees,
        )
        conn.commit()
    conn.close()


init_database()

# ── Token generation ───────────────────────────────────────────────────────

def make_id_token(user_name, user_email, client_id, nonce=None):
    now = int(time.time())
    payload = {
        "iss": ISSUER,
        "sub": user_email,
        "aud": client_id,
        "exp": now + ID_TOKEN_EXPIRY_SECONDS,
        "iat": now,
        "auth_time": now,
        "email": user_email,
        "email_verified": True,
        "name": user_name,
        "preferred_username": user_email.split("@")[0],
    }
    if nonce:
        payload["nonce"] = nonce
    return jwt.encode(
        payload, private_key, algorithm="RS256", headers={"kid": "wissen-sso-key-1"}
    )


def make_access_token(user_name, user_email, client_id, scope):
    now = int(time.time())
    payload = {
        "iss": ISSUER,
        "sub": user_email,
        "aud": client_id,
        "exp": now + ACCESS_TOKEN_EXPIRY_SECONDS,
        "iat": now,
        "scope": scope,
        "client_id": client_id,
        "name": user_name,
    }
    return jwt.encode(
        payload, private_key, algorithm="RS256", headers={"kid": "wissen-sso-key-1"}
    )


# ── Client validation ──────────────────────────────────────────────────────

def validate_client(client_id, client_secret=None):
    client = CLIENTS.get(client_id)
    if not client:
        return None
    if client_secret and client["client_secret"] != client_secret:
        return None
    return client


def validate_redirect_uri(client, redirect_uri):
    return redirect_uri in client["redirect_uris"]


# ── Internal token exchange (no HTTP) ──────────────────────────────────────

def exchange_code(code, client_id, client_secret, redirect_uri):
    client = validate_client(client_id, client_secret)
    if not client:
        return {"error": "invalid_client"}, 401

    if code not in auth_codes:
        return {"error": "invalid_grant"}, 400

    stored = auth_codes.pop(code)
    if stored["client_id"] != client_id:
        return {"error": "invalid_grant"}, 400
    if stored["redirect_uri"] != redirect_uri:
        return {"error": "invalid_grant"}, 400
    if time.time() > stored["expires_at"]:
        return {"error": "invalid_grant"}, 400

    user = stored["user"]
    scope = stored["scope"] or "openid"
    nonce = stored.get("nonce")

    id_token = make_id_token(user["name"], user["email"], client_id, nonce)
    access_token = make_access_token(user["name"], user["email"], client_id, scope)

    return {
        "access_token": access_token,
        "id_token": id_token,
        "token_type": "Bearer",
        "expires_in": ACCESS_TOKEN_EXPIRY_SECONDS,
        "scope": scope,
    }, 200


# ═══════════════════════════════════════════════════════════════════════════
#  SSO ROUTES
# ═══════════════════════════════════════════════════════════════════════════

@app.route("/.well-known/openid-configuration")
def openid_configuration():
    return jsonify({
        "issuer": ISSUER,
        "authorization_endpoint": f"{ISSUER}/authorize",
        "token_endpoint": f"{ISSUER}/token",
        "userinfo_endpoint": f"{ISSUER}/userinfo",
        "jwks_uri": f"{ISSUER}/jwks.json",
        "end_session_endpoint": f"{ISSUER}/sso-logout",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "token_endpoint_auth_methods_supported": ["client_secret_post"],
        "claims_supported": ["sub", "email", "name", "preferred_username"],
    })


@app.route("/jwks.json")
def jwks_uri():
    return jsonify({"keys": [get_jwk()]})


@app.route("/access-denied")
def access_denied():
    reason = request.args.get("reason", "You are not authorized to access this system.")
    return render_template("access-denied.html",
        company_name=COMPANY_NAME,
        reason=reason)


@app.route("/authorize", methods=["GET", "POST"])
def authorize():
    client_id = request.args.get("client_id")
    redirect_uri = request.args.get("redirect_uri")
    response_type = request.args.get("response_type", "code")
    scope = request.args.get("scope", "openid profile email")
    state = request.args.get("state")
    nonce = request.args.get("nonce")

    if request.method == "POST":
        client_id = request.form.get("client_id") or client_id
        redirect_uri = request.form.get("redirect_uri") or redirect_uri
        response_type = request.form.get("response_type") or response_type
        scope = request.form.get("scope") or scope
        state = request.form.get("state") or state
        nonce = request.form.get("nonce") or nonce

    if not client_id:
        return "Missing client_id", 400

    client = validate_client(client_id)
    if not client:
        return "Invalid client", 400

    if not validate_redirect_uri(client, redirect_uri):
        return "Invalid redirect_uri", 400

    if request.method == "GET":
        error = request.args.get("error")
        if "sso_user" in session:
            return render_template("consent.html",
                company_name=COMPANY_NAME,
                client_id=client_id,
                redirect_uri=redirect_uri,
                scope=scope,
                state=state,
                nonce=nonce,
                user=session["sso_user"])
        return render_template("login.html",
            company_name=COMPANY_NAME,
            client_id=client_id,
            redirect_uri=redirect_uri,
            scope=scope,
            state=state,
            nonce=nonce,
            error=error)

    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")

    if not email.endswith(f"@{ALLOWED_EMAIL_DOMAIN}"):
        return redirect(url_for("access_denied",
            reason=quote(f"Only @{ALLOWED_EMAIL_DOMAIN} email addresses are allowed")))

    employee = get_employee(email)

    if not employee:
        return redirect(url_for("access_denied",
            reason=quote("This email is not registered as a Wissen Technology employee")))

    if employee["password"] != password:
        return redirect(url_for("access_denied", reason=quote("Incorrect password")))

    session["sso_user"] = {
        "name": employee["name"],
        "email": employee["email"],
    }

    return render_template("consent.html",
        company_name=COMPANY_NAME,
        client_id=client_id,
        redirect_uri=redirect_uri,
        scope=scope,
        state=state,
        nonce=nonce,
        user=session["sso_user"])


@app.route("/consent", methods=["POST"])
def consent():
    action = request.form.get("action")
    redirect_uri = request.form.get("redirect_uri")

    if action != "allow":
        return redirect(f"{redirect_uri}?error=access_denied")

    client_id = request.form.get("client_id")
    scope = request.form.get("scope")
    state = request.form.get("state")
    nonce = request.form.get("nonce")

    if "sso_user" not in session:
        return redirect(f"{redirect_uri}?error=login_required")

    user = session["sso_user"]

    code = generate_auth_code()
    auth_codes[code] = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "user": user,
        "scope": scope,
        "nonce": nonce,
        "expires_at": time.time() + AUTH_CODE_EXPIRY_SECONDS,
    }

    params = urlencode({"code": code, "state": state}) if state else urlencode({"code": code})
    return redirect(f"{redirect_uri}?{params}")


@app.route("/token", methods=["POST"])
def token():
    code = request.form.get("code")
    client_id = request.form.get("client_id")
    client_secret = request.form.get("client_secret")
    redirect_uri = request.form.get("redirect_uri")

    result, status = exchange_code(code, client_id, client_secret, redirect_uri)
    return jsonify(result), status


@app.route("/userinfo", methods=["GET"])
def userinfo():
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"error": "invalid_token"}), 401

    token = auth_header.replace("Bearer ", "", 1)

    try:
        payload = jwt.decode(
            token, public_key, algorithms=["RS256"],
            options={"verify_aud": False}
        )
    except Exception as e:
        return jsonify({"error": "invalid_token", "description": str(e)}), 401

    email = payload.get("sub")
    name = payload.get("name", email.split("@")[0])

    return jsonify({
        "sub": email,
        "email": email,
        "email_verified": True,
        "name": name,
        "preferred_username": email.split("@")[0],
    })


@app.route("/sso-logout")
def sso_logout():
    session.pop("sso_user", None)
    redirect_uri = request.args.get("redirect_uri", "/")
    return redirect(redirect_uri)


# ═══════════════════════════════════════════════════════════════════════════
#  CLIENT ROUTES
# ═══════════════════════════════════════════════════════════════════════════

@app.route("/")
def home():
    if "client_user" in session:
        return render_template("home.html",
            company_name=COMPANY_NAME,
            user=session["client_user"],
            apps=APPS,
            authenticated=True)
    return render_template("home.html",
        company_name=COMPANY_NAME,
        apps=APPS,
        authenticated=False)


@app.route("/login")
def login():
    app_id = request.args.get("app")
    if not app_id or not any(a["id"] == app_id for a in APPS):
        app_id = "zoho"

    if "client_user" in session:
        return redirect(url_for("launch_app", app_id=app_id))

    session["pending_app"] = app_id

    state = secrets.token_urlsafe(16)
    nonce = secrets.token_urlsafe(16)
    session["oauth_state"] = state
    session["oauth_nonce"] = nonce

    params = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": f"{BASE_URL}/callback",
        "scope": SCOPES,
        "state": state,
        "nonce": nonce,
    }
    qs = urlencode(params)
    return redirect(f"{BASE_URL}/authorize?{qs}")


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

    # Exchange code directly (no HTTP loopback needed)
    result, status = exchange_code(code, CLIENT_ID, CLIENT_SECRET, f"{BASE_URL}/callback")

    if status != 200:
        return f"Token exchange failed ({status}): {result}", 400

    tokens = result
    id_token = tokens["id_token"]

    verification_note = None
    try:
        jwk_data = get_jwk()
        signing_key = jwt.PyJWK(jwk_data)

        user_info = jwt.decode(
            id_token,
            signing_key.key,
            algorithms=["RS256"],
            audience=CLIENT_ID,
            issuer=BASE_URL,
            options={"require": ["exp", "iss", "aud"]},
        )
    except Exception as e:
        user_info = jwt.decode(id_token, options={"verify_signature": False})
        verification_note = f"Signature verification skipped: {e}"

    user_info["_verification_note"] = (
        "Verified using RS256 signature from JWKS" if not verification_note else verification_note
    )

    session["client_user"] = user_info
    session["tokens"] = tokens

    pending_app = session.pop("pending_app", None)
    if pending_app:
        return redirect(url_for("launch_app", app_id=pending_app))
    return redirect(url_for("launch_app", app_id="zoho"))


@app.route("/apps/<app_id>")
def launch_app(app_id):
    user = session.get("client_user")
    if not user:
        return redirect(url_for("login", app=app_id))

    app_info = next((a for a in APPS if a["id"] == app_id), None)
    if not app_info:
        return "App not found", 404

    return render_template("app-landing.html",
        company_name=COMPANY_NAME,
        user=user,
        app=app_info)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


# ── Public key endpoint ────────────────────────────────────────────────────

@app.route("/public-key")
def public_key_endpoint():
    with open(PUBLIC_KEY_PATH, "rb") as f:
        return f.read().decode("utf-8"), 200, {"Content-Type": "text/plain"}


# ── Main ───────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    debug_mode = os.environ.get("FLASK_DEBUG", "").lower() in ("1", "true", "yes")
    app.run(host="0.0.0.0", port=PORT, debug=debug_mode, threaded=True)
