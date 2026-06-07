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
from flask import Flask, request, redirect, render_template, session, jsonify
import jwt

from .config import (
    COMPANY_NAME,
    ALLOWED_EMAIL_DOMAIN,
    DB_PATH,
    CLIENTS,
    AUTH_CODE_EXPIRY_SECONDS,
    ACCESS_TOKEN_EXPIRY_SECONDS,
    ID_TOKEN_EXPIRY_SECONDS,
)

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(32))

PORT = int(os.environ.get("FLASK_PORT", 8000))
ISSUER = f"http://localhost:{PORT}"

KEYS_DIR = os.path.join(os.path.dirname(__file__), "keys")
os.makedirs(KEYS_DIR, exist_ok=True)
PRIVATE_KEY_PATH = os.path.join(KEYS_DIR, "private_key.pem")
PUBLIC_KEY_PATH = os.path.join(KEYS_DIR, "public_key.pem")


def _base64url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def load_or_generate_keys():
    if os.path.exists(PRIVATE_KEY_PATH) and os.path.exists(PUBLIC_KEY_PATH):
        with open(PRIVATE_KEY_PATH, "rb") as f:
            priv = serialization.load_pem_private_key(f.read(), password=None)
        with open(PUBLIC_KEY_PATH, "rb") as f:
            pub = serialization.load_pem_public_key(f.read())
    else:
        priv = rsa.generate_private_key(
            public_exponent=65537, key_size=2048
        )
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


auth_codes = {}


def generate_auth_code():
    return secrets.token_urlsafe(32)


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


def validate_client(client_id, client_secret=None):
    client = CLIENTS.get(client_id)
    if not client:
        return None
    if client_secret and client["client_secret"] != client_secret:
        return None
    return client


def validate_redirect_uri(client, redirect_uri):
    return redirect_uri in client["redirect_uris"]


def init_database():
    from .init_db import init_db
    init_db()


init_database()


@app.route("/.well-known/openid-configuration")
def openid_configuration():
    return jsonify({
        "issuer": ISSUER,
        "authorization_endpoint": f"{ISSUER}/authorize",
        "token_endpoint": f"{ISSUER}/token",
        "userinfo_endpoint": f"{ISSUER}/userinfo",
        "jwks_uri": f"{ISSUER}/jwks.json",
        "end_session_endpoint": f"{ISSUER}/logout",
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

    def build_error_redirect(error_msg):
        params = urlencode({
            k: v for k, v in [
                ("client_id", client_id),
                ("redirect_uri", redirect_uri),
                ("response_type", response_type),
                ("scope", scope),
                ("state", state),
                ("nonce", nonce),
                ("error", error_msg),
            ] if v is not None
        })
        return redirect(f"{ISSUER}/authorize?{params}")

    if request.method == "GET":
        error = request.args.get("error")
        if "user" in session:
            return render_template("consent.html",
                company_name=COMPANY_NAME,
                client_id=client_id,
                redirect_uri=redirect_uri,
                scope=scope,
                state=state,
                nonce=nonce,
                user=session["user"])
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
        return redirect(f"{ISSUER}/access-denied?reason={quote('Only @wissen.com email addresses are allowed')}")

    employee = get_employee(email)

    if not employee:
        return redirect(f"{ISSUER}/access-denied?reason={quote('This email is not registered as a Wissen Technology employee')}")

    if employee["password"] != password:
        return redirect(f"{ISSUER}/access-denied?reason={quote('Incorrect password')}")

    session["user"] = {
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
        user=session["user"])


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

    if "user" not in session:
        return redirect(f"{redirect_uri}?error=login_required")

    user = session["user"]

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
    grant_type = request.form.get("grant_type")

    if grant_type != "authorization_code":
        return jsonify({"error": "unsupported_grant_type"}), 400

    client = validate_client(client_id, client_secret)
    if not client:
        return jsonify({"error": "invalid_client"}), 401

    if code not in auth_codes:
        return jsonify({"error": "invalid_grant"}), 400

    stored = auth_codes.pop(code)
    if stored["client_id"] != client_id:
        return jsonify({"error": "invalid_grant"}), 400
    if stored["redirect_uri"] != redirect_uri:
        return jsonify({"error": "invalid_grant"}), 400
    if time.time() > stored["expires_at"]:
        return jsonify({"error": "invalid_grant"}), 400

    user = stored["user"]
    scope = stored["scope"] or "openid"
    nonce = stored.get("nonce")

    id_token = make_id_token(user["name"], user["email"], client_id, nonce)
    access_token = make_access_token(user["name"], user["email"], client_id, scope)

    return jsonify({
        "access_token": access_token,
        "id_token": id_token,
        "token_type": "Bearer",
        "expires_in": ACCESS_TOKEN_EXPIRY_SECONDS,
        "scope": scope,
    })


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


@app.route("/logout")
def logout():
    session.clear()
    redirect_uri = request.args.get("redirect_uri", "http://localhost:8001")
    return redirect(redirect_uri)


@app.route("/public-key")
def public_key_endpoint():
    with open(PUBLIC_KEY_PATH, "rb") as f:
        return f.read().decode("utf-8"), 200, {"Content-Type": "text/plain"}


if __name__ == "__main__":
    debug_mode = os.environ.get("FLASK_DEBUG", "").lower() in ("1", "true", "yes")
    app.run(host="0.0.0.0", port=PORT, debug=debug_mode)
