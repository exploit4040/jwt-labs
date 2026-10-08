from flask import Flask, request, jsonify, render_template, make_response
import base64, json, hmac, hashlib, time
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

app = Flask(__name__)

# ─────────────────────────────────────────────────────────
#  Clé RSA générée au démarrage
# ─────────────────────────────────────────────────────────
PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
PUBLIC_KEY  = PRIVATE_KEY.public_key()

# PEM en UNE SEULE LIGNE (sans \n) : indispensable pour que jwt.io
# reproduise exactement le même secret HMAC que le serveur.
_pem = PUBLIC_KEY.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
).decode()

PUBLIC_KEY_PEM = _pem.replace("\n", "").encode()

# ─────────────────────────────────────────────────────────
#  Utilisateurs
# ─────────────────────────────────────────────────────────
USERS = {
    "alice": {"password": "alice123", "sub": "1", "role": "user",  "email": "alice@novabank.io"},
    "admin": {"password": "admin123", "sub": "0", "role": "admin", "email": "admin@novabank.io"},
}

# ─────────────────────────────────────────────────────────
#  Helpers JWT
# ─────────────────────────────────────────────────────────
def b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def b64d(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))

def jwt_sign_rs256(payload):
    header = {"alg": "RS256", "typ": "JWT"}
    h = b64e(json.dumps(header, separators=(",", ":")).encode())
    p = b64e(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h}.{p}".encode()
    sig = PRIVATE_KEY.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return f"{h}.{p}.{b64e(sig)}"

def jwt_verify_rs256(token):
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("invalid token format")
    h_b64, p_b64, s_b64 = parts
    header = json.loads(b64d(h_b64))
    payload = json.loads(b64d(p_b64))

    if header.get("alg") != "RS256":
        raise ValueError("algorithm not allowed")

    try:
        sig = b64d(s_b64)
        PUBLIC_KEY.verify(sig, f"{h_b64}.{p_b64}".encode(),
                          padding.PKCS1v15(), hashes.SHA256())
    except Exception:
        raise ValueError("invalid signature")

    if "exp" in payload and int(payload["exp"]) < int(time.time()):
        raise ValueError("token expired")

    return payload

def decode_unsafe(token):
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("invalid token format")
    return json.loads(b64d(parts[1]))

def make_token(username):
    u = USERS[username]
    return jwt_sign_rs256({
        "sub": u["sub"],
        "username": username,
        "email": u["email"],
        "role": u["role"],
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
    })

def get_token():
    return request.cookies.get("token") or \
           request.headers.get("Authorization", "").replace("Bearer ", "").strip()

# ─────────────────────────────────────────────────────────
#  Pages
# ─────────────────────────────────────────────────────────
@app.route("/")
def home():
    return render_template("login.html")

@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")

# ─────────────────────────────────────────────────────────
#  Clé publique exposée (single-line, prête pour jwt.io)
# ─────────────────────────────────────────────────────────
@app.route("/api/public-key")
def public_key_endpoint():
    return PUBLIC_KEY_PEM.decode(), 200, {"Content-Type": "text/plain"}

@app.route("/api/debug/secret")
def debug_secret():
    return jsonify({
        "length": len(PUBLIC_KEY_PEM),
        "first_30": PUBLIC_KEY_PEM[:30].decode(),
        "last_30":  PUBLIC_KEY_PEM[-30:].decode(),
    })

# ─────────────────────────────────────────────────────────
#  Auth
# ─────────────────────────────────────────────────────────
@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json() or {}
    username = data.get("username", "")
    password = data.get("password", "")
    if username in USERS and USERS[username]["password"] == password:
        resp = make_response(jsonify(ok=True, redirect="/dashboard"))
        resp.set_cookie("token", make_token(username), httponly=False)
        return resp
    return jsonify(ok=False, error="Identifiants incorrects"), 401

@app.route("/api/me")
def api_me():
    token = get_token()
    if not token:
        return jsonify(ok=False, error="Non authentifié"), 401
    try:
        payload = decode_unsafe(token)
    except Exception as e:
        return jsonify(ok=False, error=str(e)), 401
    return jsonify(ok=True, user=payload)

# ─────────────────────────────────────────────────────────
#  🔴 VULNÉRABLE : accepte HS256 en utilisant la clé publique
#     comme secret HMAC
# ─────────────────────────────────────────────────────────
@app.route("/api/admin/vulnerable")
def admin_vulnerable():
    token = get_token()
    if not token:
        return jsonify(ok=False, error="Non authentifié"), 401

    try:
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("invalid format")
        h_b64, p_b64, s_b64 = parts
        header  = json.loads(b64d(h_b64))
        payload = json.loads(b64d(p_b64))
        alg = header.get("alg")
        signing_input = f"{h_b64}.{p_b64}".encode()
        sig = b64d(s_b64)

        if alg == "HS256":
            expected = hmac.new(PUBLIC_KEY_PEM, signing_input, hashlib.sha256).digest()
            if not hmac.compare_digest(expected, sig):
                raise ValueError("invalid signature")
        elif alg == "RS256":
            PUBLIC_KEY.verify(sig, signing_input, padding.PKCS1v15(), hashes.SHA256())
        else:
            raise ValueError("algorithm not allowed")
    except Exception as e:
        return jsonify(ok=False, error=f"Erreur: {e}"), 401

    if payload.get("role") != "admin":
        return jsonify(ok=False, error="Accès refusé"), 403

    return jsonify(ok=True, data={
        "flag": "SPECTRA{rs256_turn3d_1nt0_hm4c}",
        "vault": {
            "solde_total": "12 480 250 EUR",
            "virements_jour": 342,
            "comptes_actifs": 8421,
            "alertes": 3,
        },
        "users": [
            {"id": 1, "username": "alice",   "role": "user",  "email": "alice@novabank.io",   "status": "actif"},
            {"id": 2, "username": "bob",     "role": "user",  "email": "bob@novabank.io",     "status": "actif"},
            {"id": 3, "username": "charlie", "role": "user",  "email": "charlie@novabank.io", "status": "inactif"},
            {"id": 4, "username": "diana",   "role": "mod",   "email": "diana@novabank.io",   "status": "actif"},
            {"id": 5, "username": "admin",   "role": "admin", "email": "admin@novabank.io",   "status": "actif"},
        ],
        "logs": [
            "09:12 - Virement 12 000 EUR vers FR76...4821",
            "09:47 - Connexion depuis 82.64.x.x",
            "10:03 - Nouveau compte créé : eve@novabank.io",
            "10:21 - Alerte : 3 tentatives échouées",
            "11:08 - Rapport réglementaire généré",
        ],
    })

# ─────────────────────────────────────────────────────────
#  🟢 SÉCURISÉ : impose RS256 explicitement
# ─────────────────────────────────────────────────────────
@app.route("/api/admin/secure")
def admin_secure():
    token = get_token()
    if not token:
        return jsonify(ok=False, error="Non authentifié"), 401

    try:
        payload = jwt_verify_rs256(token)
    except Exception as e:
        return jsonify(ok=False, error=f"Bloqué: {e}"), 401

    if payload.get("role") != "admin":
        return jsonify(ok=False, error="Accès refusé"), 403

    return jsonify(ok=True, data={"message": "Accès autorisé — RS256 vérifié"})

# ─────────────────────────────────────────────────────────
if __name__ == "__main__":
    app.run(debug=True, port=5000)