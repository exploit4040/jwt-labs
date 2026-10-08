from flask import Flask, request, jsonify, render_template, make_response
import base64, json, hmac, hashlib, time

app = Flask(__name__)
SECRET_KEY = b"super-secret-key"

# ─────────────────────────────────────────────────────────
#  "Base de données" utilisateurs
# ─────────────────────────────────────────────────────────
USERS = {
    "alice": {"password": "alice123", "sub": "1", "role": "user",  "email": "alice@acme.io"},
    "bob":   {"password": "bob123",   "sub": "2", "role": "user",  "email": "bob@acme.io"},
    "admin": {"password": "admin123", "sub": "0", "role": "admin", "email": "admin@acme.io"},
}

# ─────────────────────────────────────────────────────────
#  Helpers JWT
# ─────────────────────────────────────────────────────────
def b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def b64d(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))

def jwt_encode(payload, secret, alg="HS256"):
    header = {"alg": alg, "typ": "JWT"}
    h = b64e(json.dumps(header, separators=(",", ":")).encode())
    p = b64e(json.dumps(payload, separators=(",", ":")).encode())
    sig = hmac.new(secret, f"{h}.{p}".encode(), hashlib.sha256).digest()
    return f"{h}.{p}.{b64e(sig)}"

def jwt_decode(token, secret, allowed=("HS256",), check_sig=True, check_exp=True):
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("invalid token format")
    h_b64, p_b64, s_b64 = parts
    try:
        header  = json.loads(b64d(h_b64))
        payload = json.loads(b64d(p_b64))
    except Exception:
        raise ValueError("invalid encoding")

    if header.get("alg") not in allowed:
        raise ValueError("algorithm not allowed")

    if check_sig:
        if not s_b64:
            raise ValueError("missing signature")
        expected = b64e(hmac.new(secret, f"{h_b64}.{p_b64}".encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(expected, s_b64):
            raise ValueError("invalid signature")

    if check_exp and "exp" in payload and int(payload["exp"]) < int(time.time()):
        raise ValueError("token expired")

    return payload

def make_token(username):
    u = USERS[username]
    return jwt_encode({
        "sub": u["sub"],
        "username": username,
        "email": u["email"],
        "role": u["role"],
        "isAdmin": u["role"] == "admin",
        "permissions": ["read"] if u["role"] == "user" else ["read", "write", "delete", "admin"],
        "exp": int(time.time()) + 3600,
    }, SECRET_KEY)

def get_token_from_request():
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
    token = get_token_from_request()
    if not token:
        return jsonify(ok=False, error="Non authentifié"), 401
    try:
        payload = json.loads(b64d(token.split(".")[1]))
    except Exception as e:
        return jsonify(ok=False, error=str(e)), 401
    return jsonify(ok=True, user=payload)

# ─────────────────────────────────────────────────────────
#  🔴 VULNÉRABLE : re-signe les claims fournis par le client
# ─────────────────────────────────────────────────────────
@app.route("/api/profile", methods=["PUT"])
def update_profile_vuln():
    token = get_token_from_request()
    if not token:
        return jsonify(ok=False, error="Non authentifié"), 401
    try:
        payload = jwt_decode(token, SECRET_KEY, allowed=("HS256",))
    except Exception as e:
        return jsonify(ok=False, error=str(e)), 401

    updates = request.get_json() or {}

    # ❌ Faille : fusion aveugle + re-signature de TOUS les champs
    new_payload = {**payload, **updates}
    new_payload["exp"] = int(time.time()) + 3600

    new_token = jwt_encode(new_payload, SECRET_KEY)
    resp = make_response(jsonify(ok=True, user=new_payload))
    resp.set_cookie("token", new_token, httponly=False)
    return resp

# ─────────────────────────────────────────────────────────
#  🟢 CORRIGÉ : whitelist stricte des champs modifiables
# ─────────────────────────────────────────────────────────
@app.route("/api/profile/secure", methods=["PUT"])
def update_profile_secure():
    token = get_token_from_request()
    if not token:
        return jsonify(ok=False, error="Non authentifié"), 401
    try:
        payload = jwt_decode(token, SECRET_KEY, allowed=("HS256",))
    except Exception as e:
        return jsonify(ok=False, error=str(e)), 401

    updates = request.get_json() or {}

    # ✅ Whitelist : seuls email et username modifiables
    ALLOWED_FIELDS = {"email"}
    clean = {k: v for k, v in updates.items() if k in ALLOWED_FIELDS}

    # ✅ On recharge le rôle DEPUIS LA BASE, jamais depuis le client
    username = payload.get("username")
    if username not in USERS:
        return jsonify(ok=False, error="Utilisateur inconnu"), 401
    db_user = USERS[username]

    new_payload = {
        "sub":         db_user["sub"],
        "username":    username,
        "email":       clean.get("email", db_user["email"]),
        "role":        db_user["role"],                              # <— source de vérité
        "isAdmin":     db_user["role"] == "admin",
        "permissions": ["read"] if db_user["role"] == "user" else ["read", "write", "delete", "admin"],
        "exp":         int(time.time()) + 3600,
    }

    new_token = jwt_encode(new_payload, SECRET_KEY)
    resp = make_response(jsonify(ok=True, user=new_payload))
    resp.set_cookie("token", new_token, httponly=False)
    return resp

# ─────────────────────────────────────────────────────────
#  🔴 VULNÉRABLE : fait confiance au claim "role" du JWT
# ─────────────────────────────────────────────────────────
@app.route("/api/admin/data")
def admin_data_vuln():
    token = get_token_from_request()
    if not token:
        return jsonify(ok=False, error="Non authentifié"), 401
    try:
        payload = jwt_decode(token, SECRET_KEY, allowed=("HS256",))
    except Exception as e:
        return jsonify(ok=False, error=str(e)), 401

    # ❌ On croit le token sur parole
    if payload.get("role") != "admin":
        return jsonify(ok=False, error="Accès refusé"), 403

    return jsonify(ok=True, data={
        "flag": "SPECTRA{cl41ms_4r3_n0t_trust}",
        "stats": {
            "utilisateurs": 1284,
            "commandes_du_jour": 342,
            "revenu_mensuel": "1 250 000 EUR",
            "taux_conversion": "4.7 %",
        },
        "users": [
            {"id": 1, "username": "alice",   "role": "user",  "email": "alice@acme.io",   "status": "actif"},
            {"id": 2, "username": "bob",     "role": "user",  "email": "bob@acme.io",     "status": "actif"},
            {"id": 3, "username": "charlie", "role": "user",  "email": "charlie@acme.io", "status": "inactif"},
            {"id": 4, "username": "diana",   "role": "mod",   "email": "diana@acme.io",   "status": "actif"},
            {"id": 5, "username": "admin",   "role": "admin", "email": "admin@acme.io",   "status": "actif"},
        ],
        "logs": [
            "12:01 - alice a passé commande #4821",
            "12:14 - bob a modifié son profil",
            "12:32 - diana a validé 3 remboursements",
            "13:05 - admin a généré le rapport Q4",
            "13:47 - nouveau compte créé : eve@acme.io",
        ],
        "settings": {
            "maintenance": False,
            "mode_paiement": "Stripe",
            "region": "EU-West",
        }
    })

# ─────────────────────────────────────────────────────────
#  🟢 CORRIGÉ : vérifie le rôle en base, ignore le claim
# ─────────────────────────────────────────────────────────
@app.route("/api/admin/secure")
def admin_data_secure():
    token = get_token_from_request()
    if not token:
        return jsonify(ok=False, error="Non authentifié"), 401
    try:
        payload = jwt_decode(token, SECRET_KEY, allowed=("HS256",))
    except Exception as e:
        return jsonify(ok=False, error=f"Bloqué: {e}"), 401

    # ✅ Le rôle vient de la base, jamais du token
    username = payload.get("username")
    if username not in USERS:
        return jsonify(ok=False, error="Utilisateur inconnu"), 401
    if USERS[username]["role"] != "admin":
        return jsonify(ok=False, error="Accès refusé"), 403

    return jsonify(ok=True, data={"message": "Accès autorisé"})

if __name__ == "__main__":
    app.run(debug=True, port=5000)