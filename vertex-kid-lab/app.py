from flask import Flask, request, jsonify, render_template, make_response
import base64, json, hmac, hashlib, time, os

app = Flask(__name__)

# ─────────────────────────────────────────────────────────
#  Répertoire des clés HMAC (par "kid")
# ─────────────────────────────────────────────────────────
KEYS_DIR = "/tmp/vertex_keys"
os.makedirs(KEYS_DIR, exist_ok=True)

# Clé principale légitime
PRIMARY_SECRET = b"vertex-primary-secret-9f2a7c"
with open(os.path.join(KEYS_DIR, "primary.key"), "wb") as f:
    f.write(PRIMARY_SECRET)

# Clé secondaire (rotation)
with open(os.path.join(KEYS_DIR, "secondary.key"), "wb") as f:
    f.write(b"vertex-secondary-4e1b8a")

# ─────────────────────────────────────────────────────────
#  Utilisateurs
# ─────────────────────────────────────────────────────────
USERS = {
    "marc":  {"password": "marc123",  "sub": "1", "role": "user",  "email": "marc@vertex.io"},
    "admin": {"password": "admin123", "sub": "0", "role": "admin", "email": "admin@vertex.io"},
}

# ─────────────────────────────────────────────────────────
#  Helpers JWT
# ─────────────────────────────────────────────────────────
def b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

def load_key_from_kid(kid: str):
    """Charge la clé associée au kid (VULNERABLE : aucune validation)."""
    path = os.path.join(KEYS_DIR, kid)
    try:
        with open(path, "rb") as f:
            return f.read()
    except Exception:
        return None

def jwt_sign(payload, kid="primary.key"):
    header = {"alg": "HS256", "typ": "JWT", "kid": kid}
    h = b64e(json.dumps(header, separators=(",", ":")).encode())
    p = b64e(json.dumps(payload, separators=(",", ":")).encode())
    key = load_key_from_kid(kid) or PRIMARY_SECRET
    sig = hmac.new(key, f"{h}.{p}".encode(), hashlib.sha256).digest()
    return f"{h}.{p}.{b64e(sig)}"

def make_token(username):
    u = USERS[username]
    return jwt_sign({
        "sub": u["sub"],
        "username": username,
        "email": u["email"],
        "role": u["role"],
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
    })

def decode_unsafe(token):
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("invalid format")
    return json.loads(b64d(parts[1]))

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
#  🔴 VULNÉRABLE : lit kid depuis le header et l'utilise
#     directement comme chemin de fichier
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
        kid = header.get("kid")

        # ❌ Faille : on charge le fichier désigné par le kid, sans validation
        key = load_key_from_kid(kid)
        if key is None:
            raise ValueError(f"key '{kid}' not found")

        expected = hmac.new(key, f"{h_b64}.{p_b64}".encode(), hashlib.sha256).digest()
        if not hmac.compare_digest(expected, b64d(s_b64)):
            raise ValueError("invalid signature")
    except Exception as e:
        return jsonify(ok=False, error=str(e)), 401

    if payload.get("role") != "admin":
        return jsonify(ok=False, error="Accès refusé"), 403

    return jsonify(ok=True, data={
        "flag": "SPECTRA{k1d_p4th_tr4v3rs4l_pwn3d}",
        "overview": {
            "revenu_mensuel": "248 500 EUR",
            "clients_actifs": 1842,
            "taux_retention": "94.2 %",
            "requetes_jour": 1284520,
        },
        "customers": [
            {"id": 1, "name": "Airbus SE",       "plan": "Enterprise", "mrr": "42 000 EUR", "status": "actif"},
            {"id": 2, "name": "Decathlon SA",    "plan": "Business",   "mrr": "18 500 EUR", "status": "actif"},
            {"id": 3, "name": "Ubisoft Ent.",    "plan": "Enterprise", "mrr": "38 200 EUR", "status": "actif"},
            {"id": 4, "name": "Doctolib",        "plan": "Business",   "mrr": "22 100 EUR", "status": "actif"},
            {"id": 5, "name": "OVHcloud",        "plan": "Enterprise", "mrr": "56 800 EUR", "status": "actif"},
        ],
        "activity": [
            "10:42 — Nouvel abonnement Enterprise : Thales Group",
            "09:18 — Pic d'utilisation API : 4 200 req/s",
            "08:55 — Déploiement v3.2.1 réussi",
            "07:30 — Sauvegarde chiffrée effectuée",
        ],
    })

# ─────────────────────────────────────────────────────────
#  🟢 SÉCURISÉ : ignore kid, utilise une clé fixe côté serveur
# ─────────────────────────────────────────────────────────
@app.route("/api/admin/secure")
def admin_secure():
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

        # ✅ On impose l'algorithme
        if header.get("alg") != "HS256":
            raise ValueError("algorithm not allowed")

        # ✅ Clé fixe, indépendante du kid fourni par le client
        expected = hmac.new(PRIMARY_SECRET, f"{h_b64}.{p_b64}".encode(), hashlib.sha256).digest()
        if not hmac.compare_digest(expected, b64d(s_b64)):
            raise ValueError("invalid signature")

        if "exp" in payload and int(payload["exp"]) < int(time.time()):
            raise ValueError("token expired")
    except Exception as e:
        return jsonify(ok=False, error=f"Bloqué: {e}"), 401

    if payload.get("role") != "admin":
        return jsonify(ok=False, error="Accès refusé"), 403

    return jsonify(ok=True, data={"message": "Accès autorisé — kid ignoré"})

if __name__ == "__main__":
    app.run(debug=True, port=5000)