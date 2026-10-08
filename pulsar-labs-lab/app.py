from flask import Flask, request, jsonify, render_template, make_response
import base64, json, hmac, hashlib, time

app = Flask(__name__)

# ─────────────────────────────────────────────────────────
#  ⚠️ SECRET FAIBLE — crackable par dictionnaire en quelques secondes
#  Aucune entropie, mot du dictionnaire + année
# ─────────────────────────────────────────────────────────
SECRET_KEY = b"pulsar2024"

USERS = {
    "dev":   {"password": "dev123",   "sub": "1", "role": "user",  "email": "dev@pulsar.io"},
    "admin": {"password": "admin123", "sub": "0", "role": "admin", "email": "admin@pulsar.io"},
}

# ─────────────────────────────────────────────────────────
#  Helpers JWT
# ─────────────────────────────────────────────────────────
def b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

def jwt_encode(payload, secret):
    header = {"alg": "HS256", "typ": "JWT"}
    h = b64e(json.dumps(header, separators=(",", ":")).encode())
    p = b64e(json.dumps(payload, separators=(",", ":")).encode())
    sig = hmac.new(secret, f"{h}.{p}".encode(), hashlib.sha256).digest()
    return f"{h}.{p}.{b64e(sig)}"

def jwt_decode(token, secret):
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("invalid format")
    h_b64, p_b64, s_b64 = parts
    header  = json.loads(b64d(h_b64))
    payload = json.loads(b64d(p_b64))

    if header.get("alg") != "HS256":
        raise ValueError("algorithm not allowed")

    expected = b64e(hmac.new(secret, f"{h_b64}.{p_b64}".encode(), hashlib.sha256).digest())
    if not hmac.compare_digest(expected, s_b64):
        raise ValueError("invalid signature")

    if "exp" in payload and int(payload["exp"]) < int(time.time()):
        raise ValueError("token expired")

    return payload

def decode_unsafe(token):
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("invalid format")
    return json.loads(b64d(parts[1]))

def make_token(username):
    u = USERS[username]
    return jwt_encode({
        "sub": u["sub"],
        "username": username,
        "email": u["email"],
        "role": u["role"],
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
    }, SECRET_KEY)

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

# Endpoint d'aide : renvoie le token courant (pour le cracking)
@app.route("/api/token")
def api_token():
    token = get_token()
    if not token:
        return jsonify(ok=False, error="Non authentifié"), 401
    return jsonify(ok=True, token=token)

# ─────────────────────────────────────────────────────────
#  🔴 VULNÉRABLE : la seule "protection" est le secret HS256
#     Si le secret est cracké, TOUT est forgable.
# ─────────────────────────────────────────────────────────
@app.route("/api/admin/vulnerable")
def admin_vulnerable():
    token = get_token()
    if not token:
        return jsonify(ok=False, error="Non authentifié"), 401

    try:
        payload = jwt_decode(token, SECRET_KEY)
    except Exception as e:
        return jsonify(ok=False, error=f"Erreur: {e}"), 401

    if payload.get("role") != "admin":
        return jsonify(ok=False, error="Accès refusé"), 403

    return jsonify(ok=True, data={
        "flag": "SPECTRA{w34k_s3cr3ts_4r3_cr4ck3d}",
        "cluster": {
            "noeuds_actifs": 247,
            "gpu_total": "1 976 × H100",
            "charge_moyenne": "68 %",
            "uptime": "99.997 %",
        },
        "jobs": [
            {"id": "j-8a2f", "nom": "llama3-finetune",    "gpu": 64, "eta": "4h 12m",  "priorite": "haute"},
            {"id": "j-4c9d", "nom": "sdxl-batch-gen",     "gpu": 32, "eta": "1h 48m",  "priorite": "normale"},
            {"id": "j-7e1b", "nom": "whisper-transcribe", "gpu": 16, "eta": "22m",     "priorite": "normale"},
            {"id": "j-2f5a", "nom": "bert-embed-v3",      "gpu": 8,  "eta": "8m",      "priorite": "basse"},
            {"id": "j-9d3c", "nom": "clip-indexer",       "gpu": 4,  "eta": "3m",      "priorite": "basse"},
        ],
        "secrets": {
            "api_master_key": "pulsar_sk_prod_7f4a9c2b8e1d",
            "webhook_signing": "whsec_pulsar_4b8c1d7a",
            "db_password_hint": "pulsar-db-prod-eu-***",
        },
        "logs": [
            "02:14 — job j-8a2f démarré sur 64× H100",
            "02:31 — autoscaling : +12 nœuds ajoutés",
            "03:02 — checkpoint sauvegardé (model-v7)",
            "03:47 — alerte : GPU #042 température élevée",
            "04:11 — job j-4c9d terminé en 1h 48m",
        ],
    })

# ─────────────────────────────────────────────────────────
#  🟢 SÉCURISÉ : secret robuste (256 bits aléatoires)
#     → Crack HS256 impossible
# ─────────────────────────────────────────────────────────
STRONG_SECRET = bytes.fromhex(
    "8f3a9c2b7e1d4f6a8b2c5e9d1f4a7c3b6e8d2f5a9c1b4e7d3f6a8c2b5e9d1f4a"
)  # 32 octets = 256 bits d'entropie

@app.route("/api/admin/secure")
def admin_secure():
    token = get_token()
    if not token:
        return jsonify(ok=False, error="Non authentifié"), 401

    try:
        payload = jwt_decode(token, STRONG_SECRET)
    except Exception as e:
        return jsonify(ok=False, error=f"Bloqué: {e}"), 401

    if payload.get("role") != "admin":
        return jsonify(ok=False, error="Accès refusé"), 403

    return jsonify(ok=True, data={"message": "Accès autorisé — secret robuste"})

if __name__ == "__main__":
    app.run(debug=True, port=5000)