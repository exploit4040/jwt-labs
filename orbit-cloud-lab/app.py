from flask import Flask, request, jsonify, render_template, make_response
import base64, json, hmac, hashlib, time

app = Flask(__name__)
SECRET_KEY = b"orbit-secret-2024"

# ─────────────────────────────────────────────────────────
#  Base de données utilisateurs
# ─────────────────────────────────────────────────────────
USERS = {
    "alice": {"password": "alice123", "sub": "1", "isPremium": False, "plan": "free", "email": "alice@orbit.io"},
    "bob":   {"password": "bob123",   "sub": "2", "isPremium": True,  "plan": "pro",  "email": "bob@orbit.io"},
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

def decode_without_verify(token):
    """Décode le payload SANS vérifier la signature (usage dangereux)."""
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("invalid token format")
    return json.loads(b64d(parts[1]))

def make_token(username):
    u = USERS[username]
    return jwt_encode({
        "sub": u["sub"],
        "username": username,
        "email": u["email"],
        "isPremium": u["isPremium"],
        "plan": u["plan"],
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
        payload = decode_without_verify(token)
    except Exception as e:
        return jsonify(ok=False, error=str(e)), 401
    return jsonify(ok=True, user=payload)

# ─────────────────────────────────────────────────────────
#  🔴 VULNÉRABLE : décode sans vérifier la signature
#  Le simple fait de changer "isPremium" en true suffit
# ─────────────────────────────────────────────────────────
@app.route("/api/premium/vulnerable")
def premium_vulnerable():
    token = get_token()
    if not token:
        return jsonify(ok=False, error="Non authentifié"), 401

    try:
        # ❌ Aucune vérification de signature : on lit juste le payload
        payload = decode_without_verify(token)
    except Exception as e:
        return jsonify(ok=False, error=str(e)), 401

    # ❌ On fait confiance au claim booléen tel quel
    if payload.get("isPremium") is not True:
        return jsonify(ok=False, error="Accès refusé — abonnement Premium requis"), 403

    return jsonify(ok=True, data={
        "flag": "SPECTRA{s1gn4tur3_1s_s4cr3d}",
        "account": {
            "email": payload.get("email"),
            "plan": payload.get("plan", "pro"),
            "isPremium": payload.get("isPremium"),
            "storage": "1 TB",
            "features": ["Analytics avancés", "API illimitée", "Support 24/7", "Export CSV"],
        },
        "stats": {
            "requetes_api_ce_mois": "1 284 502",
            "utilisateurs_actifs": 8421,
            "revenu_mensuel": "48 250 EUR",
            "uptime": "99.98 %",
        },
        "logs": [
            "09:12 — Requête API #4821 traitée en 42 ms",
            "09:47 — Sauvegarde automatique effectuée",
            "10:03 — Nouvel utilisateur inscrit : eve@orbit.io",
            "10:21 — Pic de trafic détecté (1200 req/s)",
            "11:08 — Déploiement réussi v2.4.1",
        ],
    })

# ─────────────────────────────────────────────────────────
#  🟢 SÉCURISÉ : vérifie la signature PUIS recharge depuis la DB
# ─────────────────────────────────────────────────────────
@app.route("/api/premium/secure")
def premium_secure():
    token = get_token()
    if not token:
        return jsonify(ok=False, error="Non authentifié"), 401

    try:
        payload = jwt_decode(token, SECRET_KEY, allowed=("HS256",))
    except Exception as e:
        return jsonify(ok=False, error=f"Bloqué — {e}"), 401

    # ✅ On ignore le claim : on consulte la base
    username = payload.get("username")
    if username not in USERS:
        return jsonify(ok=False, error="Utilisateur inconnu"), 401
    if not USERS[username]["isPremium"]:
        return jsonify(ok=False, error="Accès refusé — abonnement Premium requis"), 403

    return jsonify(ok=True, data={
        "message": "Accès autorisé — vérification signature + base",
        "plan_db": USERS[username]["plan"],
    })

if __name__ == "__main__":
    app.run(debug=True, port=5000)