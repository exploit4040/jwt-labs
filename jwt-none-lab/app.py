from flask import Flask, request, jsonify, render_template, make_response
import base64, json, hmac, hashlib, time

app = Flask(__name__)
SECRET_KEY = b"super-secret-key"

USERS = {
    "alice": {"password": "alice123", "role": "user",  "sub": "1"},
    "admin": {"password": "admin123", "role": "admin", "sub": "0"},
}

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
    payload = {
        "sub": u["sub"],
        "username": username,
        "role": u["role"],
        "exp": int(time.time()) + 3600,
    }
    return jwt_encode(payload, SECRET_KEY)

@app.route("/")
def home():
    return render_template("login.html")

@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")

@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json() or {}
    username = data.get("username", "")
    password = data.get("password", "")
    if username in USERS and USERS[username]["password"] == password:
        token = make_token(username)
        resp = make_response(jsonify(ok=True, redirect="/dashboard"))
        resp.set_cookie("token", token, httponly=False)
        return resp
    return jsonify(ok=False, error="Identifiants incorrects"), 401

# ✅ CORRIGÉ : ne bloque plus sur alg:none
@app.route("/api/me")
def api_me():
    token = request.cookies.get("token") or \
            request.headers.get("Authorization", "").replace("Bearer ", "")
    if not token:
        return jsonify(ok=False, error="Non authentifié"), 401
    try:
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("invalid token format")
        payload = json.loads(b64d(parts[1]))
    except Exception as e:
        return jsonify(ok=False, error=str(e)), 401
    return jsonify(ok=True, user=payload)

@app.route("/api/admin/data")
def admin_data_vuln():
    token = request.cookies.get("token") or \
            request.headers.get("Authorization", "").replace("Bearer ", "")
    if not token:
        return jsonify(ok=False, error="Non authentifié"), 401
    try:
        parts = token.split(".")
        header  = json.loads(b64d(parts[0]))
        payload = json.loads(b64d(parts[1]))
        alg = header.get("alg")
        if alg != "none":
            jwt_decode(token, SECRET_KEY, allowed=(alg,), check_exp=False)
    except Exception as e:
        return jsonify(ok=False, error=str(e)), 401

    if payload.get("role") != "admin":
        return jsonify(ok=False, error="Accès refusé"), 403

    return jsonify(ok=True, data={
        "flag": "SPECTRA{n0n3_4lg_1s_4_w34p0n}",
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

@app.route("/api/admin/secure")
def admin_data_secure():
    token = request.cookies.get("token") or \
            request.headers.get("Authorization", "").replace("Bearer ", "")
    if not token:
        return jsonify(ok=False, error="Non authentifié"), 401
    try:
        payload = jwt_decode(token, SECRET_KEY, allowed=("HS256",))
    except Exception as e:
        return jsonify(ok=False, error=f"Bloqué: {e}"), 401

    if payload.get("role") != "admin":
        return jsonify(ok=False, error="Accès refusé"), 403

    return jsonify(ok=True, data={"message": "Accès autorisé"})

if __name__ == "__main__":
    app.run(debug=True, port=5000)