from flask import Flask, request, jsonify, render_template, make_response
import base64, json, time, urllib.request
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

app = Flask(__name__)

# ─────────────────────────────────────────────────────────
#  Deux paires de clés RSA
#   - LEGIT_KEY     : la clé officielle du serveur Vitalis
#   - ATTACKER_KEY  : simule la clé que l'attaquant hébergerait
# ─────────────────────────────────────────────────────────
LEGIT_KEY    = rsa.generate_private_key(public_exponent=65537, key_size=2048)
ATTACKER_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)

def public_pem(key):
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

def jwk_from_public_key(key, kid):
    """Construit un JWK (JSON Web Key) minimal depuis une clé publique RSA."""
    pub_numbers = key.public_key().public_numbers()
    def b64u_int(n):
        length = (n.bit_length() + 7) // 8
        return base64.urlsafe_b64encode(n.to_bytes(length, "big")).rstrip(b"=").decode()
    return {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": kid,
        "n": b64u_int(pub_numbers.n),
        "e": b64u_int(pub_numbers.e),
    }

# ─────────────────────────────────────────────────────────
#  Utilisateurs
# ─────────────────────────────────────────────────────────
USERS = {
    "docteur": {"password": "docteur123", "sub": "1", "role": "user",  "email": "docteur@vitalis.io"},
    "admin":   {"password": "admin123",   "sub": "0", "role": "admin", "email": "admin@vitalis.io"},
}

# ─────────────────────────────────────────────────────────
#  Helpers JWT
# ─────────────────────────────────────────────────────────
def b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

def sign_rs256(payload, private_key, kid="vitalis-2024", jku=None):
    header = {"alg": "RS256", "typ": "JWT", "kid": kid}
    if jku:
        header["jku"] = jku
    h = b64e(json.dumps(header, separators=(",", ":")).encode())
    p = b64e(json.dumps(payload, separators=(",", ":")).encode())
    sig = private_key.sign(f"{h}.{p}".encode(), padding.PKCS1v15(), hashes.SHA256())
    return f"{h}.{p}.{b64e(sig)}"

def verify_rs256(token, public_key):
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("invalid format")
    h_b64, p_b64, s_b64 = parts
    header = json.loads(b64d(h_b64))
    payload = json.loads(b64d(p_b64))

    if header.get("alg") != "RS256":
        raise ValueError("algorithm not allowed")

    public_key.verify(b64d(s_b64), f"{h_b64}.{p_b64}".encode(),
                      padding.PKCS1v15(), hashes.SHA256())

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
    return sign_rs256({
        "sub": u["sub"],
        "username": username,
        "email": u["email"],
        "role": u["role"],
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
    }, LEGIT_KEY)

def get_token():
    return request.cookies.get("token") or \
           request.headers.get("Authorization", "").replace("Bearer ", "").strip()

def rsa_from_jwk(jwk):
    """Reconstruit une clé publique RSA depuis un JWK."""
    n = int.from_bytes(b64d(jwk["n"]), "big")
    e = int.from_bytes(b64d(jwk["e"]), "big")
    return rsa.RSAPublicNumbers(e, n).public_key()

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
#  JWKS légitime + JWKS "attaquant" (simulé)
# ─────────────────────────────────────────────────────────
@app.route("/api/jwks.json")
def legit_jwks():
    return jsonify({"keys": [jwk_from_public_key(LEGIT_KEY, "vitalis-2024")]})

@app.route("/api/attacker-jwks.json")
def attacker_jwks():
    # Simule un JWKS hébergé par l'attaquant sur son propre serveur
    return jsonify({"keys": [jwk_from_public_key(ATTACKER_KEY, "attacker-key")]})

@app.route("/api/public-key")
def public_key_endpoint():
    return public_pem(LEGIT_KEY), 200, {"Content-Type": "text/plain"}

# Endpoint utilitaire : forger un token admin signé avec la clé "attaquant"
# + jku pointant vers /api/attacker-jwks.json
@app.route("/api/forge-attacker-token", methods=["POST"])
def forge_attacker_token():
    data = request.get_json() or {}
    role = data.get("role", "admin")
    username = data.get("username", "docteur")

    payload = {
        "sub": "0",
        "username": username,
        "email": f"{username}@vitalis.io",
        "role": role,
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
    }
    jku = request.host_url.rstrip("/") + "/api/attacker-jwks.json"
    token = sign_rs256(payload, ATTACKER_KEY, kid="attacker-key", jku=jku)

    return jsonify(ok=True, token=token, jku=jku, payload=payload)

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
#  🔴 VULNÉRABLE : lit "jku" du header et télécharge la clé
#     à l'URL fournie par le client
# ─────────────────────────────────────────────────────────
@app.route("/api/admin/vulnerable")
def admin_vulnerable():
    token = get_token()
    if not token:
        return jsonify(ok=False, error="Non authentifié"), 401

    try:
        h_b64 = token.split(".")[0]
        header = json.loads(b64d(h_b64))
        jku = header.get("jku")

        if jku:
            # ❌ Faille : on suit l'URL fournie par le client
            with urllib.request.urlopen(jku, timeout=3) as resp:
                jwks = json.loads(resp.read().decode())
            key = rsa_from_jwk(jwks["keys"][0])
        else:
            key = LEGIT_KEY.public_key()

        payload = verify_rs256(token, key)
    except Exception as e:
        return jsonify(ok=False, error=f"Erreur: {e}"), 401

    if payload.get("role") != "admin":
        return jsonify(ok=False, error="Accès refusé"), 403

    return jsonify(ok=True, data={
        "flag": "SPECTRA{jku_h34d3r_1nj3ct10n}",
        "patients": [
            {"id": "P-4821", "nom": "Martin L.",   "age": 62, "statut": "stable",   "service": "Cardiologie"},
            {"id": "P-4822", "nom": "Dubois A.",   "age": 45, "statut": "critique", "service": "Réanimation"},
            {"id": "P-4823", "nom": "Bernard S.",  "age": 71, "statut": "stable",   "service": "Oncologie"},
            {"id": "P-4824", "nom": "Petit J.",    "age": 34, "statut": "sortie",   "service": "Chirurgie"},
            {"id": "P-4825", "nom": "Roux M.",     "age": 58, "statut": "stable",   "service": "Neurologie"},
        ],
        "stats": {
            "patients_actifs": 482,
            "lits_occupes": "312 / 350",
            "urgences_24h": 47,
            "blocs_operatoires": "8 / 10",
        },
        "confidentiel": {
            "note_direction": "Fusion avec Clinique du Parc validée Q1 2025",
            "budget_r_and_d": "2 480 000 EUR",
        },
    })

# ─────────────────────────────────────────────────────────
#  🟢 SÉCURISÉ : ignore le jku, utilise uniquement la clé légitime
# ─────────────────────────────────────────────────────────
@app.route("/api/admin/secure")
def admin_secure():
    token = get_token()
    if not token:
        return jsonify(ok=False, error="Non authentifié"), 401

    try:
        #  On utilise toujours la clé fixe, jamais celle du jku
        payload = verify_rs256(token, LEGIT_KEY.public_key())
    except Exception as e:
        return jsonify(ok=False, error=f"Bloqué: {e}"), 401

    if payload.get("role") != "admin":
        return jsonify(ok=False, error="Accès refusé"), 403

    return jsonify(ok=True, data={"message": "Accès autorisé — jku ignoré"})

if __name__ == "__main__":
    app.run(debug=True, port=5000)