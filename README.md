# 🔐 JWT Security Labs

Collection de laboratoires pratiques dédiés à l'exploitation et à la remédiation des vulnérabilités JWT.

Chaque lab est une application Flask autonome qui reproduit une faille réelle, fournit un endpoint vulnérable, un endpoint corrigé, et un write-up complet avec exploitation pas à pas.

---

## 📋 Table des matières

- [Vue d'ensemble](#vue-densemble)
- [Labs inclus](#labs-inclus)
- [Prérequis](#prérequis)
- [Installation](#installation)
- [Lancement d'un lab](#lancement-dun-lab)
- [Structure du dépôt](#structure-du-dépôt)
- [Matrice des vulnérabilités](#matrice-des-vulnérabilités)
- [Avertissement légal](#avertissement-légal)
- [Contact](#contact)

---

## Vue d'ensemble

Ce dépôt regroupe **7 laboratoires JWT** couvrant les failles les plus critiques identifiées par l'OWASP et la communauté pentest. Chaque lab suit la même logique :

1. **Endpoint vulnérable** — implémentation naïve exploitable
2. **Endpoint sécurisé** — implémentation corrigée
3. **Script d'attaque** — exploitation reproductible
4. **Write-up complet** — analyse, exploitation, remédiation

Ces labs sont conçus pour être exécutés **localement** dans un cadre pédagogique.

---

## Labs inclus

| # | Lab | Vulnérabilité | Difficulté | Thème |
|---|-----|---------------|------------|-------|
| 01 | [jwt-none-lab](./jwt-none-lab) | `alg:none` — signature ignorée | Facile | Corporate |
| 02 | [jwt-privilege-lab](./jwt-privilege-lab) | Élévation de privilèges via claims | Facile | Corporate |
| 03 | [orbit-cloud-lab](./orbit-cloud-lab) | Manipulation des claims (signature non vérifiée) | Facile | SaaS |
| 04 | [nova-bank-lab](./nova-bank-lab) | Algorithm Confusion RS256 → HS256 | Difficile | Banking |
| 05 | [vertex-kid-lab](./vertex-kid-lab) | KID Injection (Path Traversal / SQLi) | Difficile | Analytics |
| 06 | [pulsar-labs-lab](./pulsar-labs-lab) | Weak JWT Secrets (cracking HS256) | Moyen | Dev Terminal |
| 07 | [vitalis-health-lab](./vitalis-health-lab) | JKU/X5U Header Injection | Expert | Médical |

---

## Prérequis

- **Python 3.8+**
- **pip**
- **Git**
- Un navigateur web moderne
- (Optionnel) **Hashcat** pour le lab 06
- (Optionnel) **jwt_tool** pour l'exploitation avancée

---

## Installation

```bash
# Cloner le dépôt
git clone https://github.com/exploit4040/jwt-labs.git
cd jwt-labs

# Installer les dépendances
pip install flask cryptography requests
```

Pour certains labs, des dépendances supplémentaires peuvent être requises. Consultez le README de chaque lab.

---

## Lancement d'un lab

Chaque lab est indépendant. Pour en lancer un :

```bash
# Exemple avec le lab 01
cd jwt-none-lab
python app.py
```

Puis ouvrez votre navigateur à l'adresse :

```
http://127.0.0.1:5000
```

### Comptes de test

| Lab | Utilisateur | Administrateur |
|-----|-------------|----------------|
| jwt-none-lab | alice / alice123 | admin / admin123 |
| jwt-privilege-lab | alice / alice123 | admin / admin123 |
| orbit-cloud-lab | marc / marc123 | admin / admin123 |
| nova-bank-lab | alice / alice123 | admin / admin123 |
| vertex-kid-lab | marc / marc123 | admin / admin123 |
| pulsar-labs-lab | dev / dev123 | admin / admin123 |
| vitalis-health-lab | docteur / docteur123 | admin / admin123 |

---

## Structure du dépôt

```
jwt-labs/
├── README.md
├── LICENSE
├── .gitignore
│
├── jwt-none-lab/
│   ├── app.py
│   ├── templates/
│   │   ├── login.html
│   │   └── dashboard.html
│   └── write-ups.md
│
├── jwt-privilege-lab/
│   ├── app.py
│   ├── templates/
│   └── write-ups.md
│
├── orbit-cloud-lab/
│   ├── app.py
│   ├── templates/
│   └── write-ups.md
│
├── nova-bank-lab/
│   ├── app.py
│   ├── attack.py
│   ├── templates/
│   └── write-ups.md
│
├── vertex-kid-lab/
│   ├── app.py
│   ├── templates/
│   └── write-ups.md
│
├── pulsar-labs-lab/
│   ├── app.py
│   ├── crack.py
│   ├── templates/
│   └── write-ups.md
│
└── vitalis-health-lab/
    ├── app.py
    ├── templates/
    └── write-ups.md
```

---

## Matrice des vulnérabilités

| Faille | CWE | OWASP Top 10 | Algorithme concerné |
|--------|-----|--------------|---------------------|
| `alg:none` | CWE-347 | A02:2021 | HMAC / RSA |
| Élévation de privilèges | CWE-269, CWE-639 | A01:2021 | Tous |
| Manipulation des claims | CWE-347 | A02:2021, A01:2021 | Tous |
| Algorithm Confusion | CWE-347, CWE-757 | A02:2021 | RS256 → HS256 |
| KID Injection | CWE-22, CWE-89 | A03:2021 | HMAC |
| Weak Secrets | CWE-521, CWE-326 | A02:2021, A07:2021 | HS256 |
| JKU/X5U Injection | CWE-347, CWE-918 | A02:2021, A10:2021 | RS256 |

---

## Outils recommandés

| Outil | Usage | Lien |
|-------|-------|------|
| jwt.io | Décodage et forge de JWT | https://jwt.io |
| hashcat | Cracking HS256 (mode 16500) | https://hashcat.net |
| jwt_tool | Framework d'exploitation JWT | https://github.com/ticarpi/jwt_tool |
| CyberChef | Manipulation de données | https://gchq.github.io/CyberChef |

---

## Avertissement légal

> ⚠️ **Ce dépôt est destiné exclusivement à des fins éducatives et de recherche en sécurité.**
>
> Toutes les techniques d'exploitation présentées ici ne doivent être utilisées que :
> - Sur des systèmes que vous possédez
> - Sur des systèmes pour lesquels vous disposez d'une autorisation écrite explicite
> - Dans le cadre d'un engagement de pentest légal
>
> L'utilisation de ces techniques sur des systèmes sans autorisation est **illégale** et peut entraîner des poursuites pénales.
>
> L'auteur décline toute responsabilité en cas d'utilisation abusive.

---

## Licence

Ce projet est distribué sous licence MIT. Voir le fichier [LICENSE](./LICENSE) pour plus de détails.

---

## Contact

**SPECTRA MZ** — exploit4040

- GitHub : [@exploit4040](https://github.com/exploit4040)
- Blog : [exploit4040.github.io/MZ](https://exploit4040.github.io/MZ/)

---

## Crédits

Ces labs s'inspirent des travaux de la communauté sécurité :

- [PortSwigger Web Security Academy](https://portswigger.net/web-security/jwt) — JWT attacks
- [OWASP JWT Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [HiitCat/JWT-SecLabs](https://github.com/HiitCat/JWT-SecLabs) — Inspiration pour la structure
- RFC 7515, 7517, 7518, 7519 — Standards JWT

---

*Learn. Break. Fix. Automate. Repeat.*
