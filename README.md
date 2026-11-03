# openbudget

Application web **locale** et **déterministe** de suivi de budget personnel.
Elle tourne entièrement sur votre machine (aucune donnée n'est envoyée ailleurs), lit vos
opérations bancaires depuis des fichiers locaux, et peut les récupérer automatiquement via
l'API open banking **[Enable Banking](https://enablebanking.com/)** (DSP2, gratuit pour un
usage individuel non commercial).

> Pas de cloud, pas de compte tiers, pas de télémétrie. Vos relevés restent chez vous.

## Fonctionnalités

- **Vue d'ensemble** : soldes des comptes, dépenses/revenus du mois, reste à vivre.
- **Opérations** : recherche, filtres (montant, moyen de paiement, catégorie, compte),
  nettoyage des libellés, re-catégorisation manuelle.
- **Catégories** : référentiel éditable, règles d'auto-catégorisation.
- **Budgets** : enveloppes par catégorie, suivi de consommation, suggestions basées sur
  l'historique, objectif d'épargne et projection de fin de mois.
- **Abonnements & charges fixes** : détection des prélèvements récurrents, regroupés par type
  (abonnements de services, assurances, factures, frais bancaires, prêts, montants variables),
  avec alertes de hausse et de doublon.
- **Récurrences** : repérage automatique des flux mensuels (salaire, loyer, abonnements…).
- **Synchronisation Enable Banking** : connexion de vos banques et import des transactions à la
  demande, avec import à blanc (dry-run) avant écriture.
- **Authentification** : l'app est protégée par un login / mot de passe (HTTP Basic, mot de
  passe stocké haché en PBKDF2).

L'app est écrite en **Python de la bibliothèque standard** (aucune dépendance pour le serveur
web) côté back, et en **JavaScript vanille** côté front (page unique, graphiques SVG en ligne).

## Démarrage rapide

```bash
git clone <votre-fork>/openbudget.git
cd openbudget
python3 make_demo_data.py        # génère des données de démo 100 % fictives dans ./data
python3 server.py                # démarre sur http://127.0.0.1:8787
```

Identifiants par défaut : **`openbudget` / `openbudget`** (changez-les dans l'onglet « Mon
compte », ou à la première connexion).

Le dépôt est livré avec un **jeu de données de démonstration** (comptes et opérations
entièrement fictifs) pour que l'app soit utilisable immédiatement après le clone.

## Vos vraies données

L'app lit ses données depuis le dossier `./data` par défaut. Vous pouvez :

1. **Remplacer** les fichiers de `./data` par les vôtres (même format, voir ci-dessous), ou
2. **Pointer ailleurs** via la variable d'environnement `OPENBUDGET_DATA` :
   ```bash
   OPENBUDGET_DATA=~/mon-budget/data python3 server.py
   ```

> ⚠️ **Ne versionnez jamais vos vraies données.** Gardez-les hors du dépôt (via
> `OPENBUDGET_DATA` vers un dossier externe, ou en les plaçant dans `private-data/`, déjà
> ignoré par `.gitignore`).

Les secrets utilisateur (clé privée Enable Banking, mot de passe de l'app) sont stockés dans
`~/.openbudget` (modifiable via `OPENBUDGET_HOME`), **jamais** dans le dépôt.

### Format des données

- `data/accounts.json` — `{ "accounts": { "<id>": { "label", "banque", "type", "balance", … } } }`
- `data/operations.jsonl` — une opération JSON par ligne :
  `{ "date": "2026-01-15", "label": "...", "amount": -12.34, "account": "<id>", "categorie": "..." }`
- `data/referentiel-categories.json` — l'arbre des catégories (fourni).
- `data/recurrences.json` — récurrences détectées (généré par l'app / le script de démo).
- `data/budget.json`, `data/regles_auto.json`, `data/merchant_aliases.json` — optionnels,
  créés par l'app au fil de l'usage.

## Enable Banking (open banking)

Le client en ligne de commande `enable_banking.py` gère toute la chaîne. Les secrets vivent
dans `~/.openbudget/enable-banking/` (jamais dans le dépôt).

1. **Générez votre clé** :
   ```bash
   python3 enable_banking.py keygen
   ```
   Crée `~/.openbudget/enable-banking/private_key.pem` et `certificate.pem`.
2. **Créez une application gratuite** sur le
   [Control Panel Enable Banking](https://enablebanking.com/cp/) (plan « individuel non
   commercial ») : uploadez `certificate.pem`, déclarez votre `redirect_url`
   (par défaut `https://localhost:8080/cb`), récupérez l'**Application ID**, puis
   enregistrez-le :
   ```bash
   python3 enable_banking.py config --set-app-id <votre-app-id>
   ```
3. **Autorisez une banque** (adaptez d'abord la liste `EB_TARGETS` dans `server.py` à vos
   banques — `python3 enable_banking.py banks --grep <nom>` donne le nom ASPSP exact) :
   ```bash
   python3 enable_banking.py auth "<Nom banque>"    # validez la SCA côté banque
   python3 enable_banking.py import                 # aperçu à blanc (dry-run)
   python3 enable_banking.py import --apply          # écrit réellement dans operations.jsonl
   ```
   Vous pouvez aussi piloter l'autorisation et la synchro depuis l'onglet « Mon compte » de
   l'app web.

L'import affiche toujours d'abord un **aperçu à blanc** (opérations nouvelles / en doublon)
avant toute écriture.

> Enable Banking impose un `redirect_url` en **HTTPS**. Le client génère un certificat
> auto-signé local pour le catcher ; acceptez l'avertissement du navigateur, ou utilisez le
> mode « coller le code » proposé dans l'app si la redirection échoue.

## Sécurité & vie privée

- L'app n'écoute que sur **`127.0.0.1`** (jamais exposée au réseau).
- Protégée par login / mot de passe (PBKDF2).
- Aucune donnée ne quitte votre machine, sauf les appels que **vous** initiez vers l'API de
  votre banque via Enable Banking.
- `.gitignore` est configuré pour ne jamais versionner données réelles ni secrets.

## Licence

[GPL-3.0](LICENSE). Logiciel libre : utilisez, étudiez, modifiez et partagez.
