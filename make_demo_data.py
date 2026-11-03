#!/usr/bin/env python3
"""Génère des données de DÉMO 100 % fictives dans ./data pour qu'openbudget tourne dès le clone.
Remplace ces fichiers par tes vraies données (ou connecte tes banques via Enable Banking)."""
import json
import os
import random
from datetime import date, timedelta

random.seed(42)
DATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')
os.makedirs(DATA, exist_ok=True)
TODAY = date.today()
START = TODAY - timedelta(days=180)

ACCOUNTS = {
    'compte_courant': {'label': 'Compte courant', 'banque': 'Banque Démo', 'type': 'courant',
                       'actif': True, 'dashboard': True, 'balance': 2450.80, 'balance_date': TODAY.isoformat()},
    'compte_joint': {'label': 'Compte joint', 'banque': 'Banque Démo', 'type': 'courant',
                     'actif': True, 'dashboard': True, 'balance': 1320.15, 'balance_date': TODAY.isoformat()},
    'livret': {'label': 'Livret', 'banque': 'Banque Démo', 'type': 'epargne',
               'actif': True, 'dashboard': False, 'balance': 8000.00, 'balance_date': TODAY.isoformat()},
}

# (libellé, catégorie, montant min, max, compte, nb/mois environ)
MARCHANDS = [
    ('Supermarché Démo', 'alimentation', 15, 90, 'compte_courant', 10),
    ('Resto Démo', 'restauration', 12, 45, 'compte_courant', 5),
    ('Boulangerie Démo', 'alimentation', 2, 12, 'compte_courant', 6),
    ('Boutique Démo', 'shopping', 20, 150, 'compte_courant', 3),
    ('Station Démo', 'auto_carburant', 40, 80, 'compte_courant', 3),
    ('Cinéma Démo', 'loisirs', 10, 30, 'compte_courant', 2),
    ('Pharmacie Démo', 'sante', 8, 40, 'compte_joint', 2),
]
# Abonnements / charges fixes (libellé, catégorie, montant, jour, compte)
RECURRENTS = [
    ('Salaire', 'salaire', +2600.00, 28, 'compte_courant'),
    ('Loyer', 'immobilier_autre', -780.00, 5, 'compte_joint'),
    ('Netflix', 'abonnements', -13.49, 15, 'compte_courant'),
    ('Spotify', 'abonnements', -11.99, 8, 'compte_courant'),
    ('Opérateur Mobile', 'telecom', -19.99, 3, 'compte_courant'),
    ('Fournisseur Énergie', 'energie', -95.00, 10, 'compte_joint'),
    ('Assurance Habitation', 'assurance_habitation', -28.50, 6, 'compte_joint'),
    ('Assurance Auto', 'auto_assurance', -42.00, 6, 'compte_courant'),
    ('Salle de sport', 'loisirs', -29.90, 2, 'compte_courant'),
    ('Frais de tenue de compte', 'frais_bancaires', -3.00, 4, 'compte_courant'),
]

ops = []


def daterange_months(start, end):
    d = start.replace(day=1)
    while d <= end:
        yield d.year, d.month
        d = (d.replace(day=28) + timedelta(days=7)).replace(day=1)


# Opérations variables
d = START
while d <= TODAY:
    for lbl, cat, lo, hi, acc, per_month in MARCHANDS:
        if random.random() < per_month / 30.0:
            amt = -round(random.uniform(lo, hi), 2)
            ops.append({'date': d.isoformat(), 'label': lbl, 'amount': amt,
                        'account': acc, 'categorie': cat, 'source': 'demo'})
    d += timedelta(days=1)

# Récurrences (une occurrence par mois, au jour typique) + objet recurrences.json
import calendar
recurrences = []
for lbl, cat, amt, day, acc in RECURRENTS:
    occ = 0
    first = last = None
    for y, m in daterange_months(START, TODAY):
        dd = date(y, m, min(day, calendar.monthrange(y, m)[1]))
        if START <= dd <= TODAY:
            ops.append({'date': dd.isoformat(), 'label': lbl, 'amount': amt,
                        'account': acc, 'categorie': cat, 'source': 'demo'})
            occ += 1
            first = first or dd.isoformat()
            last = dd.isoformat()
    recurrences.append({'account': acc, 'creditor': lbl, 'categorie': cat,
                        'direction': 'credit' if amt > 0 else 'debit', 'frequence': 'mensuel',
                        'amount': amt, 'typical_day': day, 'occurrences': occ,
                        'first_date': first, 'last_date': last, 'active': True, 'sample_label': lbl})

ops.sort(key=lambda o: o['date'])
with open(os.path.join(DATA, 'operations.jsonl'), 'w', encoding='utf-8') as f:
    for o in ops:
        f.write(json.dumps(o, ensure_ascii=False) + '\n')
with open(os.path.join(DATA, 'accounts.json'), 'w', encoding='utf-8') as f:
    json.dump({'accounts': ACCOUNTS}, f, indent=2, ensure_ascii=False)
with open(os.path.join(DATA, 'recurrences.json'), 'w', encoding='utf-8') as f:
    json.dump({'_stats': {'total': len(recurrences), 'actives': len(recurrences)},
               'recurrences': recurrences}, f, indent=2, ensure_ascii=False)

print(f'{len(ops)} opérations de démo, {len(recurrences)} récurrences, {len(ACCOUNTS)} comptes → {DATA}')
