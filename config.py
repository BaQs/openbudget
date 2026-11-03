"""Chemins et configuration d'openbudget.

Données : ./data (ou le dossier pointé par $OPENBUDGET_DATA).
Config/secrets utilisateur : ~/.openbudget (ou $OPENBUDGET_HOME) — clé privée Enable, mot de
passe de l'app… jamais versionnés.
"""
import os

ROOT = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.environ.get('OPENBUDGET_DATA', os.path.join(ROOT, 'data'))
HOME = os.environ.get('OPENBUDGET_HOME', os.path.expanduser('~/.openbudget'))

OPERATIONS_FILE = os.path.join(DATA_DIR, 'operations.jsonl')
ACCOUNTS_FILE = os.path.join(DATA_DIR, 'accounts.json')
RECURRENCES_FILE = os.path.join(DATA_DIR, 'recurrences.json')
REFERENTIEL_FILE = os.path.join(DATA_DIR, 'referentiel-categories.json')
REGLES_FILE = os.path.join(DATA_DIR, 'regles_auto.json')
BUDGET_FILE = os.path.join(DATA_DIR, 'budget.json')
MERCHANT_ALIASES_FILE = os.path.join(DATA_DIR, 'merchant_aliases.json')
ACCOUNT_MAPS_FILE = os.path.join(DATA_DIR, 'account_maps.json')

ENABLE_DIR = os.path.join(HOME, 'enable-banking')
AUTH_FILE = os.path.join(HOME, 'webapp.json')

# Catégories exclues des « dépenses réelles » / du reste à vivre (flux non consommés).
EXCLUDED_CATS = {'pret_immobilier', 'pret_auto', 'pret_conso',
                 'virements_internes', 'epargne', 'placements', 'especes'}
