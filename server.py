#!/usr/bin/env python3
"""
openbudget — app web LOCALE (déterministe, hors-ligne, 127.0.0.1).

Affiche les comptes, opérations, catégories et récurrences de openbudget, et synchronise à la
demande via Enable Banking (si connecté : `pull` + `import --apply` par session autorisée —
aucune SCA tant que le consentement est valide).

Rien n'est exposé au réseau : écoute sur 127.0.0.1 uniquement. Aucune dépendance (stdlib).
Les données viennent des fichiers existants de openbudget ; la page ne fait que les lire.

Lancement :
    python3 webapp/server.py            # http://127.0.0.1:8787
    python3 webapp/server.py --port 9000
"""
import argparse
import base64
import calendar
import datetime as dt
import hashlib
import hmac
import json
import os
import re
import secrets
import subprocess
import sys
from collections import defaultdict
from datetime import date
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import config

HERE = config.ROOT
BANQUE_DIR = config.DATA_DIR
OPERATIONS_FILE = config.OPERATIONS_FILE
ACCOUNTS_FILE = config.ACCOUNTS_FILE
RECURRENCES_FILE = config.RECURRENCES_FILE
REGLES_FILE = config.REGLES_FILE
REFERENTIEL_FILE = config.REFERENTIEL_FILE
BUDGET_FILE = config.BUDGET_FILE
INDEX_HTML = os.path.join(HERE, 'index.html')

# Enveloppes de budget par défaut (exemples génériques, modifiables dans l'app).
DEFAULT_BUDGET = {
    'enveloppes': [
        {'key': 'courses', 'label': '🛒 Courses', 'categories': ['alimentation'], 'plafond': 800},
        {'key': 'resto', 'label': '🍽️ Restauration', 'categories': ['restauration'], 'plafond': 400},
        {'key': 'shopping', 'label': '🛍️ Shopping', 'categories': ['shopping'], 'plafond': 300},
        {'key': 'loisirs', 'label': '🎉 Loisirs', 'categories': ['loisirs'], 'plafond': 300},
        {'key': 'maison', 'label': '🏠 Maison (énergie, télécom, courant)',
         'categories': ['energie', 'telecom', 'vie_courante'], 'plafond': 600},
        {'key': 'enfants', 'label': '👨‍👩‍👧 Enfants', 'categories': ['enfants', 'famille'], 'plafond': 400},
        {'key': 'voitures', 'label': '🚗 Voitures',
         'categories': ['auto_assurance', 'auto_carburant', 'auto_entretien', 'auto_parking', 'auto_leasing'], 'plafond': 400},
        {'key': 'sante', 'label': '❤️ Santé', 'categories': ['sante'], 'plafond': 150},
    ]
}
# Catégories exclues du calcul « reste à vivre » et des abonnements (flux non consommés).
RAV_EXCLUDE = {'virements_internes', 'especes', 'epargne', 'placements'}

EB_CONFIG = os.path.join(config.ENABLE_DIR, 'config.json')
EB_SESSIONS = os.path.join(config.ENABLE_DIR, 'sessions.json')

# Si accounts.json nomme un compte autrement que la clé d'opération, mapper ici ops→registre.
OPS_KEY_ALIAS = {}

EXCLUDED_CATS = config.EXCLUDED_CATS

_ops_cache = {'mtime': None, 'data': None}

AUTH_FILE = config.AUTH_FILE
AUTH_DEFAULT_USER = 'openbudget'
AUTH_DEFAULT_PASSWORD = 'openbudget'   # défaut, à changer : server.py --set-password <mdp>
_auth_accepted = None            # dernier en-tête Authorization validé (évite de re-hacher à chaque requête)


# ---------------------------------------------------------------- chargement données

def load_json(path, default):
    try:
        with open(path, encoding='utf-8') as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


# ---------------------------------------------------------------- authentification (Basic)

def _hash_pw(password, salt_hex):
    return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), bytes.fromhex(salt_hex), 120000).hex()


def write_auth(user, password):
    salt = secrets.token_hex(16)
    data = {'user': user, 'salt': salt, 'hash': _hash_pw(password, salt)}
    os.makedirs(os.path.dirname(AUTH_FILE), exist_ok=True)
    with open(AUTH_FILE, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)
    os.chmod(AUTH_FILE, 0o600)
    return data


def load_auth(announce=False):
    data = load_json(AUTH_FILE, None)
    if not data or 'hash' not in data:
        data = write_auth(AUTH_DEFAULT_USER, AUTH_DEFAULT_PASSWORD)
        if announce:
            print(f"⚠️  Identifiants web créés par défaut — login « {data['user']} », "
                  f"mot de passe « {AUTH_DEFAULT_PASSWORD} ». À changer : "
                  "python3 webapp/server.py --set-password <nouveau>")
    return data


def check_auth(header):
    global _auth_accepted
    if not header or not header.startswith('Basic '):
        return False
    if _auth_accepted is not None and hmac.compare_digest(header, _auth_accepted):
        return True
    try:
        user, _, pw = base64.b64decode(header[6:]).decode('utf-8').partition(':')
    except Exception:  # noqa: BLE001
        return False
    a = load_auth()
    ok = (hmac.compare_digest(user, a['user'])
          and hmac.compare_digest(_hash_pw(pw, a['salt']), a['hash']))
    if ok:
        _auth_accepted = header
    return ok


def load_ops():
    """Opérations (cache invalidé par mtime)."""
    try:
        mtime = os.path.getmtime(OPERATIONS_FILE)
    except OSError:
        return []
    if _ops_cache['mtime'] == mtime and _ops_cache['data'] is not None:
        return _ops_cache['data']
    ops = []
    with open(OPERATIONS_FILE, encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    ops.append(json.loads(line))
                except ValueError:
                    pass
    ops.sort(key=lambda o: o.get('date', ''), reverse=True)
    _ops_cache['data'] = ops          # data d'abord : un lecteur concurrent ne voit jamais
    _ops_cache['mtime'] = mtime       # un mtime à jour avec des données encore None
    return ops


def _op_id(o):
    """Identifiant stable d'une opération (pour la cibler depuis l'app)."""
    key = f"{o.get('date')}|{o.get('amount')}|{o.get('label')}|{o.get('account')}|{o.get('source')}"
    return hashlib.sha1(key.encode('utf-8')).hexdigest()[:12]


def _load_ops_raw():
    """Opérations dans l'ordre du fichier (pour réécriture ; distinct du cache trié)."""
    ops = []
    with open(OPERATIONS_FILE, encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line:
                ops.append(json.loads(line))
    return ops


def _save_ops_raw(ops):
    tmp = OPERATIONS_FILE + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        for o in ops:
            f.write(json.dumps(o, ensure_ascii=False) + '\n')
    os.replace(tmp, OPERATIONS_FILE)
    _ops_cache['mtime'] = None


MERCHANT_ALIASES = {
    'CARREFOUR': 'Carrefour', 'INTERMARCHE': 'Intermarché', 'LECLERC': 'Leclerc', 'AUCHAN': 'Auchan',
    'LIDL': 'Lidl', 'MONOPRIX': 'Monoprix', 'FRANPRIX': 'Franprix', 'PICARD': 'Picard',
    'AMAZON': 'Amazon', 'AMZN': 'Amazon', 'NETFLIX': 'Netflix', 'SPOTIFY': 'Spotify', 'DISNEY': 'Disney+',
    'TESLA': 'Tesla', 'APPLE': 'Apple', 'UBER': 'Uber', 'DELIVEROO': 'Deliveroo', 'PAYPAL': 'PayPal',
    'SNCF': 'SNCF', 'FNAC': 'Fnac', 'DARTY': 'Darty', 'BOULANGER': 'Boulanger', 'DECATHLON': 'Decathlon',
    'IKEA': 'Ikea', 'LEROY MERLIN': 'Leroy Merlin', 'CASTORAMA': 'Castorama', 'ZARA': 'Zara',
    'TOTALENERGIES': 'TotalEnergies', 'EDF': 'EDF', 'ENGIE': 'Engie', 'VEOLIA': 'Veolia',
    'FREE MOBILE': 'Free Mobile', 'FREE ': 'Free', 'ORANGE': 'Orange', 'BOUYGUES': 'Bouygues', 'SFR': 'SFR',
    'YAHOO': 'Yahoo', 'GOOGLE': 'Google', 'MICROSOFT': 'Microsoft', 'OPENAI': 'OpenAI', 'ANTHROPIC': 'Anthropic',
    'NESPRESSO': 'Nespresso', 'STARBUCKS': 'Starbucks',
}


def _merchant_aliases():
    """Alias marchands génériques (commités) fusionnés avec des alias PERSONNELS hors dépôt
    (data/merchant_aliases.json) — p. ex. {"MON FOURNISSEUR": "Mon Fournisseur"}. Non versionné."""
    merged = dict(MERCHANT_ALIASES)
    merged.update(load_json(config.MERCHANT_ALIASES_FILE, {}) or {})
    return merged


_MERCHANTS = _merchant_aliases()


def _clean_label(label):
    """Transforme un libellé bancaire brut en nom lisible (marchand ou bénéficiaire)."""
    s = label or ''
    s = re.sub(r'^CARTE\s+X?\d+\s+\d{2}/\d{2}\s+', '', s)
    m = re.match(r'PRELEVEMENT EUROPEEN\s+\d+\s+DE:\s*(.+?)(?:\s+ID:|\s+MOTIF:|\s+REF:|$)', s)
    if m:
        s = m.group(1)
    m = re.search(r'/DE\s+(.+?)(?:\s+/MOTIF|\s+/REF|$)', s)
    if m:
        s = m.group(1)
    m = re.search(r'POUR:\s*(.+?)(?:\s+\d{2}\s+\d{2}\b|\s+BQ\b|\s+REF:|$)', s)
    if m:
        s = m.group(1)
    m = re.search(r'\bDE:\s*(.+?)(?:\s+MOTIF:|\s+REF:|\s+ID:|\s+/|$)', s)
    if m:
        s = m.group(1)
    s = re.sub(r'^(?:\d+\s+)?VIR(?:EMENT)?\s+(?:SEPA\s+|EUROPEEN\s+|INSTANTANE\s+)?(?:RECU|EMIS)?\s*(?:DE\s+)?', '', s)
    s = re.sub(r'\s+\d[\d .,]*\s*EUR\b.*', '', s)
    s = re.sub(r'\s+COMMERCE ELECTRONIQUE\b.*', '', s, flags=re.I)
    s = re.sub(r'\s+CB\*?\d+.*', '', s)
    s = re.sub(r'\s+\d{2}/\d{2}/\d{2,4}.*', '', s)
    s = re.sub(r'\s{2,}', ' ', s).strip(' -')
    up = s.upper()
    for pat, nice in _MERCHANTS.items():
        if pat in up:
            return nice
    if s and s.isupper() and len(s) > 3:
        s = s.title()
    return s or (label or '')


def accounts_registry():
    return (load_json(ACCOUNTS_FILE, {}) or {}).get('accounts', {})


def account_balance(info):
    for amt, dkey in (('balance', 'balance_date'), ('solde', 'date_solde'),
                      ('dernierSolde', 'dernierSoldeDate')):
        if info.get(amt) is not None:
            return info[amt], info.get(dkey)
    return None, None


def label_for(op_account, reg):
    key = OPS_KEY_ALIAS.get(op_account, op_account)
    info = reg.get(key) or reg.get(op_account) or {}
    return info.get('label') or op_account


def bank_for(op_account, reg):
    key = OPS_KEY_ALIAS.get(op_account, op_account)
    info = reg.get(key) or reg.get(op_account) or {}
    return info.get('banque') or '—'


def enable_connected():
    cfg = load_json(EB_CONFIG, {})
    sess = load_json(EB_SESSIONS, {})
    has_sessions = any(k for k in sess if not k.startswith('_'))
    return bool(cfg.get('app_id')) and has_sessions


# ---------------------------------------------------------------- endpoints

def api_overview():
    reg = accounts_registry()
    ops = load_ops()
    cards, total = [], 0.0
    for key, info in reg.items():
        if not info.get('dashboard') or not info.get('actif'):
            continue
        bal, bdate = account_balance(info)
        if bal is None:
            continue
        total += bal
        cards.append({'key': key, 'label': info.get('label', key),
                      'banque': info.get('banque', '—'), 'type': info.get('type', ''),
                      'balance': round(bal, 2), 'balance_date': bdate})
    cards.sort(key=lambda c: c['balance'], reverse=True)

    months = sorted({o['date'][:7] for o in ops if o.get('date')}, reverse=True)
    op_accounts = sorted({o['account'] for o in ops if o.get('account')})
    op_accounts = [{'key': k, 'label': label_for(k, reg)} for k in op_accounts]
    categories = sorted({o.get('categorie') for o in ops if o.get('categorie')})
    payment_methods = sorted({o.get('payment_method') for o in ops if o.get('payment_method')})

    return {
        'accounts': cards,
        'total_courant': round(total, 2),
        'n_ops': len(ops),
        'last_op_date': ops[0]['date'] if ops else None,
        'months': months,
        'op_accounts': op_accounts,
        'categories': categories,
        'payment_methods': payment_methods,
        'enable_connected': enable_connected(),
        'generated_at': date.today().isoformat(),
    }


def api_operations(qs):
    reg = accounts_registry()
    ops = load_ops()
    account = (qs.get('account', [''])[0] or '').strip()
    categorie = (qs.get('categorie', [''])[0] or '').strip()
    month = (qs.get('month', [''])[0] or '').strip()
    direction = (qs.get('direction', [''])[0] or '').strip()
    q = (qs.get('q', [''])[0] or '').strip().lower()
    pm = (qs.get('payment_method', [''])[0] or '').strip().lower()
    limit = min(int(qs.get('limit', ['100'])[0] or 100), 1000)
    offset = int(qs.get('offset', ['0'])[0] or 0)

    def _num(name):
        try:
            return float(qs.get(name, [''])[0] or 0) or None
        except ValueError:
            return None
    amt_min, amt_max = _num('amount_min'), _num('amount_max')

    def keep(o):
        if account and o.get('account') != account:
            return False
        if categorie == '__none__':
            if (o.get('categorie') or '') not in ('', '(sans)', 'non_categorise'):
                return False
        elif categorie and o.get('categorie') != categorie:
            return False
        if month and not (o.get('date', '').startswith(month)):
            return False
        if direction == 'credit' and o.get('amount', 0) <= 0:
            return False
        if direction == 'debit' and o.get('amount', 0) >= 0:
            return False
        if q and q not in o.get('label', '').lower():
            return False
        if pm and pm not in (o.get('payment_method', '') or '').lower():
            return False
        a = abs(o.get('amount', 0))
        if amt_min and a < amt_min:
            return False
        if amt_max and a > amt_max:
            return False
        return True

    filtered = [o for o in ops if keep(o)]
    total = len(filtered)
    page = filtered[offset:offset + limit]
    rows = [{
        'id': _op_id(o),
        'date': o.get('date'),
        'label': o.get('label', ''),
        'label_clean': _clean_label(o.get('label', '')),
        'amount': round(o.get('amount', 0), 2),
        'account': o.get('account'),
        'account_label': label_for(o.get('account'), reg),
        'categorie': o.get('categorie', ''),
        'estimee': bool(o.get('date_estimee')),
    } for o in page]
    somme = round(sum(o.get('amount', 0) for o in filtered), 2)
    return {'total': total, 'offset': offset, 'limit': limit, 'rows': rows, 'somme': somme}


def api_categories(qs):
    """Dépenses réelles par catégorie (hors prêts/virements internes/épargne/placements).
    `all=1` inclut tout. Les flux exclus sont renvoyés à part (interne_total)."""
    ops = load_ops()
    month = (qs.get('month', [''])[0] or '').strip()
    include_all = qs.get('all', ['0'])[0] in ('1', 'true')
    depenses, credits_total, debits_total, interne_total = defaultdict(float), 0.0, 0.0, 0.0
    for o in ops:
        if month and not o.get('date', '').startswith(month):
            continue
        amt = o.get('amount', 0)
        cat = o.get('categorie') or '(sans)'
        if amt >= 0:
            credits_total += amt
            continue
        debits_total += amt
        if not include_all and cat in EXCLUDED_CATS:
            interne_total += -amt
        else:
            depenses[cat] += -amt
    cats = sorted(({'categorie': c, 'montant': round(v, 2)} for c, v in depenses.items()),
                  key=lambda x: x['montant'], reverse=True)
    return {'month': month, 'categories': cats,
            'credits': round(credits_total, 2), 'debits': round(debits_total, 2),
            'net': round(credits_total + debits_total, 2),
            'depenses_reelles': round(sum(c['montant'] for c in cats), 2),
            'interne_total': round(interne_total, 2)}


def api_categories_ref():
    ref = load_json(REFERENTIEL_FILE, {})
    cats = ref.get('categories', {}) or {}
    groupes = ref.get('groupes', {}) or {}
    bucket = {}
    for slug, info in cats.items():
        g = info.get('groupe', 'autre')
        bucket.setdefault(g, []).append({'slug': slug, 'label': info.get('label', slug)})
    groups = [{'groupe': g, 'label': groupes.get(g, g),
               'items': sorted(v, key=lambda x: x['label'])} for g, v in bucket.items()]
    groups.sort(key=lambda x: x['label'])
    return {'groups': groups}


def _add_rule(pattern, categorie):
    data = load_json(REGLES_FILE, {'rules': []})
    data.setdefault('rules', [])
    pu = pattern.strip().upper()
    for r in data['rules']:
        if r.get('pattern', '').upper() == pu:
            r['categorie'] = categorie
            break
    else:
        data['rules'].append({'pattern': pu, 'categorie': categorie,
                              'source': 'app openbudget — ' + dt.date.today().isoformat()})
    data['_updated'] = dt.datetime.now().isoformat()
    with open(REGLES_FILE, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


_RECAT_BACKUP = OPERATIONS_FILE + '.bak-recat'


def api_recategorize(body):
    cat = ((body or {}).get('categorie') or '').strip()
    op_id = (body or {}).get('id')
    make_rule = bool((body or {}).get('make_rule'))
    pattern = ((body or {}).get('pattern') or '').strip()
    if not cat:
        return {'ok': False, 'error': 'catégorie manquante'}
    ops = _load_ops_raw()
    changed = 0
    if make_rule and pattern:
        pu = pattern.upper()
        for o in ops:
            if pu in (o.get('label', '') or '').upper() and o.get('categorie') != cat:
                o['categorie'] = cat
                changed += 1
        _add_rule(pattern, cat)
    else:
        if not op_id:
            return {'ok': False, 'error': 'opération non identifiée'}
        for o in ops:
            if _op_id(o) == op_id and o.get('categorie') != cat:
                o['categorie'] = cat
                changed += 1
    if changed or (make_rule and pattern):
        try:
            import shutil
            shutil.copy2(OPERATIONS_FILE, _RECAT_BACKUP)
        except OSError:
            pass
        _save_ops_raw(ops)
    return {'ok': True, 'changed': changed, 'rule_added': bool(make_rule and pattern)}


def _load_budget():
    b = load_json(BUDGET_FILE, None)
    return b if b else dict(DEFAULT_BUDGET)


def api_budgets():
    return _load_budget()


def api_budgets_save(body):
    b = body or {}
    cur = _load_budget()
    if b.get('enveloppes'):          # ne pas écraser avec une liste vide
        cur['enveloppes'] = b['enveloppes']
    if 'objectif_epargne' in b:
        cur['objectif_epargne'] = b['objectif_epargne']
    with open(BUDGET_FILE, 'w', encoding='utf-8') as f:
        json.dump(cur, f, indent=2, ensure_ascii=False)
    return {'ok': True}


def _month_fraction(month):
    y, m = map(int, month.split('-'))
    dim = calendar.monthrange(y, m)[1]
    today = dt.date.today()
    if (y, m) == (today.year, today.month):
        return max(today.day / dim, 0.03)
    return 1.0 if (y, m) < (today.year, today.month) else 0.03


def _recurrences_fixes():
    """(revenus_fixes_mensuels, charges_fixes_mensuelles) depuis recurrences.json."""
    rec = (load_json(RECURRENCES_FILE, {}) or {}).get('recurrences', [])
    rev = sum(r['amount'] for r in rec if r.get('active') and r.get('frequence') == 'mensuel'
              and r.get('amount', 0) > 0 and r.get('categorie') not in RAV_EXCLUDE)
    chg = sum(-r['amount'] for r in rec if r.get('active') and r.get('frequence') == 'mensuel'
              and r.get('amount', 0) < 0 and r.get('categorie') not in RAV_EXCLUDE)
    return round(rev, 2), round(chg, 2)


def api_budget_status(qs):
    ops = load_ops()
    month = (qs.get('month', [''])[0] or dt.date.today().strftime('%Y-%m'))
    budget = _load_budget()
    spent, credits, income, outflow = defaultdict(float), 0.0, 0.0, 0.0
    for o in ops:
        if not o.get('date', '').startswith(month):
            continue
        amt = o.get('amount', 0)
        cat = o.get('categorie') or ''
        if amt < 0:
            spent[cat] += -amt
            if cat not in ('virements_internes', 'epargne', 'placements'):
                outflow += -amt   # tout ce qui sort réellement (hors épargne déjà mise de côté)
        else:
            if cat not in RAV_EXCLUDE:
                credits += amt
            if cat != 'virements_internes':
                income += amt
    frac = _month_fraction(month)
    envs = []
    for e in budget.get('enveloppes', []):
        s = round(sum(spent.get(c, 0) for c in e.get('categories', [])), 2)
        plafond = e.get('plafond') or 0
        proj = round(s / frac, 2) if frac < 1 else s
        envs.append({'key': e['key'], 'label': e['label'], 'categories': e.get('categories', []),
                     'plafond': plafond, 'spent': s, 'projection': proj,
                     'reste': round(plafond - s, 2) if plafond else None})
    rev, chg = _recurrences_fixes()
    return {'month': month, 'enveloppes': envs, 'credits': round(credits, 2),
            'frac': round(frac, 2), 'revenus_fixes': rev, 'charges_fixes': chg,
            'reste_a_vivre': round(rev - chg, 2),
            'net_mois': round(income - outflow, 2),
            'objectif_epargne': budget.get('objectif_epargne')}


# Ordre et libellés des groupes d'abonnements/charges (du plus « abonnement » au plus variable).
ABO_GROUPS = [('abos', '💳 Abonnements & services'), ('assurances', '🛡️ Assurances'),
              ('factures', '⚡ Énergie & factures'), ('bancaire', '🏦 Frais bancaires'),
              ('prets', '🏦 Prêts & impôts'), ('variable', '🔄 Récurrent variable')]
# flux où une hausse de montant / un doublon est un vrai signal (montant censé être stable).
HAUSSE_BUCKETS = {'abos', 'assurances'}
DOUBLON_BUCKETS = {'abos'}


def _abo_bucket(cat, cv, nops):
    cat = cat or ''
    if cat.startswith('pret') or cat == 'impots':
        return 'prets'
    if cat in ('abonnements', 'telecom'):
        return 'abos'
    if cat in ('assurance_habitation', 'auto_assurance', 'sante', 'mutuelle'):
        return 'assurances'
    if cat in ('energie', 'eau'):
        return 'factures'
    if cat == 'frais_bancaires':
        return 'bancaire'
    # autres catégories (loisirs, famille, enfants…) :
    #  - créancier identifié + montant stable → service récurrent (club, aide à domicile…)
    #  - montant non mesurable mais très régulier (ex. école) → service aussi
    if nops >= 4 and cv and cv < 0.30:
        return 'abos'
    if nops >= 6 and not cv:
        return 'abos'
    return 'variable'


def _future_occurrences(rec, end):
    """Dates des prochaines échéances d'une récurrence, de demain jusqu'à `end`."""
    freq = {'mensuel': 1, 'trimestriel': 3, 'annuel': 12}.get(rec.get('frequence'))
    if not freq:
        return []
    today = dt.date.today()
    tday = rec.get('typical_day') or 1
    try:
        cur = dt.date.fromisoformat(rec.get('last_date'))
    except (TypeError, ValueError):
        cur = today
    out, guard = [], 0
    while guard < 240:
        guard += 1
        m = cur.month + freq
        y = cur.year + (m - 1) // 12
        m = (m - 1) % 12 + 1
        cur = dt.date(y, m, min(tday, calendar.monthrange(y, m)[1]))
        if cur > end:
            break
        if cur > today:
            out.append(cur)
    return out


PROJ_EXCLUDE = {'virements_internes', 'placements'}


def api_projection(qs):
    days = int(qs.get('days', ['90'])[0] or 90)
    today = dt.date.today()
    end = today + dt.timedelta(days=days)
    reg = accounts_registry()
    base = 0.0
    for info in reg.values():
        if info.get('dashboard') and info.get('actif'):
            bal, _ = account_balance(info)
            if bal is not None:
                base += bal
    rec = (load_json(RECURRENCES_FILE, {}) or {}).get('recurrences', [])
    flows = []
    for r in rec:
        if not r.get('active') or not r.get('amount') or r.get('categorie') in PROJ_EXCLUDE:
            continue
        for d in _future_occurrences(r, end):
            flows.append((d.isoformat(), round(r['amount'], 2), r.get('creditor') or r.get('sample_label', '')))
    flows.sort()
    bal = round(base, 2)
    points = [{'date': today.isoformat(), 'balance': bal}]
    minbal, mindate = bal, today.isoformat()
    for dstr, amt, lbl in flows:
        bal = round(bal + amt, 2)
        points.append({'date': dstr, 'balance': bal, 'amount': amt, 'label': lbl})
        if bal < minbal:
            minbal, mindate = bal, dstr

    def bal_at(n):
        tgt = (today + dt.timedelta(days=n)).isoformat()
        b = round(base, 2)
        for dstr, amt, _ in flows:
            if dstr <= tgt:
                b = round(b + amt, 2)
        return b

    return {'base': round(base, 2), 'days': days, 'points': points,
            'min_balance': round(minbal, 2), 'min_date': mindate, 'decouvert': minbal < 0,
            'j30': bal_at(30), 'j60': bal_at(60), 'j90': bal_at(90),
            'net_flux': round(sum(f[1] for f in flows), 2)}


def _last_months(n):
    today = dt.date.today()
    y, m, out = today.year, today.month, []
    for _ in range(n):
        m -= 1
        if m == 0:
            m, y = 12, y - 1
        out.append(f'{y:04d}-{m:02d}')
    return out


def api_budget_suggest():
    """Plafonds suggérés = moyenne mensuelle des 6 derniers mois complets, par enveloppe."""
    ops = load_ops()
    budget = _load_budget()
    months = _last_months(6)
    spent = defaultdict(lambda: defaultdict(float))
    for o in ops:
        mo = o.get('date', '')[:7]
        if mo in months and o.get('amount', 0) < 0:
            spent[mo][o.get('categorie') or ''] += -o['amount']
    sugg = {}
    for e in budget.get('enveloppes', []):
        vals = [sum(spent[mo].get(c, 0) for c in e.get('categories', [])) for mo in months]
        avg = (sum(vals) / len(vals)) if vals else 0
        sugg[e['key']] = int(round(avg / 10.0) * 10)
    return {'suggestions': sugg, 'months': months}


def api_monthly(qs):
    n = int(qs.get('n', ['12'])[0] or 12)
    ops = load_ops()
    agg = defaultdict(lambda: {'revenus': 0.0, 'depenses': 0.0})
    for o in ops:
        mo = o.get('date', '')[:7]
        if not mo:
            continue
        amt = o.get('amount', 0)
        cat = o.get('categorie') or ''
        if amt >= 0:
            if cat not in RAV_EXCLUDE:
                agg[mo]['revenus'] += amt
        elif cat not in EXCLUDED_CATS:
            agg[mo]['depenses'] += -amt
    months = sorted(agg.keys())[-n:]
    out = [{'month': mo, 'revenus': round(agg[mo]['revenus'], 2),
            'depenses': round(agg[mo]['depenses'], 2),
            'net': round(agg[mo]['revenus'] - agg[mo]['depenses'], 2)} for mo in months]
    return {'months': out}


def api_abonnements():
    import statistics
    rec = (load_json(RECURRENCES_FILE, {}) or {}).get('recurrences', [])
    ops = load_ops()
    reg = accounts_registry()
    subs = [r for r in rec if r.get('active') and r.get('frequence') == 'mensuel'
            and r.get('amount', 0) < 0 and r.get('categorie') not in RAV_EXCLUDE]
    items, cred_count = [], defaultdict(int)
    for r in subs:
        cat = r.get('categorie')
        cred = r.get('creditor') or r.get('sample_label', '') or ''
        token = cred.upper()[:12]
        amts = []
        if token:
            for o in ops:
                if (o.get('account') == r.get('account') and o.get('amount', 0) < 0
                        and token in (o.get('label', '') or '').upper()):
                    amts.append((o.get('date', ''), -o['amount']))
        vals = [a for _, a in amts]
        cv = (statistics.pstdev(vals) / statistics.mean(vals)) if len(vals) >= 2 and statistics.mean(vals) else 0
        nops = r.get('occurrences') or len(vals)
        bucket = _abo_bucket(cat, cv, nops)
        hausse = None
        if bucket in HAUSSE_BUCKETS and len(amts) >= 3:
            amts.sort()
            recent = amts[-1][1]
            earlier = sorted(a for _, a in amts[:-1])
            med = earlier[len(earlier) // 2]
            if med > 0 and recent > med * 1.12:
                hausse = round((recent / med - 1) * 100)
        if bucket in DOUBLON_BUCKETS and token:
            cred_count[(bucket, token)] += 1
        items.append({'creditor': cred, 'token': token, 'categorie': cat, 'amount': round(r['amount'], 2),
                      'typical_day': r.get('typical_day'), 'account': label_for(r.get('account'), reg),
                      'bucket': bucket, 'hausse': hausse})
    for it in items:
        tk = it.get('token')
        it['doublon'] = it['bucket'] in DOUBLON_BUCKETS and bool(tk) and cred_count[(it['bucket'], tk)] > 1
        it.pop('token', None)
    groups = {k: [] for k, _ in ABO_GROUPS}
    for it in sorted(items, key=lambda x: x['amount']):
        groups.setdefault(it['bucket'], []).append(it)
    totals = {k: round(sum(x['amount'] for x in v), 2) for k, v in groups.items()}
    rev, _ = _recurrences_fixes()
    pct = round(100 * (-totals.get('abos', 0)) / rev, 1) if rev else None
    return {'groups': groups, 'order': ABO_GROUPS, 'totals': totals,
            'revenus_mensuels': rev, 'pct_service': pct}


def api_recurrences():
    data = load_json(RECURRENCES_FILE, {})
    reg = accounts_registry()
    recs = [r for r in data.get('recurrences', []) if r.get('active')]
    out = [{
        'creditor': r.get('creditor') or r.get('sample_label', ''),
        'categorie': r.get('categorie', ''),
        'frequence': r.get('frequence', ''),
        'amount': round(r.get('amount', 0), 2),
        'typical_day': r.get('typical_day'),
        'account': r.get('account'),
        'account_label': label_for(r.get('account'), reg),
        'direction': r.get('direction', ''),
    } for r in recs]
    out.sort(key=lambda x: abs(x['amount']), reverse=True)
    mensuel_debit = round(sum(x['amount'] for x in out
                              if x['frequence'] == 'mensuel' and x['amount'] < 0), 2)
    mensuel_credit = round(sum(x['amount'] for x in out
                               if x['frequence'] == 'mensuel' and x['amount'] > 0), 2)
    return {'recurrences': out, 'stats': data.get('_stats', {}),
            'mensuel_debit': mensuel_debit, 'mensuel_credit': mensuel_credit}


def api_sync():
    """Synchro à la demande. Via Enable Banking si connecté ; sinon recharge + explique."""
    log = []
    if not enable_connected():
        log.append('Enable Banking non connecté — affichage des données existantes.')
        log.append('Pour brancher tes banques en direct : voir scripts/ENABLE-BANKING.md')
        _ops_cache['mtime'] = None  # force relecture au prochain appel
        return {'ok': True, 'enable_connected': False, 'log': log}

    sess = load_json(EB_SESSIONS, {})
    sids = [k for k in sess if not k.startswith('_')]
    eb = os.path.join(HERE, 'enable_banking.py')
    ok = True

    def run(cmd, label):
        nonlocal ok
        try:
            r = subprocess.run([sys.executable, eb] + cmd, cwd=HERE,
                               capture_output=True, text=True, timeout=180)
        except subprocess.TimeoutExpired:
            log.append(f'⏱ timeout : {label}')
            ok = False
            return
        out = (r.stdout or '').strip() + (('\n' + r.stderr.strip()) if r.stderr.strip() else '')
        if r.returncode != 0:
            ok = False
            log.append('✗ ' + (out or f'{label} échoué'))
        else:
            log.append(out or f'({label} : ok)')

    # 1) pull de toutes les sessions (les candidats s'accumulent)
    for sid in sids:
        aspsp = (sess[sid].get('aspsp') or {}).get('name', sid)
        run(['pull', '--session-id', sid], f'{aspsp} pull')
    # 2) un SEUL import --apply à la fin (sinon un refus « non mappé » bloque les banques suivantes)
    run(['import', '--apply'], 'import --apply')
    _ops_cache['mtime'] = None
    return {'ok': ok, 'enable_connected': True, 'log': log}


# ---------------------------------------------------------------- Enable Banking (gestion comptes)

def _eb():
    sys.path.insert(0, HERE)
    import enable_banking as eb
    return eb


# Banques à connecter via Enable Banking (nom ASPSP EXACT côté Enable → clé courte interne).
# ADAPTEZ cette liste à VOS banques : `python3 enable_banking.py banks --grep <nom>` donne le
# nom ASPSP exact à mettre ici. Exemples de grandes banques françaises :
EB_TARGETS = [('Société Générale', 'sg'), ('BNP Paribas', 'bnp'),
              ('Boursorama Banque', 'bourso'), ('Crédit Mutuel', 'cm')]


def api_enable_status():
    eb = _eb()
    cfg = eb.load_config()
    app_id_set = bool(cfg.get('app_id'))
    if not app_id_set:
        return {'app_id_set': False, 'banks': [], 'sessions': []}
    try:
        sessions = eb.session_status()
    except Exception as e:  # noqa: BLE001
        return {'app_id_set': True, 'error': str(e), 'banks': [], 'sessions': []}
    by_aspsp = {s['aspsp']: s for s in sessions}
    banks = [{'aspsp': name, 'key': key, 'session': by_aspsp.get(name)} for name, key in EB_TARGETS]
    return {'app_id_set': True, 'redirect_url': cfg.get('redirect_url'),
            'banks': banks, 'sessions': sessions}


def api_enable_reauth(body):
    eb = _eb()
    aspsp = (body or {}).get('aspsp')
    if not aspsp:
        return {'error': 'aspsp manquant'}
    try:
        return eb.start_auth(aspsp)
    except Exception as e:  # noqa: BLE001
        return {'error': str(e)}


def api_enable_complete(body):
    import re
    raw = ((body or {}).get('code') or '').strip()
    m = re.search(r'[?&]code=([^&\s]+)', raw)   # accepte une URL de retour complète OU un code brut
    code = m.group(1) if m else raw
    if not code:
        return {'ok': False, 'log': ['Code vide — colle le code ou l\'URL de retour localhost.']}
    eb_path = os.path.join(HERE, 'enable_banking.py')
    log, ok = [], True
    for cmd, label in (([['session', code]], 'récupération'), ([['import', '--apply']], 'import')):
        try:
            r = subprocess.run([sys.executable, eb_path] + cmd[0], cwd=HERE,
                               capture_output=True, text=True, timeout=240)
            out = (r.stdout or '').strip() + (('\n' + r.stderr.strip()) if r.stderr.strip() else '')
            if r.returncode != 0:
                ok = False
                log.append('✗ ' + (out or f'{label} échoué'))
                break
            log.append(out or f'({label} ok)')
        except subprocess.TimeoutExpired:
            ok = False
            log.append(f'timeout {label}')
            break
    _ops_cache['mtime'] = None
    return {'ok': ok, 'log': log}


def api_enable_sync(body):
    """Re-tire une session déjà autorisée (pull + import), sans SCA."""
    sid = (body or {}).get('session_id')
    eb_path = os.path.join(HERE, 'enable_banking.py')
    log, ok = [], True
    pull_cmd = ['pull'] + (['--session-id', sid] if sid else [])
    for cmd, label in ((pull_cmd, 'pull'), (['import', '--apply'], 'import')):
        try:
            r = subprocess.run([sys.executable, eb_path] + cmd, cwd=HERE,
                               capture_output=True, text=True, timeout=240)
            out = (r.stdout or '').strip() + (('\n' + r.stderr.strip()) if r.stderr.strip() else '')
            if r.returncode != 0:
                ok = False
                log.append('✗ ' + (out or f'{label} échoué'))
                break
            log.append(out or f'({label} ok)')
        except subprocess.TimeoutExpired:
            ok = False
            log.append(f'timeout {label}')
            break
    _ops_cache['mtime'] = None
    return {'ok': ok, 'log': log}


ROUTES_GET = {
    '/api/overview': lambda qs: api_overview(),
    '/api/operations': api_operations,
    '/api/categories': api_categories,
    '/api/recurrences': lambda qs: api_recurrences(),
    '/api/enable/status': lambda qs: api_enable_status(),
    '/api/account': lambda qs: api_account(),
    '/api/categories-ref': lambda qs: api_categories_ref(),
    '/api/budgets': lambda qs: api_budgets(),
    '/api/budget-status': api_budget_status,
    '/api/abonnements': lambda qs: api_abonnements(),
    '/api/projection': api_projection,
    '/api/budget-suggest': lambda qs: api_budget_suggest(),
    '/api/monthly': api_monthly,
}

# ---------------------------------------------------------------- compte / administration

def api_account():
    return {'user': load_auth().get('user', AUTH_DEFAULT_USER)}


def api_account_password(body):
    global _auth_accepted
    new = ((body or {}).get('new_password') or '').strip()
    if len(new) < 3:
        return {'ok': False, 'error': 'Mot de passe trop court (3 caractères minimum).'}
    user = load_auth().get('user', AUTH_DEFAULT_USER)
    write_auth(user, new)
    _auth_accepted = None   # invalide le cache → le navigateur redemandera les identifiants
    return {'ok': True, 'user': user}


ROUTES_POST = {
    '/api/enable/reauth': api_enable_reauth,
    '/api/enable/complete': api_enable_complete,
    '/api/enable/sync': api_enable_sync,
    '/api/account/password': api_account_password,
    '/api/recategorize': api_recategorize,
    '/api/budgets': api_budgets_save,
}


# ---------------------------------------------------------------- serveur HTTP

class Handler(BaseHTTPRequestHandler):
    def _send_json(self, obj, status=200):
        body = json.dumps(obj, ensure_ascii=False).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _auth_guard(self):
        if check_auth(self.headers.get('Authorization')):
            return True
        body = 'Authentification requise.'.encode('utf-8')
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Basic realm="openbudget", charset="UTF-8"')
        self.send_header('Content-Type', 'text/plain; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        return False

    def do_GET(self):
        if not self._auth_guard():
            return
        parsed = urlparse(self.path)
        path, qs = parsed.path, parse_qs(parsed.query)
        if path in ('/', '/index.html'):
            try:
                with open(INDEX_HTML, 'rb') as f:
                    body = f.read()
            except OSError:
                self.send_error(404, 'index.html manquant')
                return
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        handler = ROUTES_GET.get(path)
        if handler:
            try:
                self._send_json(handler(qs))
            except Exception as e:  # noqa: BLE001 — un bug d'endpoint ne doit pas tuer le serveur
                self._send_json({'error': str(e)}, 500)
            return
        self.send_error(404)

    def _read_body(self):
        try:
            n = int(self.headers.get('Content-Length', 0))
            if n <= 0:
                return {}
            return json.loads(self.rfile.read(n).decode('utf-8') or '{}')
        except (ValueError, TypeError):
            return {}

    def do_POST(self):
        if not self._auth_guard():
            return
        path = urlparse(self.path).path
        if path == '/api/sync':
            try:
                self._send_json(api_sync())
            except Exception as e:  # noqa: BLE001
                self._send_json({'ok': False, 'log': [str(e)]}, 500)
            return
        handler = ROUTES_POST.get(path)
        if handler:
            body = self._read_body()
            try:
                self._send_json(handler(body))
            except Exception as e:  # noqa: BLE001
                self._send_json({'ok': False, 'error': str(e)}, 500)
            return
        self.send_error(404)

    def log_message(self, fmt, *args):
        pass  # silencieux


def main():
    ap = argparse.ArgumentParser(description='openbudget — app web locale')
    ap.add_argument('--port', type=int, default=8787)
    ap.add_argument('--host', default='127.0.0.1')
    ap.add_argument('--user', help='nom d\'utilisateur (avec --set-password)')
    ap.add_argument('--set-password', metavar='MDP', help='(re)définit le mot de passe puis quitte')
    args = ap.parse_args()

    if args.set_password:
        user = args.user or (load_json(AUTH_FILE, {}) or {}).get('user', AUTH_DEFAULT_USER)
        write_auth(user, args.set_password)
        print(f"✓ Identifiants web mis à jour (login « {user} »).")
        return

    load_auth(announce=True)
    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    url = f'http://{args.host}:{args.port}'
    print(f'openbudget — app locale sur {url}  (Ctrl+C pour arrêter)')
    print(f'Opérations : {OPERATIONS_FILE}')
    print(f'Enable Banking connecté : {enable_connected()}')
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print('\nArrêt.')
        srv.server_close()


if __name__ == '__main__':
    main()
