#!/usr/bin/env python3
"""
Client Enable Banking (open banking DSP2) pour openbudget.

Mode « restricted / individual non-commercial » : on lit SES PROPRES comptes, sans
contrat ni KYB. On branche chaque banque en direct → on récupère TOUTES les opérations,
y compris les prélèvements récurrents que les alertes bancaires ne signalent pas.

Flux complet :
  1. keygen                       → génère la clé privée + le certificat à uploader
  2. [vous, navigateur]           → créez le compte Enable, enregistrez une appli,
                                    déclarez le redirect_url, uploadez le certificat, récupérez
                                    l'app_id, puis « Activate by linking accounts » par banque
  3. config --set-app-id <uuid>   → enregistre l'app_id
  4. banks --grep <nom>           → confirme la couverture de votre banque
  5. auth "<Nom banque>"          → autorise + récupère tout l'historique (fenêtre 1 h après SCA)
  6. import                       → dry-run de la fusion dans operations.jsonl
  7. import --apply               → écrit réellement

Secrets HORS dépôt : ~/.openbudget/enable-banking/ (clé privée chmod 600, config.json).
Rien n'est écrit dans operations.jsonl sans --apply (dry-run par défaut).
API : https://api.enablebanking.com — JWT RS256 (iss=enablebanking.com, aud=api.enablebanking.com).
"""
import argparse
import base64
import copy
import datetime as dt
import json
import os
import sys
import time
import uuid
from urllib.parse import parse_qs, urlparse

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

API_BASE = 'https://api.enablebanking.com'
JWT_ISS = 'enablebanking.com'
JWT_AUD = 'api.enablebanking.com'

import config

CONFIG_DIR = config.ENABLE_DIR
CONFIG_FILE = os.path.join(CONFIG_DIR, 'config.json')
KEY_FILE = os.path.join(CONFIG_DIR, 'private_key.pem')
CERT_FILE = os.path.join(CONFIG_DIR, 'certificate.pem')
SESSIONS_FILE = os.path.join(CONFIG_DIR, 'sessions.json')
CANDIDATE_FILE = os.path.join(CONFIG_DIR, 'candidate_ops.jsonl')

SCRIPT_DIR = config.ROOT
ACCOUNTS_JSON = config.ACCOUNTS_FILE

# Optionnel : si accounts.json nomme un compte autrement que les opérations, mapper ici
# registre→clé d'opérations (fichier data/account_maps.json, clé « alias »). Vide par défaut.
def _load_alias():
    try:
        with open(config.ACCOUNT_MAPS_FILE, encoding='utf-8') as f:
            return json.load(f).get('alias', {})
    except (OSError, ValueError):
        return {}


ALIAS_REGISTRE_VERS_OPS = _load_alias()

TLS_CERT = os.path.join(CONFIG_DIR, 'localhost-tls-cert.pem')
TLS_KEY = os.path.join(CONFIG_DIR, 'localhost-tls-key.pem')

DEFAULT_CONFIG = {
    'app_id': '',
    'private_key': KEY_FILE,
    'redirect_url': 'https://localhost:8080/cb',   # Enable exige HTTPS (http refusé)
    'psu_ip': '',           # certaines banques exigent Psu-Ip-Address ; sinon laisser vide
    'account_map': {},      # IBAN -> clé de compte openbudget (mapping manuel, complète l'auto-détection)
}


# ---------------------------------------------------------------- config / IO

def load_config():
    if not os.path.exists(CONFIG_FILE):
        return dict(DEFAULT_CONFIG)
    with open(CONFIG_FILE, encoding='utf-8') as f:
        cfg = json.load(f)
    merged = dict(DEFAULT_CONFIG)
    merged.update(cfg)
    return merged


def save_config(cfg):
    os.makedirs(CONFIG_DIR, exist_ok=True)
    with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)


def _require_app_id(cfg):
    if not cfg.get('app_id'):
        sys.exit("app_id manquant. Fais `keygen`, uploade le certificat sur enablebanking.com, "
                 "puis `config --set-app-id <uuid>`.")
    if not os.path.exists(os.path.expanduser(cfg['private_key'])):
        sys.exit(f"Clé privée introuvable ({cfg['private_key']}). Lance d'abord `keygen`.")


# ---------------------------------------------------------------- JWT (RS256)

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


def make_jwt(app_id, key_path, ttl=3600):
    """JWT RS256 signé localement. ttl ≤ 86400 s (contrainte Enable Banking)."""
    ttl = min(ttl, 86400)
    with open(os.path.expanduser(key_path), 'rb') as f:
        key = serialization.load_pem_private_key(f.read(), password=None)
    iat = int(time.time())
    header = {'typ': 'JWT', 'alg': 'RS256', 'kid': app_id}
    body = {'iss': JWT_ISS, 'aud': JWT_AUD, 'iat': iat, 'exp': iat + ttl}
    signing_input = (_b64url(json.dumps(header, separators=(',', ':')).encode()) + '.'
                     + _b64url(json.dumps(body, separators=(',', ':')).encode()))
    sig = key.sign(signing_input.encode(), padding.PKCS1v15(), hashes.SHA256())
    return signing_input + '.' + _b64url(sig)


# ---------------------------------------------------------------- HTTP

class EnableApiError(Exception):
    def __init__(self, status, method, path, payload):
        self.status = status
        self.method = method
        self.path = path
        self.payload = payload
        self.code = payload.get('error') if isinstance(payload, dict) else None
        super().__init__(f"[API {status}] {method} {path}" + (f" — {self.code}" if self.code else ''))


def api(method, path, params=None, body=None, extra_headers=None):
    cfg = load_config()
    _require_app_id(cfg)
    token = make_jwt(cfg['app_id'], cfg['private_key'])
    headers = {'Authorization': f'Bearer {token}'}
    if extra_headers:
        headers.update(extra_headers)
    r = requests.request(method, API_BASE + path, headers=headers,
                         params=params, json=body, timeout=45)
    if r.status_code >= 300:
        try:
            payload = r.json()
        except ValueError:
            payload = {'raw': r.text}
        raise EnableApiError(r.status_code, method, path, payload)
    return r.json() if r.content else {}


# ---------------------------------------------------------------- keygen

def cmd_keygen(args):
    os.makedirs(CONFIG_DIR, exist_ok=True)
    if os.path.exists(KEY_FILE) and not args.force:
        sys.exit(f"Une clé existe déjà ({KEY_FILE}). Relance avec --force pour la remplacer "
                 "(⚠️ invalide l'app_id actuel : il faudra réuploader le certificat).")
    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    with open(KEY_FILE, 'wb') as f:
        f.write(key.private_bytes(serialization.Encoding.PEM,
                                  serialization.PrivateFormat.TraditionalOpenSSL,
                                  serialization.NoEncryption()))
    os.chmod(KEY_FILE, 0o600)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'openbudget-enable-banking')])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now).not_valid_after(now + dt.timedelta(days=3650))
            .sign(key, hashes.SHA256()))
    with open(CERT_FILE, 'wb') as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    if not os.path.exists(CONFIG_FILE):
        save_config(dict(DEFAULT_CONFIG))
    print(f"✓ Clé privée : {KEY_FILE} (chmod 600)")
    print(f"✓ Certificat : {CERT_FILE}  ← à UPLOADER sur enablebanking.com (Control Panel)")
    print(f"✓ Config     : {CONFIG_FILE}")
    print("\nSuite : crée le compte Enable + une appli PRODUCTION, déclare le redirect_url "
          f"({load_config()['redirect_url']}), uploade le certificat ci-dessus, récupère l'app_id,")
    print("puis : python3 enable_banking.py config --set-app-id <uuid>")


# ---------------------------------------------------------------- config CLI

def cmd_config(args):
    cfg = load_config()
    changed = False
    if args.set_app_id:
        cfg['app_id'] = args.set_app_id.strip()
        changed = True
    if args.set_redirect:
        cfg['redirect_url'] = args.set_redirect.strip()
        changed = True
    if args.set_psu_ip:
        cfg['psu_ip'] = args.set_psu_ip.strip()
        changed = True
    if args.map:
        for pair in args.map:
            iban, _, key = pair.partition('=')
            if not key:
                sys.exit(f"Format attendu IBAN=cle_compte, reçu : {pair}")
            cfg.setdefault('account_map', {})[iban.strip()] = key.strip()
            changed = True
    if changed:
        save_config(cfg)
        print("✓ config mise à jour")
    shown = dict(cfg)
    print(json.dumps(shown, indent=2, ensure_ascii=False))


# ---------------------------------------------------------------- banks

def cmd_banks(args):
    data = api('GET', '/aspsps', params={'country': args.country})
    aspsps = data.get('aspsps', [])
    q = (args.grep or '').lower()
    rows = [a for a in aspsps if not q or q in a.get('name', '').lower()]
    for a in sorted(rows, key=lambda x: x.get('name', '').lower()):
        days = a.get('maximum_consent_validity', 0) // 86400
        approaches = ','.join(sorted({m.get('approach', '?') for m in a.get('auth_methods', [])}))
        beta = ' [BETA]' if a.get('beta') else ''
        print(f"{a.get('name', '?'):42} {a.get('country', '?')}  consentement≤{days}j  {approaches}{beta}")
    print(f"\n{len(rows)}/{len(aspsps)} ASPSP (country={args.country}"
          + (f", filtre « {args.grep} »" if args.grep else '') + ').')


# ---------------------------------------------------------------- auth + pull

def _find_aspsp(name, country):
    data = api('GET', '/aspsps', params={'country': country})
    aspsps = data.get('aspsps', [])
    exact = [a for a in aspsps if a.get('name', '').lower() == name.lower()]
    if exact:
        return exact[0]
    partial = [a for a in aspsps if name.lower() in a.get('name', '').lower()]
    if len(partial) == 1:
        return partial[0]
    if not partial:
        sys.exit(f"Aucun ASPSP « {name} » en {country}. Liste-les avec : banks --country {country}")
    sys.exit("Plusieurs correspondances : " + ', '.join(a['name'] for a in partial))


def _ensure_localhost_tls():
    """Certificat TLS auto-signé pour que le catcher serve en HTTPS (Enable n'accepte que https)."""
    if os.path.exists(TLS_CERT) and os.path.exists(TLS_KEY):
        return TLS_CERT, TLS_KEY
    import ipaddress
    os.makedirs(CONFIG_DIR, exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')])
    now = dt.datetime.now(dt.timezone.utc)
    san = x509.SubjectAlternativeName([x509.DNSName('localhost'),
                                       x509.IPAddress(ipaddress.ip_address('127.0.0.1'))])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now).not_valid_after(now + dt.timedelta(days=3650))
            .add_extension(san, critical=False).sign(key, hashes.SHA256()))
    with open(TLS_KEY, 'wb') as f:
        f.write(key.private_bytes(serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
    os.chmod(TLS_KEY, 0o600)
    with open(TLS_CERT, 'wb') as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    return TLS_CERT, TLS_KEY


def _catch_code(redirect_url, expected_state):
    import http.server
    u = urlparse(redirect_url)
    port = u.port or (443 if u.scheme == 'https' else 80)
    host, path = u.hostname or 'localhost', u.path or '/'
    result = {}

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            pu = urlparse(self.path)
            if pu.path == path:
                qs = parse_qs(pu.query)
                result['code'] = qs.get('code', [None])[0]
                result['state'] = qs.get('state', [None])[0]
                result['error'] = qs.get('error', [None])[0]
                self.send_response(200)
                self.send_header('Content-Type', 'text/html; charset=utf-8')
                self.end_headers()
                msg = ('Autorisation reçue — tu peux fermer cet onglet et revenir au terminal.'
                       if result['code'] else f"Erreur : {result['error']}")
                self.wfile.write(f'<html><body style="font-family:sans-serif"><h2>openbudget × Enable Banking</h2><p>{msg}</p></body></html>'.encode())
            else:
                self.send_response(404)
                self.end_headers()

        def log_message(self, *a):
            pass

    try:
        srv = http.server.HTTPServer((host, port), Handler)
    except OSError as e:
        sys.exit(f"Impossible d'écouter sur {host}:{port} ({e}). "
                 "Utilise --manual pour coller le code à la main.")
    if u.scheme == 'https':
        import ssl
        certfile, keyfile = _ensure_localhost_tls()
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile, keyfile)
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    print(f"[en attente du retour sur {redirect_url} — valide dans le navigateur…]")
    while 'code' not in result and 'error' not in result:
        srv.handle_request()
    srv.server_close()
    if result.get('error'):
        sys.exit(f"Autorisation refusée : {result['error']}")
    if result.get('state') != expected_state:
        sys.exit("State mismatch (anti-CSRF) — abandon.")
    return result['code']


def cmd_auth(args):
    cfg = load_config()
    aspsp = _find_aspsp(args.aspsp, args.country)
    max_days = aspsp.get('maximum_consent_validity', 180 * 86400) // 86400
    days = min(args.days, max_days) if max_days else args.days
    valid_until = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=days)).isoformat()
    state = str(uuid.uuid4())
    body = {
        'access': {'balances': True, 'transactions': True, 'valid_until': valid_until},
        'aspsp': {'name': aspsp['name'], 'country': aspsp['country']},
        'state': state,
        'redirect_url': cfg['redirect_url'],
        'psu_type': 'personal',
    }
    resp = api('POST', '/auth', body=body)
    print(f"ASPSP : {aspsp['name']} ({aspsp['country']}) — consentement {days} j (max {max_days} j)")
    req = aspsp.get('required_psu_headers') or []
    if req:
        print(f"⚠️ Cette banque exige les en-têtes {req}. "
              "Si les requêtes échouent (PSU_HEADER_NOT_PROVIDED), fais "
              "`config --set-psu-ip <ton_ip_publique>`.")
    print("\n➜ Ouvre cette URL dans un navigateur SUR CE MAC et valide avec ta banque :\n")
    print('   ' + resp['url'] + '\n')
    if args.manual:
        code = input("Colle le `code` de l'URL de redirection : ").strip()
        got_state = input("Colle le `state` (ou Entrée pour ignorer) : ").strip()
        if got_state and got_state != state:
            sys.exit("State mismatch — abandon.")
    else:
        code = _catch_code(cfg['redirect_url'], state)
    _authorize_and_pull(code, args.history)


def _authorize_and_pull(code, history_days):
    sess = api('POST', '/sessions', body={'code': code})
    session_id = sess['session_id']
    accounts = sess.get('accounts', [])
    _save_session(sess)
    print(f"\n✓ Session {session_id} — {len(accounts)} compte(s) lié(s).")
    amap = _build_account_map(accounts)
    # Premier tirage juste après la SCA : fenêtre ~1 h pour tout l'historique → strategy=longest.
    ops = _pull_accounts(accounts, amap, history_days, strategy='longest')
    _write_candidates(ops)
    _touch_last_pull(session_id)
    return {'session_id': session_id, 'aspsp': (sess.get('aspsp') or {}).get('name'),
            'n_accounts': len([a for a in accounts if a.get('uid')]), 'n_ops': len(ops)}


def _psu_headers(cfg):
    return {'Psu-Ip-Address': cfg['psu_ip']} if cfg.get('psu_ip') else None


# Types de comptes à ne pas tirer : prêts, épargne, et cartes (en débit immédiat, les opérations
# carte sont déjà dans le compte courant → les tirer ferait des doublons).
SKIP_ACCOUNT_TYPES = {'LOAN', 'SVGS', 'CARD'}
# Erreurs « période » : on retente le compte sur 90 jours au lieu de l'historique long.
RETRY_PERIOD_CODES = {'WRONG_TRANSACTIONS_PERIOD', 'DATE_FROM_IN_FUTURE', 'WRONG_DATE_INTERVAL'}


def _pull_one(uid, key, iban, history_days, date_to, headers, strategy):
    """Tire les opérations BOOK d'un compte (paginé). Renvoie (ops, nb_pending). Lève EnableApiError."""
    date_from = (dt.date.today() - dt.timedelta(days=history_days)).isoformat()
    ops, pending, cont, seen = [], 0, None, set()
    while True:
        params = {'date_from': date_from, 'date_to': date_to}
        if strategy:
            params['strategy'] = strategy
        if cont:
            params['continuation_key'] = cont
        data = api('GET', f'/accounts/{uid}/transactions', params=params, extra_headers=headers)
        for t in data.get('transactions', []):
            op = _txn_to_op(t, key)
            if op is None:
                pending += 1
                continue
            ref = t.get('entry_reference')
            if ref and ref in seen:
                continue
            if ref:
                seen.add(ref)
            if key is None and iban:
                op['_src_iban'] = iban        # pour proposer `config --map` à l'import
            ops.append(op)
        cont = data.get('continuation_key')
        if not cont:
            break
    return ops, pending


def _pull_accounts(accounts, amap, history_days, strategy=None):
    """Une seule passe par compte (pas de polling). Un compte en erreur n'arrête pas les autres."""
    cfg = load_config()
    headers = _psu_headers(cfg)
    date_to = dt.date.today().isoformat()
    all_ops, pending = [], 0
    for acc in accounts:
        uid = acc.get('uid')
        name = acc.get('name') or uid or '?'
        if not uid:
            print(f"   {name:32} → ignoré (compte sans identifiant)")
            continue
        key = amap.get(uid)
        iban = _acc_iban(acc)
        cat = acc.get('cash_account_type')
        if cat in SKIP_ACCOUNT_TYPES:
            print(f"   {name:32} → ignoré (type {cat}, hors périmètre)")
            continue
        try:
            ops, pend = _pull_one(uid, key, iban, history_days, date_to, headers, strategy)
        except EnableApiError as e:
            if e.code in RETRY_PERIOD_CODES and history_days > 90:
                try:
                    ops, pend = _pull_one(uid, key, iban, 90, date_to, headers, None)
                    print(f"   {name:32} → historique réduit à 90 j ({e.code})")
                except EnableApiError as e2:
                    print(f"   {name:32} → ERREUR {e2.code or e2.status}, ignoré")
                    continue
            else:
                print(f"   {name:32} → ERREUR {e.code or e.status}, ignoré")
                continue
        all_ops.extend(ops)
        pending += pend
        print(f"   {name:32} → {len(ops)} opérations  [{key or 'NON MAPPÉ'}]")
    print(f"\nTotal : {len(all_ops)} opérations comptabilisées (BOOK), "
          f"{pending} en attente (PDNG, ignorées).")
    return all_ops


def _txn_to_op(t, account_key):
    if t.get('status') != 'BOOK':
        return None
    try:
        amount = float(t['transaction_amount']['amount'])
    except (KeyError, TypeError, ValueError):
        return None
    indic = t.get('credit_debit_indicator')
    amount = -abs(amount) if indic == 'DBIT' else abs(amount)
    date = t.get('booking_date') or t.get('value_date') or t.get('transaction_date')
    party = ((t.get('creditor') if indic == 'DBIT' else t.get('debtor')) or {}).get('name')
    remit = ' '.join(t.get('remittance_information') or []).strip()
    btc = (t.get('bank_transaction_code') or {}).get('description', '')
    label = ' — '.join(x for x in (party, remit) if x) or btc or '(sans libellé)'
    op = {
        'date': date,
        'label': label[:200],
        'amount': round(amount, 2),
        'account': account_key or 'enable_non_mappe',
        'categorie_originale': '',
        'source': 'enable',
    }
    if t.get('entry_reference'):
        op['ref'] = t['entry_reference']
    if t.get('merchant_category_code'):
        op['mcc'] = t['merchant_category_code']
    return op


# ---------------------------------------------------------------- mapping comptes

def _first_iban(acc):
    aid = acc.get('account_id') or {}
    if aid.get('iban'):
        return aid['iban']
    for ident in acc.get('all_account_ids') or []:
        if (ident.get('scheme_name') or '').upper() == 'IBAN' and ident.get('identification'):
            return ident['identification']
    return None


def _acc_iban(acc):
    """IBAN d'un compte, qu'il vienne d'un objet API complet ou d'une session sauvegardée (clé 'iban')."""
    return acc.get('iban') or _first_iban(acc)


def _load_registry():
    """{numéro_compte_11chiffres (ofx_acct_id) -> clé de compte ops}."""
    try:
        with open(ACCOUNTS_JSON, encoding='utf-8') as f:
            reg = json.load(f)
    except (OSError, ValueError):
        return {}
    out = {}
    for regkey, info in (reg.get('accounts') or {}).items():
        ofx = info.get('ofx_acct_id')
        if ofx:
            out[ofx] = ALIAS_REGISTRE_VERS_OPS.get(regkey, regkey)
    return out


def _build_account_map(accounts):
    cfg = load_config()
    manual = cfg.get('account_map', {})
    registry = _load_registry()
    amap, unmapped = {}, []
    for acc in accounts:
        uid = acc.get('uid')
        if not uid:
            continue        # compte sans identifiant exploitable (renvoyé par certaines banques)
        iban = _acc_iban(acc)
        key = None
        if iban and iban in manual:
            key = manual[iban]
        elif iban and len(iban) >= 25:
            acctnum = iban[14:25]        # numéro de compte (11 car.) dans un IBAN FR
            key = registry.get(acctnum)
        amap[uid] = key
        if not key:
            unmapped.append((acc.get('name'), iban, uid))
    if unmapped:
        print("\n⚠️ Comptes NON mappés (ajoute-les, clé = IBAN) :")
        for name, iban, uid in unmapped:
            print(f"     config --map {iban}=<cle>    # {name}  (uid {uid})")
    return amap


# ---------------------------------------------------------------- sessions / candidats

def _save_session(sess):
    data = {}
    if os.path.exists(SESSIONS_FILE):
        with open(SESSIONS_FILE, encoding='utf-8') as f:
            data = json.load(f)
    data[sess['session_id']] = {
        'created': dt.datetime.now(dt.timezone.utc).isoformat(),
        'aspsp': sess.get('aspsp'),
        'access': sess.get('access'),
        # on garde l'essentiel du compte (uid valable tant que la session est AUTHORIZED)
        'accounts': [{'uid': a['uid'], 'iban': _first_iban(a), 'name': a.get('name'),
                      'cash_account_type': a.get('cash_account_type')}
                     for a in sess.get('accounts', [])],
    }
    data['_last'] = sess['session_id']
    with open(SESSIONS_FILE, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def _op_key(o):
    """Clé d'unicité d'une opération candidate (entre banques et entre run)."""
    if o.get('ref'):
        return ('ref', o.get('account'), o['ref'])
    return ('cmp', o.get('account'), o.get('date'), round(o.get('amount', 0), 2), o.get('label', ''))


def _read_candidates():
    ops = []
    if os.path.exists(CANDIDATE_FILE):
        with open(CANDIDATE_FILE, encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line:
                    ops.append(json.loads(line))
    return ops


def _write_candidates(ops):
    """Accumule : `auth CIC` puis `auth BNP` sans import entre-temps ne doit pas écraser CIC."""
    existing = _read_candidates()
    seen = {_op_key(o) for o in existing}
    nouveaux = 0
    for o in ops:
        k = _op_key(o)
        if k in seen:
            continue
        seen.add(k)
        existing.append(o)
        nouveaux += 1
    with open(CANDIDATE_FILE, 'w', encoding='utf-8') as f:
        for o in existing:
            f.write(json.dumps(o, ensure_ascii=False) + '\n')
    print(f"\n✓ {nouveaux} nouvelles opérations ajoutées aux candidats "
          f"(total {len(existing)} dans {CANDIDATE_FILE})")
    print("   Vérifie la fusion : python3 enable_banking.py import")


def cmd_session(args):
    _authorize_and_pull(args.code, args.history)


def cmd_pull(args):
    if not os.path.exists(SESSIONS_FILE):
        sys.exit("Aucune session. Lance d'abord `auth`.")
    with open(SESSIONS_FILE, encoding='utf-8') as f:
        data = json.load(f)
    sid = args.session_id or data.get('_last')
    if not sid or sid not in data:
        sys.exit(f"Session introuvable ({sid}). Sessions connues : "
                 + ', '.join(k for k in data if not k.startswith('_')))
    saved = data[sid]
    accounts = saved['accounts']
    amap = _build_account_map(accounts)
    ops = _pull_accounts(accounts, amap, args.days, strategy=args.strategy)
    _write_candidates(ops)
    _touch_last_pull(sid)


# ---------------------------------------------------------------- import (fusion)

def cmd_import(args):
    sys.path.insert(0, SCRIPT_DIR)
    from config import OPERATIONS_FILE
    from op_merger import load_operations, merge_and_enrich, save_operations

    candidates = _read_candidates()
    if not candidates:
        sys.exit("Aucun candidat. Lance d'abord `auth` ou `pull`.")
    non_mappe = [o for o in candidates if o.get('account') == 'enable_non_mappe']
    existing = load_operations(OPERATIONS_FILE)
    work = existing if args.apply else copy.deepcopy(existing)
    added, enriched = merge_and_enrich(work, candidates)
    matched = len(candidates) - len(added)
    print(f"{len(candidates)} candidats Enable → {len(added)} nouveaux, "
          f"{len(enriched)} enrichis, {matched} déjà connus"
          + (f"  (⚠️ {len(non_mappe)} NON MAPPÉS)" if non_mappe else '') + '.')
    for o in added[:25]:
        print(f"   NEW  {o.get('date')}  {o.get('amount'):>10.2f}  "
              f"{o.get('account'):22} {o.get('label', '')[:48]}")
    if len(added) > 25:
        print(f"   … (+{len(added) - 25} autres)")
    if args.apply:
        if non_mappe:
            ibans = sorted({o.get('_src_iban') for o in non_mappe if o.get('_src_iban')})
            print("\n✗ Écriture refusée : des opérations ne sont rattachées à aucun compte openbudget "
                  "(elles créeraient des doublons). Mappe-les puis relance l'import :")
            for ib in (ibans or ['<IBAN inconnu — revois la sortie de `auth`>']):
                print(f"     python3 enable_banking.py config --map {ib}=<cle>")
            sys.exit(1)
        save_operations(OPERATIONS_FILE, existing)
        os.remove(CANDIDATE_FILE)
        print(f"\n✓ Écrit dans {OPERATIONS_FILE} — candidats consommés.")
    else:
        print("\n(dry-run — relance avec `import --apply` pour écrire dans operations.jsonl)")


# ---------------------------------------------------------------- API réutilisable (app web)

def _touch_last_pull(session_id):
    if not os.path.exists(SESSIONS_FILE):
        return
    with open(SESSIONS_FILE, encoding='utf-8') as f:
        data = json.load(f)
    if session_id in data:
        data[session_id]['last_pull'] = dt.datetime.now(dt.timezone.utc).isoformat()
        with open(SESSIONS_FILE, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)


def _map_key_for(iban):
    """Clé de compte openbudget pour un IBAN (mapping manuel puis auto via ofx_acct_id)."""
    cfg = load_config()
    manual = cfg.get('account_map', {})
    if iban and iban in manual:
        return manual[iban]
    if iban and len(iban) >= 25:
        return _load_registry().get(iban[14:25])
    return None


def start_auth(aspsp_name, country='FR', days=180):
    """Démarre une autorisation : POST /auth et renvoie l'URL tilisy (sans catcher)."""
    cfg = load_config()
    aspsp = _find_aspsp(aspsp_name, country)
    max_days = aspsp.get('maximum_consent_validity', 180 * 86400) // 86400
    d = min(days, max_days) if max_days else days
    valid_until = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=d)).isoformat()
    state = str(uuid.uuid4())
    body = {
        'access': {'balances': True, 'transactions': True, 'valid_until': valid_until},
        'aspsp': {'name': aspsp['name'], 'country': aspsp['country']},
        'state': state, 'redirect_url': cfg['redirect_url'], 'psu_type': 'personal',
    }
    resp = api('POST', '/auth', body=body)
    return {'url': resp['url'], 'authorization_id': resp.get('authorization_id'),
            'state': state, 'aspsp': aspsp['name'], 'country': aspsp['country'],
            'days': d, 'max_days': max_days,
            'required_psu_headers': aspsp.get('required_psu_headers') or []}


def complete_auth(code, history_days=720):
    """Échange le code → session → tire l'historique. Renvoie un résumé."""
    return _authorize_and_pull(code, history_days)


def session_status():
    """État live de chaque session enregistrée (statut, expiration, comptes mappés)."""
    if not os.path.exists(SESSIONS_FILE):
        return []
    with open(SESSIONS_FILE, encoding='utf-8') as f:
        data = json.load(f)
    out = []
    for sid in [k for k in data if not k.startswith('_')]:
        s = data[sid]
        valid_until = (s.get('access') or {}).get('valid_until')
        status = None
        try:
            r = api('GET', f'/sessions/{sid}')
            status = r.get('status')
            valid_until = (r.get('access') or {}).get('valid_until') or valid_until
        except EnableApiError as e:
            status = f'ERREUR {e.code or e.status}'
        accounts = [{'name': a.get('name'), 'iban': a.get('iban'), 'uid': a.get('uid'),
                     'cle': _map_key_for(a.get('iban'))}
                    for a in s.get('accounts', []) if a.get('uid')]
        out.append({'session_id': sid, 'aspsp': (s.get('aspsp') or {}).get('name'),
                    'status': status, 'created': s.get('created'),
                    'last_pull': s.get('last_pull'), 'valid_until': valid_until,
                    'accounts': accounts})
    return out


# ---------------------------------------------------------------- CLI

def main():
    p = argparse.ArgumentParser(description='Client Enable Banking (DSP2) pour openbudget.')
    sub = p.add_subparsers(dest='cmd', required=True)

    sp = sub.add_parser('keygen', help='génère la clé privée + le certificat à uploader')
    sp.add_argument('--force', action='store_true', help='remplace une clé existante')
    sp.set_defaults(func=cmd_keygen)

    sp = sub.add_parser('config', help='affiche / modifie la config')
    sp.add_argument('--set-app-id')
    sp.add_argument('--set-redirect')
    sp.add_argument('--set-psu-ip')
    sp.add_argument('--map', action='append', metavar='IBAN=cle', help='mappe un IBAN vers une clé de compte openbudget')
    sp.set_defaults(func=cmd_config)

    sp = sub.add_parser('banks', help='liste les banques (ASPSP) disponibles')
    sp.add_argument('--country', default='FR')
    sp.add_argument('--grep', help='filtre sur le nom (ex. bourso)')
    sp.set_defaults(func=cmd_banks)

    sp = sub.add_parser('auth', help='autorise une banque + récupère tout l\'historique')
    sp.add_argument('aspsp', help='nom de la banque (cf. `banks`)')
    sp.add_argument('--country', default='FR')
    sp.add_argument('--days', type=int, default=180, help='durée de consentement souhaitée (plafonnée par la banque)')
    sp.add_argument('--history', type=int, default=720, help='profondeur d\'historique à récupérer (jours)')
    sp.add_argument('--manual', action='store_true', help='coller le code à la main (pas de serveur localhost)')
    sp.set_defaults(func=cmd_auth)

    sp = sub.add_parser('session', help='reprend depuis un code (si le serveur localhost a échoué)')
    sp.add_argument('code')
    sp.add_argument('--history', type=int, default=720)
    sp.set_defaults(func=cmd_session)

    sp = sub.add_parser('pull', help='re-tire les opérations d\'une session déjà autorisée')
    sp.add_argument('--session-id')
    sp.add_argument('--days', type=int, default=90, help='profondeur (jours) — 90 par défaut (limite ASPSP)')
    sp.add_argument('--strategy', default=None, help="'longest' pour tenter tout l'historique (fenêtre ~1 h après SCA)")
    sp.set_defaults(func=cmd_pull)

    sp = sub.add_parser('import', help='fusionne les candidats dans operations.jsonl')
    sp.add_argument('--apply', action='store_true', help='écrit réellement (sinon dry-run)')
    sp.set_defaults(func=cmd_import)

    args = p.parse_args()
    try:
        args.func(args)
    except EnableApiError as e:
        detail = json.dumps(e.payload, indent=2, ensure_ascii=False) if isinstance(e.payload, dict) else str(e.payload)
        sys.exit(f"{e}\n{detail}")


if __name__ == '__main__':
    main()
