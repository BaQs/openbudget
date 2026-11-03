#!/usr/bin/env python3
"""
Dédoublonnage et enrichissement multi-source pour operations.jsonl.
Format unifié: {date, label, amount, account, categorie, source, sources}

Matching cross-source: abs(montant) exact + même compte + date ±2 jours
Enrichissement: cumul sources, upgrade label (plus long), garder catégorie Linxo.
"""
import json
import os
import re
import tempfile
import unicodedata
from datetime import datetime


def ecrire_atomique(path, contenu):
    """Écrit `contenu` dans `path` atomiquement (fichier temporaire dans le même dossier + renommage)."""
    dossier = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(dir=dossier, prefix='.' + os.path.basename(path) + '.', suffix='.tmp')
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(contenu)
            f.flush()
            os.fsync(f.fileno())
        if os.path.exists(path):
            os.chmod(tmp, os.stat(path).st_mode & 0o777)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise

# Label priority: higher = preferred when longer/more detailed
SOURCE_LABEL_PRIORITY = {
    'paypal': 4,
    'bourso': 3,
    'bourso_export': 3,
    'cic': 2,
    'linxo': 1,
}


def parse_date(date_str):
    return datetime.strptime(date_str, '%Y-%m-%d')


def normalize_label(label):
    """Normalise un libellé pour comparaison."""
    s = label.upper().strip()
    s = unicodedata.normalize('NFD', s)
    s = ''.join(c for c in s if unicodedata.category(c) != 'Mn')
    s = s.replace('.', ' ').replace('-', ' ').replace('_', ' ')
    s = re.sub(r'^CARTE X\d+ ', '', s)   # préfixe carte générique (CARTE X#### …)
    for prefix in ['PRLV SEPA ', 'PRELEVEMENT EUROPEEN ', 'VIR SEPA ', 'VIR RECU ', 'MOTIF: ']:
        if s.startswith(prefix):
            s = s[len(prefix):]
    return s.strip()


def is_duplicate(new_op, existing_ops, day_tolerance=3, amount_tolerance=0.05):
    """
    Vérifie si une op existe déjà (legacy compatibility).
    Critères: même compte, montant ±0.05€, date ±3 jours, libellé similaire.
    """
    new_date = parse_date(new_op['date'])
    new_amount = float(new_op['amount'])
    new_account = new_op['account']
    new_label = normalize_label(new_op['label'])

    for ex in existing_ops:
        ex_account = ex.get('account') or ex.get('compte', '')
        if ex_account != new_account:
            continue
        ex_amount = float(ex.get('amount') or ex.get('montant', 0))
        if abs(new_amount - ex_amount) > amount_tolerance:
            continue
        ex_date = parse_date(ex['date'])
        if abs((new_date - ex_date).days) > day_tolerance:
            continue
        ex_label = normalize_label(ex.get('label') or ex.get('libelle', ''))
        if new_label in ex_label or ex_label in new_label:
            return True
        if abs(new_amount - ex_amount) < 0.01 and new_date == ex_date:
            return True
    return False


def load_operations(path):
    """Charge operations.jsonl, supporte les deux formats (ancien/nouveau)."""
    ops = []
    try:
        with open(path) as f:
            for line in f:
                if line.strip():
                    op = json.loads(line)
                    if 'montant' in op and 'amount' not in op:
                        op['amount'] = op.pop('montant')
                    if 'compte' in op and 'account' not in op:
                        op['account'] = op.pop('compte')
                    if 'libelle' in op and 'label' not in op:
                        op['label'] = op.pop('libelle')
                    ops.append(op)
    except FileNotFoundError:
        pass
    return ops


def inject_ops(ops_path, new_ops, existing_ops=None):
    """
    Legacy: injecte des nouvelles ops avec dédoublonnage simple.
    Retourne la liste des ops ajoutées.
    """
    if existing_ops is None:
        existing_ops = load_operations(ops_path)

    added = []
    with open(ops_path, 'a') as f:
        for op in new_ops:
            if not is_duplicate(op, existing_ops):
                f.write(json.dumps(op, ensure_ascii=False) + '\n')
                existing_ops.append(op)
                added.append(op)
    return added


def _is_generic_paypal(label):
    """Check if label is a generic PayPal label (not a specific merchant)."""
    upper = label.upper()
    return 'PAYPAL' in upper and ('EUROPE' in upper or 'S.A.R.L' in upper)


def _is_paypal_label(label):
    """Check if a label looks like a PayPal transaction."""
    upper = label.upper()
    return 'PAYPAL' in upper or 'ALIEXPRESS' in upper or 'NESPRESSO' in upper


def _comptes_compatibles(a, b):
    """Même compte, ou compte incertain (alerte Bourso multi-comptes) dont les candidats incluent l'autre."""
    if a.get('account') == b.get('account'):
        return True
    return (a.get('account') in (b.get('comptes_possibles') or [])
            or b.get('account') in (a.get('comptes_possibles') or []))


MOTS_VIDES = {'CARTE', 'PRLV', 'SEPA', 'PRELEVEMENT', 'EUROPEEN', 'VIREMENT', 'RECU', 'MOTIF',
              'PAIEMENT', 'COMMERCE', 'ELECTRONIQUE', 'FRANCE', 'VIR', 'DES', 'LES', 'POUR', 'PAR',
              'SUR', 'AUX', 'AVEC', 'CHEZ', 'SAS', 'SARL', 'CIE', 'EUR', 'DAB', 'REF', 'CPTE', 'VIA'}


def _mots(label):
    s = unicodedata.normalize('NFD', (label or '').upper())
    s = ''.join(c for c in s if unicodedata.category(c) != 'Mn')
    return {m for m in re.findall(r'[A-Z]{3,}', s) if m not in MOTS_VIDES}


BOURSO = {'bourso', 'bourso_export'}   # alertes et export CSV : paiements carte datés du jour d'achat


def _sources(op):
    return set(op.get('sources') or [op.get('source')])


def _decalage_carte(cand, ex, ecart):
    """Paiement carte daté du jour par Bourso, et 3-4 jours plus tard par Linxo (date comptable,
    week-end) : même opération si Linxo est après Bourso et que les libellés ont un mot commun."""
    for carte, compta, delta in ((cand, ex, -ecart), (ex, cand, ecart)):   # delta = date Linxo − date carte
        if (_sources(carte) & BOURSO and 'linxo' not in _sources(carte) and not carte.get('date_estimee')
                and 'linxo' in _sources(compta) and not _sources(compta) & BOURSO
                and 0 <= delta <= 4 and _mots(carte.get('label')) & _mots(compta.get('label'))):
            return True
    return False


def _decalage_paypal(cand, ex, ecart):
    """Achat PayPal (compte PayPal ou reçu) et son débit « PayPal Europe » sur le compte bancaire,
    prélevé 0 à 6 jours plus tard : même dépense."""
    for achat, debit, delta in ((cand, ex, -ecart), (ex, cand, ecart)):   # delta = date débit − date achat
        if not (achat.get('paypal_merchant') or achat.get('account') == 'paypal_eu'):
            continue
        if _is_generic_paypal(debit.get('label', '')) and 0 <= delta <= 6:
            return True
        # opération déjà fusionnée avec cet achat (« X (via PayPal) ») : on la reconnaît au marchand
        if debit.get('paypal_merchant') and debit['paypal_merchant'] == achat.get('paypal_merchant') and abs(delta) <= 6:
            return True
    return False


def _nature_ligne(op):
    """Pour un relevé : achat PayPal, débit « PayPal Europe » ou ligne ordinaire."""
    label = op.get('label', '')
    if _is_generic_paypal(label):
        return 'debit_paypal'
    if op.get('paypal_merchant') or op.get('account') == 'paypal_eu' or _is_paypal_label(label):
        return 'achat_paypal'   # dont « AliExpress » ou « X (via PayPal) » : Linxo nomme le marchand
    return 'ligne'


def _find_match(candidate, existing_ops, day_tolerance=2, amount_tolerance=0.01):
    """
    Find a matching existing op for enrichment.
    Match: même montant au centime et même signe (un remboursement n'est pas l'achat) + compte
    compatible + date ±day_tolerance jours (ou décalage carte) ; si les dates diffèrent, les
    libellés doivent avoir un mot commun.
    For PayPal ops: cross-account matching allowed, sans contrôle de libellé (« PayPal Europe »
    d'un côté, le marchand de l'autre).
    Returns the closest matching op or None.
    """
    c_signed = float(candidate['amount'])
    c_amount = abs(c_signed)
    c_account = candidate['account']
    c_label = candidate.get('label', '')
    c_is_paypal = _is_paypal_label(c_label)
    c_nature = _nature_ligne(candidate)
    try:
        c_date = parse_date(candidate['date'])
    except (ValueError, KeyError):
        return None

    best = None
    for ex in existing_ops:
        ex_account = ex.get('account', '')
        ex_label = ex.get('label', '')
        ex_is_paypal = _is_paypal_label(ex_label)

        # PayPal : un débit « PayPal Europe » ne se rapproche que d'un achat PayPal (ou d'un autre
        # débit PayPal), jamais d'un paiement ordinaire d'un autre marchand
        natures = {c_nature, _nature_ligne(ex)}
        paire_paypal = natures == {'achat_paypal', 'debit_paypal'}
        if 'debit_paypal' in natures and 'ligne' in natures:
            continue
        # Account matching: strict unless uncertain (comptes_possibles), paire PayPal, ou libellé
        # PayPal avec un mot commun (Linxo nomme parfois le marchand d'un débit PayPal)
        if not _comptes_compatibles(candidate, ex):
            if not (paire_paypal or ((c_is_paypal or ex_is_paypal) and _mots(c_label) & _mots(ex_label))):
                continue

        ex_signed = float(ex.get('amount', 0))
        if (c_signed < 0) != (ex_signed < 0) or abs(c_amount - abs(ex_signed)) > amount_tolerance:
            continue
        try:
            ex_date = parse_date(ex['date'])
        except (ValueError, KeyError):
            continue
        ecart = (c_date - ex_date).days
        if (abs(ecart) > day_tolerance and not _decalage_carte(candidate, ex, ecart)
                and not _decalage_paypal(candidate, ex, ecart)):
            continue
        if ecart and not paire_paypal and not _mots(c_label) & _mots(ex_label):
            continue   # même montant à un jour d'écart mais autre marchand : autre opération
        if best is None or abs(ecart) < best[0]:   # la plus proche en date, pas la première venue
            best = (abs(ecart), ex)
    return best[1] if best else None


def _pick_best_label(existing_label, existing_source, new_label, new_source):
    """
    Pick the best label based on source priority and length.
    Higher priority source wins; if same priority, longer label wins.
    """
    ex_prio = SOURCE_LABEL_PRIORITY.get(existing_source, 0)
    new_prio = SOURCE_LABEL_PRIORITY.get(new_source, 0)

    if new_prio > ex_prio:
        return new_label
    if new_prio < ex_prio:
        return existing_label
    # Same priority: keep the longer one
    return new_label if len(new_label) > len(existing_label) else existing_label


def _best_label_source(sources_list):
    """Return the source with highest label priority from a list."""
    best = None
    best_prio = -1
    for s in sources_list:
        p = SOURCE_LABEL_PRIORITY.get(s, 0)
        if p > best_prio:
            best_prio = p
            best = s
    return best or (sources_list[0] if sources_list else 'unknown')


def enrichir(match, cand):
    """Fusionne cand dans match (même opération vue par deux sources) : sources, libellé,
    catégorie Linxo, date et compte selon les priorités ci-dessous."""
    cand_source = cand.get('source', 'unknown')
    cand_sources = cand.get('sources') or [cand_source]
    ex_sources = list(match.get('sources') or [match.get('source', 'unknown')])
    autres = [src for src in ex_sources if src not in cand_sources]   # sources propres à match
    ex_sources += [src for src in cand_sources if src not in ex_sources]
    match['sources'] = ex_sources

    # Label: pick best by source priority, then length
    # But never downgrade a specific merchant name to a generic "PayPal Europe" label
    cand_label = cand['label']
    existing_label = match['label']
    if _is_generic_paypal(cand_label) and not _is_generic_paypal(existing_label):
        # Candidate is generic PayPal, existing is specific → keep existing
        pass
    elif _is_generic_paypal(existing_label) and not _is_generic_paypal(cand_label):
        # Existing is generic PayPal, candidate is specific → upgrade
        match['label'] = cand_label
    else:
        ex_label_source = _best_label_source(autres)
        new_label = _pick_best_label(existing_label, ex_label_source, cand_label, cand_source)
        match['label'] = new_label

    # PayPal merchant enrichment
    if cand.get('paypal_merchant'):
        match['paypal_merchant'] = cand['paypal_merchant']
        # If PayPal, override label with merchant name
        match['label'] = f"{cand['paypal_merchant']} (via PayPal)"
    elif match.get('paypal_merchant') and _is_generic_paypal(cand_label):   # débit arrivé après l'achat
        match['label'] = f"{match['paypal_merchant']} (via PayPal)"

    # Category: Linxo category is preferred if present
    if cand_source == 'linxo' and cand.get('categorie_originale'):
        cat_orig = cand['categorie_originale']
        if cat_orig not in ('A catégoriser', 'Virements à catégoriser'):
            match['categorie_originale'] = cat_orig
    # Don't overwrite existing Linxo category with empty one
    if not match.get('categorie_originale') and cand.get('categorie_originale'):
        match['categorie_originale'] = cand['categorie_originale']

    # Date: Bourso has card date (most precise), Linxo has accounting date (often J+1)
    # Rule: Bourso date wins over Linxo date when both exist — sauf date estimée
    # (ligne d'alerte sans date) : elle n'écrase jamais une vraie date, et une vraie la remplace
    DATE_PRIORITY = {'bourso': 3, 'bourso_export': 3, 'cic': 2, 'paypal': 2, 'linxo': 1}
    existing_date_prio = max((DATE_PRIORITY.get(src, 0) for src in autres), default=0)
    cand_date_prio = DATE_PRIORITY.get(cand_source, 0)
    if cand.get('date_estimee'):
        pass
    elif match.get('date_estimee'):
        match['date'] = cand['date']
        del match['date_estimee']
    elif cand_date_prio > existing_date_prio and cand.get('date'):
        match['date'] = cand['date']

    # Compte : un compte certain remplace un compte deviné ; deux incertitudes se recoupent
    if match.get('comptes_possibles'):
        if not cand.get('comptes_possibles'):
            if cand['account'] in match['comptes_possibles']:   # pas un rapprochement PayPal
                match['account'] = cand['account']
                del match['comptes_possibles']
        else:
            communs = [c for c in match['comptes_possibles'] if c in cand['comptes_possibles']]
            if communs:
                match['comptes_possibles'] = communs
                if match['account'] not in communs:
                    match['account'] = communs[0]
                if len(communs) == 1:
                    del match['comptes_possibles']

    match['source'] = ex_sources[0]  # primary source


def merge_and_enrich(existing_ops, candidates, releve=False):
    """
    Multi-source merge with enrichment.

    For each candidate op:
    - If matches an existing op (abs amount exact + same account + date ±2j):
      → enrich: add source, upgrade label if better, keep Linxo category
    - If no match: create new op

    Args:
        existing_ops: list of existing ops (will be modified in-place for enrichment)
        candidates: list of new candidate ops from all sources

        releve: les candidats forment un relevé (export CSV) — chaque opération n'absorbe qu'une
            de ses lignes, sauf la paire achat PayPal + débit « PayPal Europe » (même dépense).

    Returns:
        (added, enriched) — lists of new ops and enriched existing ops
    """
    added = []
    enriched = []
    lignes_du_lot = {}   # id(op) → natures des lignes du relevé déjà fusionnées dedans

    for cand in candidates:
        cand_source = cand.get('source', 'unknown')
        nature = _nature_ligne(cand)
        pool = existing_ops
        if releve:
            complement = {'achat_paypal': {'debit_paypal'}, 'debit_paypal': {'achat_paypal'}}.get(nature, set())
            pool = [e for e in existing_ops
                    if not lignes_du_lot.get(id(e)) or lignes_du_lot[id(e)] <= complement]

        match = _find_match(cand, pool)

        if match is not None:
            enrichir(match, cand)
            lignes_du_lot.setdefault(id(match), set()).add(nature)
            if match not in enriched:
                enriched.append(match)
        else:
            # New op
            new_op = dict(cand)
            new_op.setdefault('sources', [cand_source])
            if cand_source not in new_op['sources']:
                new_op['sources'].append(cand_source)
            existing_ops.append(new_op)
            lignes_du_lot.setdefault(id(new_op), set()).add(nature)
            added.append(new_op)

    return added, enriched


def save_operations(path, ops):
    """Save all operations to JSONL file."""
    ecrire_atomique(path, ''.join(json.dumps(op, ensure_ascii=False) + '\n' for op in ops))
