"""Dated route assessments, independent of live adapter acceptance flags."""
from __future__ import annotations

from datetime import datetime, date
from urllib.parse import urlencode

AXES = {
    'hardware': ('Hardware', 'Is platform evidence authenticated under the relevant hardware and TCB policy?'),
    'session': ('Session', 'Are prompt recipient, reply key and freshness bound to the actual client exchange?'),
    'code': ('Code', 'Does measured workload identity resolve to approved, reproducible source?'),
    'operator': ('Operator access', 'Are operator-controlled inputs and access paths constrained by the approved computation?'),
    'downstream': ('Downstream', 'Are required worker hops and the requested model bound to the verified request?'),
    'updates': ('Updates', 'Can the client reject changes to accepted code until its approval policy authorizes them?'),
}
STATES = {
    'established': ('Established', '✓'), 'partial': ('Partial', '◐'),
    'gap': ('Gap', '×'), 'unknown': ('Unknown', '?'), 'na': ('N/A', '—'),
    'varies': ('Varies', '↕'),
}
NAMES = {'aci-gateway': 'ACI gateway', 'near-ai': 'NEAR AI', 'tinfoil': 'Tinfoil',
         'chutes': 'Chutes', 'venice': 'Venice', 'maple': 'Maple',
         'private-inference': 'Private Inference', 'privatemode': 'Privatemode',
         'confidential-ai': 'Confidential AI'}


def validate(data):
    if data.get('rubric_version') != 1:
        raise ValueError('unsupported assessment rubric')
    seen = set()
    for route in data['routes']:
        if route['id'] in seen:
            raise ValueError('duplicate route assessment')
        seen.add(route['id'])
        if set(route['axes']) != set(AXES):
            raise ValueError('every route needs all six assessment axes')
        if not route.get('reviewed_at') or not route.get('source_revision') or not route.get('sources') or not route.get('reviewer'):
            raise ValueError('assessment needs dated source evidence and an identified reviewer')
        date.fromisoformat(route['reviewed_at'])
        for cell in route['axes'].values():
            if cell['state'] not in STATES or cell['state'] == 'varies' or not cell.get('reason'):
                raise ValueError('invalid assessment state or missing rationale')
            if cell['state'] == 'established' and not cell.get('proof_records'):
                raise ValueError('established requires scoped proof records; adapter booleans are insufficient')


def rollup(cells):
    """Never choose a provider's best route or turn missing review into N/A."""
    states = {c['state'] for c in cells}
    return next(iter(states)) if len(states) == 1 else 'varies'


def collection(rows, as_of):
    if not rows:
        return 'Not sampled'
    try:
        now = datetime.fromisoformat(as_of.replace('Z', '+00:00'))
        dates = [datetime.fromisoformat((r.get('checked_at') or '').replace('Z', '+00:00')) for r in rows]
        if any((now - d).total_seconds() > 48 * 3600 for d in dates):
            return 'Stale / mixed'
    except (ValueError, TypeError):
        return 'Date unknown'
    n = sum(r['outcome'] != 'unavailable' and r.get('checked_count', 0) > 0 for r in rows)
    if not n:
        return 'Unavailable' if all(r['outcome'] == 'unavailable' for r in rows) else 'Not established'
    return f'{n}/{len(rows)} returned'


def build(data, cards, history, as_of):
    validate(data)
    definitions = {r['id']: r for r in data['routes']}
    groups = {}
    for card in cards:
        definition = definitions.get(card['id'])
        if definition is None:
            definition = {'id': card['id'], 'label': card['title'], 'reviewed_at': None,
                          'sources': [], 'source_revision': None,
                          'axes': {a: {'state': 'unknown', 'reason': 'No route assessment has been reviewed.'} for a in AXES}}
        route = {**card, **definition}
        route['collection'] = collection(card['matched_rows'], as_of)
        route['sources_linked'] = [{'label': p, 'url': 'https://github.com/amiller/awesome-private-inference/blob/' + definition['source_revision'] + '/' + p} for p in definition['sources']]
        group = groups.setdefault(card['provider'], {'id': card['provider'], 'name': NAMES.get(card['provider'], card['provider']), 'routes': []})
        group['routes'].append(route)
    for group in groups.values():
        group['axes'] = {a: {'state': rollup([r['axes'][a] for r in group['routes']])} for a in AXES}
        group['varies'] = any(c['state'] == 'varies' for c in group['axes'].values())
        observed = {r['route_id']: r for route in group['routes'] for r in route['matched_rows']}
        group['collection'] = collection(list(observed.values()), as_of)
        group['observations'] = list(observed.values())
        group['reviewed_at'] = min((r['reviewed_at'] or 'Unreviewed' for r in group['routes']), default='Unreviewed')
        group['history_url'] = './history.html?' + urlencode({'provider': group['id']})
        es = [e for e in history.get('events', []) if e['provider'] == group['id']]
        new = [e for e in es if e['kind'] == 'new set']
        group['last_new'] = max((e['at'] for e in new), default=None)
        group['baseline_only'] = bool(es) and not any(e['kind'] != 'baseline' for e in es)
        current = {l['id']: l['latest'] for l in history.get('lanes', []) if l['provider'] == group['id']}
        baseline = data.get('reference_baselines', {}).get(group['id'], {})
        group['changed_surfaces'] = sum(set(v) != set(baseline.get(k, [])) for k, v in current.items())
        group['missing_surfaces'] = len(set(baseline) - set(current))
    return list(groups.values())
