"""Curated implementation metadata and a read-only reference observation export.

Neither directory inclusion nor exporting a value creates an acceptance policy.
"""
from __future__ import annotations

from datetime import date
import re


def validate(catalog: dict, routes: dict) -> None:
    if catalog.get('schema_version') != 1:
        raise ValueError('unsupported verifier directory schema')
    if not re.fullmatch(r'[a-f0-9]{40}', catalog.get('source_revision', '')):
        raise ValueError('directory evidence must pin a full source revision')
    inventory = {r['id']: r['provider'] for r in routes['routes']}
    seen = set()
    covered = set()
    for item in catalog['providers']:
        if item['provider'] in seen:
            raise ValueError('duplicate directory provider')
        seen.add(item['provider'])
        date.fromisoformat(item['reviewed_at'])
        for key in ('implementations', 'checks', 'delegates', 'unchecked', 'evidence', 'route_ids'):
            if not item.get(key):
                raise ValueError(f'directory entry requires {key}')
        for route in item['route_ids']:
            if inventory.get(route) != item['provider']:
                raise ValueError('directory route/provider mismatch')
            covered.add(route)
    if covered != set(inventory):
        raise ValueError('every inventory route needs directory coverage, including missing verifiers')


def reference_export(history: dict) -> dict:
    """Preserve context and raw field semantics; unknown authority stays unknown.

    `latest` means latest retained sample of this surface, not current deployment.
    Source extraction has not authenticated all detached reported measurements.
    """
    return {
        'schema_version': 1,
        'kind': 'reference-observations',
        'policy': 'Read-only observations. Never use this feed as a client allowlist.',
        'evidence_base': 'https://github.com/amiller/awesome-private-inference/blob/main/',
        'first_observed_at': min((lane['first'] for lane in history['lanes']), default=None),
        'last_observed_at': max((lane['last'] for lane in history['lanes']), default=None),
        'limits': history['limits'] + [
            'Provider authorization and client acceptance are not established by this export.',
            'Review records have their own scope and dates; they are not client approvals.',
            'Values retain source field syntax, including JSON paths; no common hash algorithm is implied.',
        ],
        'surfaces': [{**lane, 'provider_authorization': None, 'client_acceptance': None}
                     for lane in history['lanes']],
        'events': history['events'],
        'reviews': history['reviews'],
        'inventory_providers': history['inventory_providers'],
    }
