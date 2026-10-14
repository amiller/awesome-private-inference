"""The shared observation feed must never create client authorization."""
import copy
import json
from pathlib import Path

import pytest

from probes.directory import reference_export, validate
from probes.reference_history import build
from verifiers.common import has_required_check_coverage, is_stage1_ready, REQUIRED_LAYERS_BY_SHAPE

ROOT = Path(__file__).resolve().parents[1]


def test_directory_covers_inventory_and_pins_retained_sources():
    catalog = json.loads((ROOT / 'data/verifiers.json').read_text())
    routes = json.loads((ROOT / 'data/routes.json').read_text())
    validate(catalog, routes)
    for item in catalog['providers']:
        paths = item['evidence'] + [i['source'] for i in item['implementations'] if not i['source'].startswith('https://')]
        assert all((ROOT / path).is_file() for path in paths)
    incomplete = copy.deepcopy(catalog)
    incomplete['providers'].pop()
    with pytest.raises(ValueError, match='coverage'):
        validate(incomplete, routes)
    wrong_route = copy.deepcopy(catalog)
    wrong_route['providers'][0]['route_ids'] = [routes['routes'][-1]['id']]
    with pytest.raises(ValueError, match='mismatch'):
        validate(wrong_route, routes)


def test_rejected_new_reference_and_review_cannot_create_acceptance(tmp_path):
    snapshots = tmp_path / 'data/snapshots'
    snapshots.mkdir(parents=True)
    for day, value in [('01', 'a'), ('02', 'b')]:
        (snapshots / f'2026-01-{day}.json').write_text(json.dumps({
            'generated_at': f'2026-01-{day}T00:00:00Z',
            'attestations': {'chutes': [{'model': 'm', 'valid': False, 'details': {'mrtd': value * 96}}]}}))
    audits = tmp_path / 'data/audits'
    audits.mkdir()
    (audits / 'chutes_tee.json').write_text(json.dumps({'audits': [
        {'mrtd': 'b' * 96, 'audited_at': '2026-01-02', 'verdict': 'reviewed'}]}))
    history = build(tmp_path)
    before = copy.deepcopy(history)
    exported = reference_export(history)
    assert history == before
    assert exported == reference_export(build(tmp_path))
    assert [e['kind'] for e in exported['events']] == ['baseline', 'new set']
    assert exported['events'][-1]['reviews']  # Review presence must not grant acceptance.
    surface = exported['surfaces'][0]
    assert surface['latest'] == ['b' * 96]
    assert surface['provider_authorization'] is None
    assert surface['client_acceptance'] is None
    assert 'not independently verified' in surface['scope']
    assert surface['last'] == '2026-01-02T00:00:00Z'


def test_same_digest_keeps_component_scope_and_absence(tmp_path):
    snapshots = tmp_path / 'data/snapshots'
    snapshots.mkdir(parents=True)
    (snapshots / '2026-01-01.json').write_text(json.dumps({
        'attestations': {'tinfoil': [{'model': m, 'details': {'digest': 'a' * 64}} for m in ['router', 'worker']]}}))
    routes = tmp_path / 'data/routes.json'
    routes.write_text(json.dumps({'routes': [{'id': 'missing', 'provider': 'missing-provider'}]}))
    exported = reference_export(build(tmp_path))
    assert {s['component'] for s in exported['surfaces']} == {'tinfoil/router', 'tinfoil/worker'}
    assert len({s['id'] for s in exported['surfaces']}) == 2
    assert 'missing-provider' in exported['inventory_providers']
    assert not any(s['provider'] == 'missing-provider' for s in exported['surfaces'])


def test_coverage_helper_preserves_behavior_without_stage_assignment():
    shape = 'tdx+gpu'
    checks = dict.fromkeys(REQUIRED_LAYERS_BY_SHAPE[shape], True)
    assert has_required_check_coverage(checks, shape)
    assert is_stage1_ready(checks, shape)  # Compatibility only; no stage records written.
    checks[next(iter(checks))] = None
    assert not has_required_check_coverage(checks, shape)
    assert not has_required_check_coverage({}, 'unknown')


def test_export_extent_includes_unchanged_samples(tmp_path):
    snapshots = tmp_path / 'data/snapshots'
    snapshots.mkdir(parents=True)
    for day in ['01', '02']:
        (snapshots / f'2026-01-{day}.json').write_text(json.dumps({
            'generated_at': f'2026-01-{day}T00:00:00Z',
            'attestations': {'chutes': [{'model': 'm', 'details': {'mrtd': 'a' * 96}}]}}))
    exported = reference_export(build(tmp_path))
    assert len(exported['events']) == 1
    assert exported['last_observed_at'] == '2026-01-02T00:00:00Z'
