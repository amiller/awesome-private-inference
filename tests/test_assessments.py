"""Assessment status must not be inferred from adapter success or provider grouping."""
import copy
import json
from pathlib import Path

import pytest

from probes.assessments import AXES, build, collection, rollup, validate


def definition(route='one', state='unknown'):
    return {'id': route, 'label': route, 'reviewed_at': '2026-10-14',
            'source_revision': 'a' * 40, 'sources': ['providers/example.md'], 'reviewer': 'test source review',
            'axes': {a: {'state': state, 'reason': 'Specific scoped evidence or absence.'} for a in AXES}}


def card(route='one'):
    return {'id': route, 'provider': 'test', 'title': route, 'matched_rows': [
        {'route_id': 'test/model', 'checked_at': '2026-10-14T01:00:00Z', 'outcome': 'verified', 'checked_count': 3}]}


def data(*routes):
    return {'rubric_version': 1, 'routes': list(routes), 'reference_baselines': {}}


def test_group_never_selects_best_route_or_drops_unknown():
    assert rollup([{'state': 'partial'}, {'state': 'gap'}]) == 'varies'
    assert rollup([{'state': 'established'}, {'state': 'unknown'}]) == 'varies'
    assert rollup([{'state': 'unknown'}, {'state': 'unknown'}]) == 'unknown'
    groups = build(data(definition('one','gap'),definition('two','partial')), [card(),card('two')], {}, '2026-10-14T02:00:00Z')
    assert groups[0]['axes']['session']['state'] == 'varies'
    assert groups[0]['collection'] == '1/1 returned'  # aliases are deduplicated
    assert len(groups[0]['routes']) == 2


def test_adapter_pass_never_promotes_unreviewed_route():
    group = build(data(), [card()], {}, '2026-10-14T02:00:00Z')[0]
    assert all(c['state'] == 'unknown' for c in group['axes'].values())
    assert group['reviewed_at'] == 'Unreviewed'


def test_reference_difference_flags_review_without_rewriting_assessment():
    d = data(definition(state='partial'))
    d['reference_baselines'] = {'test': {'lane': ['approved-a']}}
    h = {'lanes': [{'id': 'lane', 'provider': 'test', 'latest': ['unreviewed-b']}],
         'events': [{'provider': 'test', 'kind': 'new set', 'at': '2026-10-15T01:00:00Z'}]}
    before = copy.deepcopy(d)
    g = build(d, [card()], h, '2026-10-14T02:00:00Z')[0]
    assert g['changed_surfaces'] == 1
    assert all(c['state'] == 'partial' for c in g['axes'].values())
    assert d == before
    h['lanes'][0]['latest'] = ['approved-a']
    assert build(d,[card()],h,'2026-10-14T02:00:00Z')[0]['changed_surfaces'] == 0


def test_collection_is_distinct_from_proof_failure_and_missing_evidence():
    rows = card()['matched_rows']
    rows[0]['outcome'] = 'rejected'
    assert collection(rows, '2026-10-14T02:00:00Z') == '1/1 returned'
    rows[0]['outcome'] = 'unavailable'
    assert collection(rows, '2026-10-14T02:00:00Z') == 'Unavailable'
    rows[0].update(outcome='not_checked', checked_count=0)
    assert collection(rows, '2026-10-14T02:00:00Z') == 'Not established'
    assert collection(rows, '2026-10-17T02:00:00Z') == 'Stale / mixed'
    assert collection([], '2026-10-14T02:00:00Z') == 'Not sampled'


def test_established_requires_explicit_proof_records():
    with pytest.raises(ValueError, match='proof records'):
        validate(data(definition(state='established')))
    r=definition();del r['axes']['hardware']
    with pytest.raises(ValueError,match='all six'):
        validate(data(r))


def test_reviewed_routes_have_exact_sources_and_keep_known_distinctions():
    root = Path(__file__).resolve().parents[1]
    d = json.loads((root/'data/assessments/routes.json').read_text())
    validate(d)
    routes = {r['id']:r for r in d['routes']}
    assert set(routes) == {r['id'] for r in json.loads((root/'data/routes.json').read_text())['routes']}
    for r in routes.values():
        for p in r['sources']:
            assert (root/p).is_file()
    assert routes['near-ai-gateway-e2ee']['axes']['session']['state'] == 'gap'
    assert routes['near-ai-direct']['axes']['session']['state'] == 'unknown'
    assert routes['tinfoil-router']['axes']['hardware']['state'] == 'unknown'
    assert routes['privatemode-proxy-auto']['axes']['updates']['state'] != routes['privatemode-proxy-pinned']['axes']['updates']['state']


def test_external_model_text_is_escaped_in_measurements(tmp_path, monkeypatch):
    from probes import render
    monkeypatch.setattr(render, 'REPO_ROOT', tmp_path)
    monkeypatch.setattr(render, 'ROUTES_PATH', tmp_path/'routes.json')
    monkeypatch.setattr(render, 'REFERENCES_PATH', tmp_path/'references.json')
    monkeypatch.setattr(render, 'DOCS_DIR', tmp_path/'docs')
    model = '<script>alert("provider")</script>'
    render._render({'attestations': {'test': [{'model':model,'scorecard':{},'outcome':'not_checked'}]}})
    page=(tmp_path/'docs/measurements.html').read_text()
    assert model not in page
    assert '&lt;script&gt;' in page
