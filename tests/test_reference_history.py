import json
from pathlib import Path
from probes.reference_history import build, reference_leaves, text_delta


def snapshot(root, day, models):
    p = root / f'data/snapshots/{day}.json'
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps({'generated_at': day + 'T12:00:00Z', 'attestations': models}))


def test_historical_enclaves_not_folded_into_tinfoil_router(tmp_path):
    snapshot(tmp_path, '2026-01-01', {'tinfoil': [
        {'model': 'router', 'details': {'digest': 'a'*64}},
        {'model': 'llama', 'details': {'digest': 'b'*64}}]})
    data = build(tmp_path)
    assert {l['component'] for l in data['lanes']} == {'tinfoil/router', 'tinfoil/llama'}
    assert all(e['kind'] == 'baseline' and e['text_delta'] is None for e in data['events'])


def test_revisit_and_gap_not_deployment_or_stability(tmp_path):
    for day, value in [('01', 'a'), ('02', 'b'), ('04', 'a')]:
        snapshot(tmp_path, '2026-01-'+day, {'chutes': [{'model': 'm', 'valid': False, 'details': {'mrtd': value*96}}]})
    data=build(tmp_path)
    assert [e['kind'] for e in data['events']] == ['baseline', 'new set', 'revisit']
    assert data['snapshot_gap_days'] == ['2026-01-03']
    assert all(e['code_delta'] is None for e in data['events'])
    assert data['events'][1]['added'] == ['b'*96]
    assert data['events'][1]['removed'] == ['a'*96]


def test_shared_gateway_same_capture_compared_as_set(tmp_path):
    snapshot(tmp_path, '2026-01-01', {'aci-gateway': [
        {'model': 'one', 'details': {'compose_hash': 'a'*64}},
        {'model': 'two', 'details': {'compose_hash': 'b'*64}}]})
    data=build(tmp_path)
    assert len(data['events']) == 1
    assert data['events'][0]['new'] == ['a'*64, 'b'*64]


def test_set_paths_and_reordering_are_preserved():
    assert reference_leaves({'PCR0':'a'*96}) != reference_leaves({'PCR1':'a'*96})
    assert reference_leaves({'refs':['a'*64, 'b'*64]}) == reference_leaves({'refs':['b'*64,'a'*64]})
    assert reference_leaves({'Policies':{'c'*64:{'SANs':['worker']}}}) == ['/Policies/policy-key='+'c'*64]
    assert text_delta('a\nb\n', 'a\nc\nd\n') == {'added':2,'removed':1,'unit':'captured document lines, not deployed code LOC'}


def test_short_ledger_digest_never_matches(tmp_path):
    p=tmp_path/'data/audits/test.json';p.parent.mkdir(parents=True)
    p.write_text(json.dumps({'audits':[{'image_digest':'deadbeef','audited_at':'2026-01-01'},
                                    {'image_digest':'a'*64,'audited_at':'2026-01-02'}]}))
    assert len(build(tmp_path)['reviews']) == 1
