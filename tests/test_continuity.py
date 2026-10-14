"""Changes link exact attempts and preserve uncertainty about observed values."""
import pytest

from probes import continuity, observations
from tests.replay_cases import CASES, evaluate


def capture(tmp_path, at, digest_value, *, valid=True, audited=True, nonce=True):
    run = observations.start_run(tmp_path, {"aci-gateway": ["tee.redpill.ai"]},
                                 captured_at=at, verifier_revision="rev1",
                                 policy_revisions={"aci-gateway": "policy1"})
    row = {"provider": "aci-gateway", "model": "tee.redpill.ai", "valid": valid,
           "verified_at": at, "attestation_type": "aci-gateway",
           "scorecard": {"nonce_bound": nonce},
           "details": {"compose_hash": digest_value,
                       "policy_decisions": {"approved": audited}}, "error": None}
    result = observations.finish_attempt(tmp_path, run, "aci-gateway", "tee.redpill.ai", row)
    observations.finish_run(tmp_path, run)
    return result


def test_identity_revisit_policy_and_cell_changes(tmp_path):
    a = capture(tmp_path, "2026-10-11T00:00:00Z", "a" * 64)
    b = capture(tmp_path, "2026-10-12T00:00:00Z", "b" * 64, audited=False, nonce=False)
    c = capture(tmp_path, "2026-10-13T00:00:00Z", "a" * 64, nonce=True)
    events = continuity.derive_events([a, b, c])
    kinds = [e["kind"] for e in events]
    assert kinds.count("identity_new") == 2
    assert "identity_revisited" in kinds
    assert "policy_mismatch" in kinds
    assert "cell_changed" in kinds
    changed = next(e for e in events if e["kind"] == "identity_revisited")
    assert changed["old_observation_id"] == b["observation_id"]
    assert changed["new_observation_id"] == c["observation_id"]
    assert changed["new_observation_path"] == f"observations/records/{c['observation_id']}.json"
    assert (tmp_path / changed["new_observation_path"]).exists()
    assert changed["uncertainty"] is None
    assert len(continuity.persist_events(tmp_path, events)) == len(events)
    assert continuity.persist_events(tmp_path, events) == []
    assert len(continuity.load_events(tmp_path)) == len(events)


def test_untrusted_value_and_coverage_recovery(tmp_path):
    a = capture(tmp_path, "2026-10-11T00:00:00Z", "a" * 64)
    b = capture(tmp_path, "2026-10-12T00:00:00Z", "x" * 64, valid=False)
    c = capture(tmp_path, "2026-10-13T00:00:00Z", "a" * 64)
    events = continuity.derive_events([a, b, c])
    kinds = [e["kind"] for e in events]
    assert "verification_rejected" in kinds
    assert "verification_restored" in kinds
    assert "untrusted_identity_reported" in kinds
    assert all(e["new_value"] != "x" * 64 for e in events if e["kind"] == "identity_new")


def test_aci_keyset_is_shared_component_and_stable_event_id(tmp_path):
    run = observations.start_run(tmp_path, {"aci-gateway": ["tee.redpill.ai", "api.redpill.ai"]})
    for model in run["requested_models"]["aci-gateway"]:
        observations.finish_attempt(tmp_path, run, "aci-gateway", model, {
            "provider": "aci-gateway", "model": model, "valid": True,
            "attestation_type": "aci-gateway", "scorecard": {},
            "details": {"workload_keyset_digest": "sha256:" + "f" * 64}, "error": None})
    observations.finish_run(tmp_path, run)
    rows = observations.load_observations(tmp_path)
    first = continuity.derive_events(rows)
    second = continuity.derive_events(list(reversed(rows)))
    assert [e["event_id"] for e in first] == [e["event_id"] for e in second]
    assert {e["route_id"] for e in first if e["field"] == "workload_keyset_digest"} == {
        "aci-gateway/tee.redpill.ai", "aci-gateway/api.redpill.ai"}
    assert all(set(e["affected_routes"]) == {"aci-gateway/tee.redpill.ai", "aci-gateway/api.redpill.ai"}
               for e in first if e["field"] == "workload_keyset_digest")


def test_missing_evidence_and_declared_retirement_are_distinct(tmp_path):
    a = capture(tmp_path, "2026-10-11T00:00:00Z", "a" * 64)
    run = observations.start_run(tmp_path, {"aci-gateway": ["tee.redpill.ai"]},
                                 captured_at="2026-10-12T00:00:00Z")
    missing = observations.finish_attempt(tmp_path, run, "aci-gateway", "tee.redpill.ai", None,
                                          captured_at="2026-10-12T00:00:01Z")
    observations.finish_run(tmp_path, run)
    retired = observations.record_retirement(tmp_path, "aci-gateway", "tee.redpill.ai",
                                             retired_at="2026-10-13T00:00:00Z")
    events = continuity.derive_events([a, missing, retired])
    assert "coverage_lost" in {e["kind"] for e in events}
    assert "route_retired" in {e["kind"] for e in events}
    assert all(e["new_observation_id"] == retired["observation_id"]
               for e in events if e["kind"] == "route_retired")


def test_legacy_baseline_does_not_create_review_backlog(tmp_path):
    old = capture(tmp_path, "2026-10-11T00:00:00Z", "a" * 64)
    old["legacy"] = True
    new = capture(tmp_path, "2026-10-12T00:00:00Z", "a" * 64)
    assert not any(e["kind"] == "identity_new" for e in continuity.derive_events([old, new]))
    changed = capture(tmp_path, "2026-10-13T00:00:00Z", "b" * 64)
    assert any(e["kind"] == "identity_new" and e["new_observation_id"] == changed["observation_id"]
               for e in continuity.derive_events([old, new, changed]))


@pytest.mark.parametrize("case", CASES, ids=[case["name"] for case in CASES])
def test_labeled_replay_case(case):
    result = evaluate(case)
    assert result["passed"], result
