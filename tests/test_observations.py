"""Durability and scope of the observation store."""
import json
import sys
import pytest

from probes import observations, collect


def report(provider, model, valid=True, **details):
    return {"provider": provider, "model": model, "valid": valid,
            "verified_at": "2026-10-13T12:00:01Z", "attestation_type": provider,
            "scorecard": {"nonce_bound": valid}, "details": details, "error": None}


def test_attempt_is_persisted_before_result_and_cannot_be_rewritten(tmp_path):
    run = observations.start_run(tmp_path, {"aci-gateway": ["tee.redpill.ai"]},
                                 captured_at="2026-10-13T12:00:00Z")
    attempt = next((tmp_path / "observations" / "attempts").glob("*/*.json"))
    assert json.loads(attempt.read_text())["reason"] == "pending"
    with pytest.raises(ValueError, match="pending attempts"):
        observations.finish_run(tmp_path, run)
    row = report("aci-gateway", "tee.redpill.ai", compose_hash="a" * 64)
    first = observations.finish_attempt(tmp_path, run, "aci-gateway", "tee.redpill.ai", row)
    assert first["evidence"]["adapter_report_sha256"] == observations.digest(row)
    assert first["identities"][0]["component_id"] == "aci-gateway/shared-workload"
    try:
        observations.finish_attempt(tmp_path, run, "aci-gateway", "tee.redpill.ai", row)
    except FileExistsError:
        pass
    else:
        assert False, "result overwrite should fail"


def test_two_same_day_runs_and_partial_preserve_other_routes(tmp_path):
    all_routes = {"aci-gateway": ["tee.redpill.ai"], "near-ai": ["model-x"]}
    first = observations.start_run(tmp_path, all_routes, captured_at="2026-10-13T10:00:00Z")
    observations.finish_attempt(tmp_path, first, "aci-gateway", "tee.redpill.ai",
                                report("aci-gateway", "tee.redpill.ai", compose_hash="a" * 64),
                                captured_at="2026-10-13T10:00:01Z")
    observations.finish_attempt(tmp_path, first, "near-ai", "model-x",
                                report("near-ai", "model-x", gateway_compose_hash="b" * 64),
                                captured_at="2026-10-13T10:00:02Z")
    observations.finish_run(tmp_path, first)
    second = observations.start_run(tmp_path, {"aci-gateway": ["tee.redpill.ai"]},
                                    complete=False, captured_at="2026-10-13T11:00:00Z")
    observations.finish_attempt(tmp_path, second, "aci-gateway", "tee.redpill.ai",
                                report("aci-gateway", "tee.redpill.ai", compose_hash="c" * 64),
                                captured_at="2026-10-13T11:00:01Z")
    observations.finish_run(tmp_path, second)
    assert len(observations.load_observations(tmp_path)) == 3
    latest = observations.derive_latest(tmp_path)
    assert len(latest["attestations"]["near-ai"]) == 1
    assert latest["attestations"]["near-ai"][0]["observation_id"].startswith(first["run_id"])
    aci = latest["attestations"]["aci-gateway"][0]
    assert aci["details"]["compose_hash"] == "c" * 64
    assert aci["freshness"]["last_attempt_at"] == "2026-10-13T11:00:01Z"
    assert latest["view_completeness"] == "partial"


def test_missing_report_and_removed_catalog_route_remain_explicit(tmp_path):
    first = observations.start_run(tmp_path, {"near-ai": ["old"]},
                                   captured_at="2026-10-12T10:00:00Z")
    observations.finish_attempt(tmp_path, first, "near-ai", "old",
                                report("near-ai", "old"), captured_at="2026-10-12T10:00:01Z")
    observations.finish_run(tmp_path, first)
    second = observations.start_run(tmp_path, {"near-ai": ["new"]},
                                    captured_at="2026-10-13T10:00:00Z")
    observations.finish_attempt(tmp_path, second, "near-ai", "new", None)
    observations.finish_run(tmp_path, second)
    latest = observations.derive_latest(tmp_path)
    rows = {r["model"]: r for r in latest["attestations"]["near-ai"]}
    assert rows["old"]["row_status"] == "missing"
    assert rows["old"]["outcome_reason"] == "not_in_catalog"
    assert rows["new"]["outcome"] == "unavailable"
    assert rows["new"]["outcome_reason"] == "missing_response"


def test_backfill_is_idempotent_and_labels_legacy(tmp_path):
    folder = tmp_path / "snapshots"
    folder.mkdir()
    snapshot = {"generated_at": "2026-01-01T00:00:00Z", "git_sha": "old",
                "attestations": {"near-ai": [report("near-ai", "old")]}}
    (folder / "2026-01-01.json").write_text(json.dumps(snapshot))
    assert observations.backfill_snapshots(tmp_path) == 1
    assert observations.backfill_snapshots(tmp_path) == 0
    stored = json.loads(next((tmp_path / "observations" / "records").glob("*/*.json")).read_text())
    assert stored["evidence"]["adapter_report"] is None
    assert stored["evidence"]["adapter_report_ref"]["path"] == "snapshots/2026-01-01.json"
    obs = observations.load_observations(tmp_path)[0]
    assert obs["legacy"] is True
    assert obs["reason"] == "legacy_adapter_result"
    assert obs["identity_trust"] == "legacy_adapter_result"
    assert obs["evidence"]["raw_evidence_status"] == "not_captured_by_adapter"


def test_explicit_retirement_is_visible_and_distinct_from_catalog_omission(tmp_path):
    initial = observations.start_run(tmp_path, {"near-ai": ["old"]},
                                     captured_at="2026-10-12T10:00:00Z")
    observations.finish_attempt(tmp_path, initial, "near-ai", "old",
                                report("near-ai", "old"),
                                captured_at="2026-10-12T10:00:01Z")
    observations.finish_run(tmp_path, initial)
    retired = observations.record_retirement(tmp_path, "near-ai", "old",
                                             retired_at="2026-10-13T10:00:00Z")
    latest = observations.derive_latest(tmp_path)
    row = latest["attestations"]["near-ai"][0]
    assert row["row_status"] == "retired"
    assert row["outcome"] == "not_applicable"
    assert row["observation_id"] == retired["observation_id"]


def test_declared_incomplete_verification_is_not_a_rejection(tmp_path):
    run = observations.start_run(tmp_path, {"near-ai": ["model-x"]})
    row = report("near-ai", "model-x", valid=False)
    row["details"]["verification_status"] = "not_checked"
    row["details"]["verification_reason"] = "live signature chain was not checked"
    result = observations.finish_attempt(tmp_path, run, "near-ai", "model-x", row)
    assert result["outcome"] == "not_checked"
    assert result["reason"] == "verification_incomplete"
    assert result["reason_detail"] == "live signature chain was not checked"


def test_seed_current_preserves_unprobed_provider_without_history_backfill(tmp_path):
    snapshot = {"generated_at": "2026-10-12T10:00:00Z", "git_sha": "old",
                "attestations": {"aci-gateway": [report("aci-gateway", "tee.redpill.ai")],
                                 "near-ai": [report("near-ai", "model-x")]}}
    for rows in snapshot["attestations"].values():
        rows[0]["verified_at"] = "2026-10-12T10:00:01Z"
    (tmp_path / "latest.json").write_text(json.dumps(snapshot))
    assert observations.seed_current(tmp_path)
    assert not observations.seed_current(tmp_path)
    run = observations.start_run(tmp_path, {"near-ai": ["model-x"]}, complete=False,
                                 captured_at="2026-10-13T10:00:00Z")
    observations.finish_attempt(tmp_path, run, "near-ai", "model-x", None,
                                captured_at="2026-10-13T10:00:01Z")
    observations.finish_run(tmp_path, run)
    latest = observations.derive_latest(tmp_path)
    assert latest["attestations"]["aci-gateway"][0]["row_status"] == "current"
    assert latest["attestations"]["near-ai"][0]["outcome"] == "unavailable"


def test_raw_evidence_is_content_addressed_and_not_copied_into_view(tmp_path):
    run = observations.start_run(tmp_path, {"aci-gateway": ["tee.redpill.ai"]})
    row = report("aci-gateway", "tee.redpill.ai")
    row["details"]["raw_evidence"] = {"quote": "public quote bytes", "nonce": "n1"}
    result = observations.finish_attempt(tmp_path, run, "aci-gateway", "tee.redpill.ai", row)
    observations.finish_run(tmp_path, run)
    ref = result["evidence"]["raw_evidence_ref"]
    assert result["evidence"]["raw_evidence_status"] == "stored_separately"
    assert json.loads((tmp_path / ref).read_text()) == row["details"]["raw_evidence"]
    assert "raw_evidence" not in result["evidence"]["adapter_report"]["details"]
    assert observations.resolve_report(tmp_path, result) == row
    latest = observations.derive_latest(tmp_path)
    assert latest["attestations"]["aci-gateway"][0]["details"]["raw_evidence_ref"] == ref
    (tmp_path / ref).write_text(json.dumps({"quote": "altered"}))
    with pytest.raises(ValueError, match="raw evidence digest mismatch"):
        observations.resolve_report(tmp_path, result)


def test_collector_same_day_full_and_targeted_runs_keep_first_snapshot(tmp_path, monkeypatch):
    monkeypatch.setattr(collect.instrument, "capture", lambda *_: {
        "revision": "test-instrument", "repository_commit": "test-commit",
        "upstream_actual_revision": "test-upstream", "upstream_expected_revision": "test-upstream"})
    monkeypatch.setattr(collect, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(collect, "SNAPSHOT_DIR", tmp_path / "data" / "snapshots")
    monkeypatch.setattr(collect.catalog, "MODELS", {"aci-gateway": ["host"], "near-ai": ["model"]})
    monkeypatch.setattr(collect.attestation, "PROVIDERS", {"aci-gateway": object(), "near-ai": object()})
    counter = {"aci-gateway": 0, "near-ai": 0}

    class FakeReport:
        valid = True

        def __init__(self, provider, model, version):
            self.provider, self.model, self.version = provider, model, version

        def as_dict(self):
            value = report(self.provider, self.model, version=self.version)
            value["verified_at"] = observations.utc_now()
            value["details"]["raw_evidence"] = {"quote": f"quote-{self.provider}-{self.version}"}
            return value

    def probe(provider, models):
        counter[provider] += 1
        return [FakeReport(provider, model, counter[provider]) for model in models]

    monkeypatch.setattr(collect.attestation, "probe_provider", probe)
    monkeypatch.setattr(sys, "argv", ["collect", "--providers", "aci-gateway,near-ai"])
    assert collect.main() == 0
    snapshot_path = next((tmp_path / "data" / "snapshots").glob("*.json"))
    original = snapshot_path.read_bytes()
    assert b'"raw_evidence"' not in original
    assert b'"raw_evidence_ref"' in original
    assert collect.main() == 0
    assert snapshot_path.read_bytes() == original
    monkeypatch.setattr(sys, "argv", ["collect", "--providers", "aci-gateway"])
    assert collect.main() == 0
    data = tmp_path / "data"
    latest = json.loads((data / "latest.json").read_text())
    assert latest["attestations"]["aci-gateway"][0]["details"]["version"] == 3
    assert latest["attestations"]["near-ai"][0]["details"]["version"] == 2
    assert len(observations.load_observations(data)) == 5
    assert len(list((data / "snapshots").glob("*.json"))) == 1


def test_freshness_clocks_do_not_promote_adapter_pass_to_crypto_proof(tmp_path):
    run = observations.start_run(tmp_path, {"near-ai": ["model-x"]},
                                 captured_at="2026-10-13T10:00:00Z")
    observations.finish_attempt(tmp_path, run, "near-ai", "model-x",
                                report("near-ai", "model-x"),
                                captured_at="2026-10-13T10:00:01Z")
    observations.finish_run(tmp_path, run)
    decisions = tmp_path / "reviews" / "decisions"
    decisions.mkdir(parents=True)
    (decisions / "one.json").write_text(json.dumps({
        "event": {"route_id": "near-ai/model-x"},
        "review": {"at": "2026-10-14T09:00:00Z", "disposition": "needs_evidence"}}))
    clocks = observations.derive_latest(tmp_path)["attestations"]["near-ai"][0]["freshness"]
    assert clocks["last_attempt_at"] == "2026-10-13T10:00:01Z"
    assert clocks["last_adapter_verified_at"] == "2026-10-13T10:00:01Z"
    assert clocks["last_cryptographic_verification_at"] is None
    assert clocks["last_triage_at"] == "2026-10-14T09:00:00Z"
    assert clocks["last_policy_review_at"] is None
