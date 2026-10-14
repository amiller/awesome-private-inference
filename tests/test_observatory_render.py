"""Route/evidence presentation must not turn publication or adapter booleans into proof."""
import json
import hashlib

import pytest

from probes import render


def _quality():
    return {"calibration": {"observations": 2, "transport": 1, "no-error-invalid": 0},
            "window": {"days": 2}, "cadence": []}


def test_publication_and_adapter_pass_remain_scoped(tmp_path, monkeypatch):
    data = tmp_path / "data"
    (data / "references/events").mkdir(parents=True)
    (data / "references/events/e.json").write_text(json.dumps({
        "event_id": "e", "kind": "reference_mismatch", "route_id": "publication/pcr",
        "timestamp": "2026-10-14T01:00:00Z", "previous_sha256": "a" * 64,
        "current_sha256": "b" * 64, "priority": "high"}))
    routes = {"as_of": "2026-10-14", "routes": [
        {"id": "observed", "provider": "test", "title": "Observed path", "client_mode": "browser", "protocol": "HTTPS",
         "plaintext_holders": ["gateway"], "acceptance": "Client policy unverified", "evidence_status": "partial",
         "observation_aliases": ["test/model"], "sources": ["providers/test.md"], "blockers": ["key binding"], "next_action": "Check key"},
        {"id": "missing", "provider": "candidate", "title": "Candidate path", "client_mode": "browser", "protocol": "HTTPS",
         "plaintext_holders": ["worker"], "acceptance": "No client pin", "evidence_status": "candidate_unverified",
         "observation_aliases": [], "sources": ["https://example.test/source"], "blockers": ["quote"], "next_action": "Get quote"},
    ]}
    refs = {"summaries": {"candidate": {"observed": 1, "error": 0}},
            "mirror_agreements": {"pcrProd.json": True},
            "observations": [{"source_id": "pcr", "provider": "candidate", "url": "https://example.test/pcr",
                              "status": "observed", "observed_at": "2026-10-14T01:00:00Z", "sha256": "a" * 64,
                              "verification": "not_performed"}]}
    routes_path = data / "routes.json"
    refs_path = data / "references/latest.json"
    raw = data / "references/observations/raw/pcr.bin"
    raw.parent.mkdir(parents=True)
    raw.write_bytes(b"published exact bytes")
    digest = hashlib.sha256(raw.read_bytes()).hexdigest()
    refs["observations"][0].update(raw_base="data/references/observations", raw_path="raw/pcr.bin", sha256=digest)
    routes_path.write_text(json.dumps(routes))
    refs_path.write_text(json.dumps(refs))
    monkeypatch.setattr(render, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(render, "ROUTES_PATH", routes_path)
    monkeypatch.setattr(render, "REFERENCES_PATH", refs_path)
    monkeypatch.setattr(render, "DOCS_DIR", tmp_path / "docs")
    monkeypatch.setattr(render, "compute_quality", lambda snapshot: _quality())
    render._render({"attestations": {"test": [{"model": "model", "valid": True,
                    "attestation_type": "test", "scorecard": {"tdx_verified": True}}]}, "pricing": {}})
    home = (tmp_path / "docs/index.html").read_text()
    assert 'class="assessment-table"' in home
    assert "test" in home and "candidate" in home
    assert "Unreviewed" in home
    measurements = (tmp_path / "docs/measurements.html").read_text()
    assert "./evidence.html#observation-1" in measurements
    assert "Who can see plaintext?" not in home
    assert "./history.html" in home
    assert "reference_mismatch" not in home
    assert "Change timeline" not in home
    html = (tmp_path / "docs/evidence.html").read_text()
    assert "reference_mismatch" in html
    assert "Client policy unverified" in html
    assert "No matched request observation" in html
    assert "publication only" in html
    assert "Legacy adapter accepted" in html
    assert "TEE-verified" not in html
    assert "every layer" not in html.lower()
    assert "not full provider verdicts" in html
    assert f"./evidence/pcr-{digest}.bin" in html
    assert (tmp_path / "docs/evidence" / f"pcr-{digest}.bin").read_bytes() == b"published exact bytes"
    assert not any(line.rstrip() != line for line in html.splitlines())


def test_render_refuses_corrupted_publication_bytes(tmp_path, monkeypatch):
    monkeypatch.setattr(render, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(render, "DOCS_DIR", tmp_path / "docs")
    raw = tmp_path / "data/references/raw/x.bin"
    raw.parent.mkdir(parents=True)
    raw.write_bytes(b"wrong bytes")
    refs = {"observations": [{"source_id": "x", "status": "observed", "raw_base": "data/references",
                              "raw_path": "raw/x.bin", "sha256": "a" * 64}]}
    with pytest.raises(ValueError, match="hash mismatch"):
        render._publish_reference_archives(refs)


def test_review_attaches_only_to_exact_event(tmp_path, monkeypatch):
    monkeypatch.setattr(render, "REPO_ROOT", tmp_path)
    events = tmp_path / "data/continuity/events"
    decisions = tmp_path / "data/reviews/decisions"
    events.mkdir(parents=True)
    decisions.mkdir(parents=True)
    event = {"event_id": "event-123", "kind": "coverage_lost", "route_id": "a/b"}
    (events / "event-123.json").write_text(json.dumps(event))
    decision = {"event": event, "review": {"disposition": "needs_evidence"},
                "draft": {"summary": "Instrument scope narrowed"}}
    path = decisions / "event-123.json"
    path.write_text(json.dumps(decision))
    assert render._timeline()[0]["draft"]["summary"] == "Instrument scope narrowed"
    decision["event"] = event | {"route_id": "other"}
    path.write_text(json.dumps(decision))
    with pytest.raises(ValueError, match="immutable event"):
        render._timeline()


def test_typed_outcomes_do_not_collapse_into_rejection():
    rows = render._rows({"attestations": {"p": [
        {"model": "a", "outcome": "not_checked", "scorecard": {}},
        {"model": "b", "outcome": "unsupported", "scorecard": {}},
        {"model": "c", "outcome": "unavailable", "scorecard": {}},
        {"model": "d", "outcome": "rejected", "scorecard": {"tdx_verified": False}},
        {"model": "e", "outcome": "not_applicable", "scorecard": {}},
    ]}})
    assert [row["outcome_label"] for row in rows] == [
        "Not checked", "Unsupported", "Unavailable", "Adapter rejected", "Not applicable"]


def test_legacy_boolean_is_labeled_as_legacy_adapter_result():
    rows = render._rows({"attestations": {"p": [
        {"model": "old-pass", "valid": True, "scorecard": {}},
        {"model": "old-fail", "valid": False, "scorecard": {}},
    ]}})
    assert [row["outcome_label"] for row in rows] == ["Legacy adapter rejected", "Legacy adapter accepted"]
    assert all(row["reason"] == "legacy_adapter_result" for row in rows)
    normalized = render._rows({"attestations": {"p": [{"model": "imported", "valid": True,
        "observation_id": "legacy-run/one", "outcome": "verified", "outcome_reason": "legacy_adapter_result",
        "scorecard": {}}]}})
    assert normalized[0]["outcome_label"] == "Legacy adapter accepted"
