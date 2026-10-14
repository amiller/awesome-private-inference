import datetime as dt
import json
import pytest
from probes.review_queue import Queue
from probes import review_worker

NOW = dt.datetime(2026, 10, 14, tzinfo=dt.timezone.utc)
EVENT = {"event_id": "chg-1234567890", "kind": "policy_mismatch", "route_id": "near-ai/model", "priority": "high"}


def draft(key=EVENT["event_id"]):
    return {"event_id": key, "summary": "Provider value differs from client policy",
            "classification": "needs_evidence", "evidence": ["https://example.test/evidence"],
            "checks_performed": ["Compared captured full digests"],
            "uncertainties": ["Deployment not independently reproduced"],
            "next_action": "Review the new release before changing policy",
            "plaintext_boundary_impact": "Unknown until source mapping is obtained",
            "acceptance_policy_impact": "Client currently rejects the observed value"}


def test_ingest_idempotent_and_changed_event_refused(tmp_path):
    q = Queue(tmp_path)
    assert q.ingest([EVENT], NOW) == 1
    assert q.ingest([EVENT], NOW) == 0
    with pytest.raises(ValueError, match="changed"):
        q.ingest([EVENT | {"kind": "other"}], NOW)
    assert len(q.summary(NOW)["jobs"]) == 1


def test_launch_crash_retry_and_late_worker_rejected(tmp_path):
    q = Queue(tmp_path)
    q.ingest([EVENT], NOW)
    first = q.claim(worker="sol-1", lease_seconds=10, now=NOW)
    assert q.claim(worker="sol-2", now=NOW) is None
    later = NOW + dt.timedelta(seconds=11)
    assert q.summary(later)["jobs"][0]["lease_expired"]
    assert q.summary(NOW)["jobs"][0]["lease_until"] == "2026-10-14T00:00:10Z"
    second = q.claim(worker="sol-2", now=later)
    assert second["attempts"] == 2
    assert second["lease_token"] != first["lease_token"]
    with pytest.raises(ValueError, match="lease"):
        q.submit(EVENT["event_id"], first["lease_token"], draft(), later)
    q.submit(EVENT["event_id"], second["lease_token"], draft(), later)
    assert q.summary(later)["jobs"][0]["status"] == "draft_ready"


def test_draft_validation_and_review_before_publish(tmp_path):
    q = Queue(tmp_path / "queue")
    q.ingest([EVENT], NOW)
    job = q.claim(worker="sol", now=NOW)
    with pytest.raises(ValueError):
        q.submit(EVENT["event_id"], job["lease_token"], {"summary": "done"}, NOW)
    q.submit(EVENT["event_id"], job["lease_token"], draft(), NOW)
    with pytest.raises(ValueError, match="reviewed"):
        q.publish(EVENT["event_id"], tmp_path / "public", NOW)
    with pytest.raises(ValueError, match="distinct"):
        q.review(EVENT["event_id"], reviewer="sol", disposition="accepted", rationale="same worker", now=NOW)
    q.review(EVENT["event_id"], reviewer="astra", disposition="needs_evidence", rationale="Digest disagreement established; approval pending", now=NOW)
    path = q.publish(EVENT["event_id"], tmp_path / "public", NOW)
    assert json.loads(path.read_text())["review"]["disposition"] == "needs_evidence"
    assert q.publish(EVENT["event_id"], tmp_path / "public", NOW) == path
    assert q.summary(NOW)["jobs"][0]["status"] == "published"
    assert "lease_token" not in json.dumps(q.summary(NOW))


def test_exact_packet_ack_does_not_consume_new_event(tmp_path):
    q = Queue(tmp_path)
    q.ingest([EVENT], NOW)
    job = q.claim(worker="sol", now=NOW)
    other = EVENT | {"event_id": "chg-0987654321"}
    q.ingest([other], NOW)
    q.submit(EVENT["event_id"], job["lease_token"], draft(), NOW)
    states = {j["event_id"]: j["status"] for j in q.summary(NOW)["jobs"]}
    assert states == {EVENT["event_id"]: "draft_ready", other["event_id"]: "queued"}


def test_blocked_is_not_silently_retried(tmp_path):
    q = Queue(tmp_path)
    q.ingest([EVENT], NOW)
    job = q.claim(worker="sol", now=NOW)
    q.fail(EVENT["event_id"], job["lease_token"], "Credential required", blocked=True, now=NOW)
    assert q.claim(worker="sol", now=NOW) is None
    q.requeue(EVENT["event_id"], "Credential now available", NOW)
    assert q.claim(worker="sol", now=NOW)


def test_dispatch_failure_is_retryable_and_preserves_exact_event(tmp_path, monkeypatch):
    state = tmp_path / "queue"
    monkeypatch.setattr(review_worker, "read_events", lambda _data_dir: [EVENT])
    commands = []

    class FailedLaunch:
        returncode = 7
        stdout = ""
        stderr = "dispatch failed"

    def failed_dispatch(command, **_kwargs):
        commands.append(command)
        return FailedLaunch()

    monkeypatch.setattr(review_worker.subprocess, "run", failed_dispatch)
    result = review_worker.main(["--state-dir", str(state), "--data-dir", str(tmp_path),
                                 "--cwd", str(tmp_path)])
    assert result == 7
    assert commands[0][:3] == ["paseo", "run", "-d"]
    assert commands[0][commands[0].index("--model") + 1] == "gpt-6-sol"
    assert commands[0][commands[0].index("--mode") + 1] == "auto"
    queue = Queue(state)
    assert queue.summary()["jobs"][0]["status"] == "retryable_failure"
    retry = queue.claim(worker="second-worker")
    assert retry["event_id"] == EVENT["event_id"]
    assert retry["attempts"] == 2
    assert (state / "packets" / f"{EVENT['event_id']}-1.launch.log").read_text() == "dispatch failed"


def test_draft_requires_resolvable_exact_local_evidence_path(tmp_path):
    q = Queue(tmp_path / "queue", artifact_root=tmp_path)
    q.ingest([EVENT], NOW)
    job = q.claim(worker="sol", now=NOW)
    artifact = tmp_path / "evidence" / "capture.json"
    artifact.parent.mkdir()
    artifact.write_text("{}")
    imprecise = draft() | {"evidence": ["evidence/capture.json (public context only)"]}
    with pytest.raises(ValueError, match="exact existing"):
        q.submit(EVENT["event_id"], job["lease_token"], imprecise, NOW)
    exact = draft() | {"evidence": ["evidence/capture.json"]}
    q.submit(EVENT["event_id"], job["lease_token"], exact, NOW)
    assert q.summary(NOW)["jobs"][0]["status"] == "draft_ready"
