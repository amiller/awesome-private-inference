import datetime as dt
from probes.health import check

NOW = dt.datetime(2026, 10, 14, 12, tzinfo=dt.timezone.utc)
FRESH = {"generated_at": NOW.isoformat(), "attestations": {}}


def test_missing_collection_does_not_hide_dead_review_worker():
    result = check(None, {"jobs": [{"event_id": "event-123", "status": "running",
                                   "lease_until": "2026-10-14T11:00:00Z",
                                   "lease_expired": False}]}, now=NOW)
    assert {r["kind"] for r in result} == {
        "missing_collection", "stale_review_heartbeat", "expired_review_lease"}


def test_new_collection_does_not_refresh_unobserved_route():
    data = FRESH | {"attestations": {"near-ai": [{"model": "a", "freshness": {
        "last_attempt_at": "2026-10-12T12:00:00Z"}}]}}
    assert [r["kind"] for r in check(data, now=NOW)] == ["stale_route"]


def test_invalid_and_future_timestamps_fail_closed():
    for value in ("bad", "2026-10-14T12:00:00", "2026-10-20T12:00:00Z"):
        assert check(FRESH | {"generated_at": value}, now=NOW)[0]["kind"] == "stale_collection"


def test_fresh_observation_and_unexpired_lease():
    queue = {"generated_at": NOW.isoformat(), "jobs": [{"event_id": "event-123",
        "status": "running", "lease_until": "2026-10-14T13:00:00Z"}]}
    assert check(FRESH, queue, now=NOW) == []


def test_fresh_failed_reference_attempt_is_not_healthy():
    refs = {"observations": [{"source_id": "maple", "status": "error",
        "kind": "pcr_publication", "observed_at": NOW.isoformat()}],
        "mirror_agreements": {"prod": False}}
    assert {r["kind"] for r in check(FRESH, references=refs, now=NOW)} == {
        "reference_capture_unhealthy", "reference_mirror_mismatch"}


def test_weekly_catalog_and_daily_reference_have_distinct_deadlines():
    old = "2026-10-12T12:00:00Z"
    refs = {"observations": [
        {"source_id": "catalog", "kind": "model_catalog", "status": "observed", "observed_at": old},
        {"source_id": "policy", "kind": "pcr_publication", "status": "observed", "observed_at": old}]}
    assert [r["source_id"] for r in check(FRESH, references=refs, now=NOW)] == ["policy"]
