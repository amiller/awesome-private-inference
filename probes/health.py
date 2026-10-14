"""Read-only freshness watchdog; suitable for an independent scheduler."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys
from .review_queue import parse, utcnow, ROOT


def check(data, queue=None, *, references=None, now=None, max_age_hours=26, queue_age_hours=4):
    now = now or utcnow()
    findings = []
    def age(value):
        try:
            timestamp = parse(value)
            if timestamp.tzinfo is None:
                return None
            return (now - timestamp).total_seconds() / 3600
        except (TypeError, ValueError, AttributeError):
            return None

    def stale(value, limit):
        elapsed = age(value)
        return elapsed is None or elapsed < -1 or elapsed > limit

    if not data or not data.get("generated_at"):
        findings.append({"kind": "missing_collection", "reason": "No latest observation view"})
        data = data or {}
    elif stale(data["generated_at"], max_age_hours):
        findings.append({"kind": "stale_collection", "last": data["generated_at"]})
    for provider, rows in data.get("attestations", {}).items():
        for row in rows:
            fresh = row.get("freshness") or {}
            attempted = fresh.get("last_attempt_at") or row.get("verified_at")
            if stale(attempted, max_age_hours):
                findings.append({"kind": "stale_route", "route_id": f"{provider}/{row['model']}", "last": attempted})
    if queue is not None:
        ts = queue.get("generated_at")
        if stale(ts, queue_age_hours):
            findings.append({"kind": "stale_review_heartbeat", "last": ts})
        for job in queue.get("jobs", []):
            deadline_age = age(job.get("lease_until"))
            if job.get("lease_expired") or (job.get("status") == "running" and
                                           (deadline_age is None or deadline_age >= 0)):
                findings.append({"kind": "expired_review_lease", "event_id": job["event_id"]})
    if references is not None:
        if not references.get("observations"):
            findings.append({"kind": "missing_reference_capture"})
        for source in references.get("observations", []):
            # Catalog discovery is weekly; policy/reference publications are daily.
            limit = 8 * 24 if "catalog" in source.get("kind", "") else max_age_hours
            if source.get("status") != "observed" or stale(source.get("observed_at"), limit):
                findings.append({"kind": "reference_capture_unhealthy",
                                 "source_id": source.get("source_id"),
                                 "status": source.get("status"), "last": source.get("observed_at")})
        for name, agrees in references.get("mirror_agreements", {}).items():
            if agrees is False:
                findings.append({"kind": "reference_mirror_mismatch", "mirror": name})
    return findings


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--latest", type=Path, default=ROOT / "data/latest.json")
    ap.add_argument("--queue-status", type=Path)
    ap.add_argument("--references", type=Path, default=ROOT / "data/references/latest.json")
    args = ap.parse_args(argv)
    data = json.loads(args.latest.read_text()) if args.latest.exists() else None
    queue = None
    if args.queue_status:
        queue = json.loads(args.queue_status.read_text()) if args.queue_status.exists() else {}
    references = json.loads(args.references.read_text()) if args.references.exists() else {}
    findings = check(data, queue, references=references)
    print(json.dumps({"checked_at": utcnow().isoformat(), "findings": findings}, indent=2))
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
