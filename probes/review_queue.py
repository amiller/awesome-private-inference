"""Durable event-to-review jobs. Launch is a lease, never an acknowledgment.

State lives outside tracked data. Validated decisions can be exported separately;
this module never changes an accepted reference-value ledger.
"""
from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import sys
import tempfile
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DIR = ROOT / "local-data" / "review-queue"
TERMINAL = {"published", "superseded"}
REQUIRED_DRAFT = {"summary", "classification", "evidence", "checks_performed",
                  "uncertainties", "next_action", "plaintext_boundary_impact",
                  "acceptance_policy_impact"}


def utcnow():
    return dt.datetime.now(dt.timezone.utc)


def iso(value):
    return value.isoformat().replace("+00:00", "Z")


def parse(value):
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))


def atomic_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".write-")
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(value, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def event_key(event):
    value = event.get("event_id")
    if not value:
        value = hashlib.sha256(json.dumps(event, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    if not re.fullmatch(r"[A-Za-z0-9_-]{8,128}", value):
        raise ValueError("unsafe or missing event identifier")
    return value


class Queue:
    def __init__(self, directory=DEFAULT_DIR, *, artifact_root=ROOT):
        self.directory = Path(directory)
        self.path = self.directory / "queue.json"
        self.artifact_root = Path(artifact_root).resolve()

    @contextlib.contextmanager
    def transaction(self):
        self.directory.mkdir(parents=True, exist_ok=True)
        with (self.directory / ".lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            state = json.loads(self.path.read_text()) if self.path.exists() else {"schema_version": 1, "jobs": {}}
            yield state
            atomic_json(self.path, state)

    @staticmethod
    def transition(job, status, now, **details):
        job["status"] = status
        job["updated_at"] = iso(now)
        job.setdefault("history", []).append({"at": iso(now), "status": status, **details})

    def ingest(self, events, now=None):
        now = now or utcnow()
        added = 0
        with self.transaction() as state:
            for original in events:
                event = dict(original)
                key = event_key(event)
                event["event_id"] = key
                if key in state["jobs"]:
                    if state["jobs"][key]["event"] != event:
                        raise ValueError(f"event {key} changed after ingestion")
                    continue
                job = {"event_id": key, "event": event, "attempts": 0,
                       "created_at": iso(now), "history": []}
                self.transition(job, "queued", now)
                state["jobs"][key] = job
                added += 1
            state["last_ingest_at"] = iso(now)
        return added

    def claim(self, *, worker, lease_seconds=3600, now=None):
        now = now or utcnow()
        if not worker or not 1 <= lease_seconds <= 86400:
            raise ValueError("worker and lease between 1 and 86400 seconds required")
        with self.transaction() as state:
            for job in state["jobs"].values():
                if job["status"] == "running" and parse(job["lease_until"]) <= now:
                    self.transition(job, "retryable_failure", now, reason="worker lease expired")
                    job.pop("lease_token", None)
            candidates = [j for j in state["jobs"].values() if j["status"] in {"queued", "retryable_failure"}]
            if not candidates:
                return None
            priority = {"critical": 0, "high": 1, "warn": 2, "medium": 2, "info": 3, "low": 3}
            job = min(candidates, key=lambda j: (priority.get(str(j["event"].get("priority", "info")), 2), j["created_at"], j["event_id"]))
            job["attempts"] += 1
            job["worker"] = worker
            job["lease_token"] = secrets.token_hex(24)
            job["lease_until"] = iso(now + dt.timedelta(seconds=lease_seconds))
            self.transition(job, "running", now, worker=worker, attempt=job["attempts"])
            return json.loads(json.dumps(job))

    @staticmethod
    def check_lease(job, token, now):
        if job["status"] != "running" or not secrets.compare_digest(job.get("lease_token", ""), token):
            raise ValueError("job is not running under this lease")
        if parse(job["lease_until"]) <= now:
            raise ValueError("lease expired; late worker cannot overwrite a retry")

    def submit(self, key, token, draft, now=None):
        now = now or utcnow()
        missing = REQUIRED_DRAFT - draft.keys()
        if missing or draft.get("event_id") != key:
            raise ValueError(f"draft must identify its event and include {sorted(missing)}")
        if draft["classification"] not in {"continuity", "substantive", "regression", "needs_evidence", "coverage", "policy_change"}:
            raise ValueError("unknown classification")
        for field in REQUIRED_DRAFT - {"evidence", "checks_performed", "uncertainties"}:
            if not isinstance(draft[field], str) or not draft[field].strip():
                raise ValueError(f"{field} must be nonempty text")
        for field in ("evidence", "checks_performed", "uncertainties"):
            if not isinstance(draft[field], list) or any(not isinstance(x, str) or not x.strip() for x in draft[field]):
                raise ValueError(f"{field} must be a list of text")
        if not draft["evidence"] or not draft["checks_performed"]:
            raise ValueError("draft requires evidence and performed checks")
        for ref in draft["evidence"]:
            url = urlsplit(ref)
            if url.scheme in {"https", "http"} and url.netloc and not any(ch.isspace() for ch in ref):
                continue
            path = (self.artifact_root / ref).resolve()
            if (url.scheme or Path(ref).is_absolute() or
                    not path.is_relative_to(self.artifact_root) or not path.is_file()):
                raise ValueError(f"evidence must be an exact existing relative path or URL: {ref}")
        with self.transaction() as state:
            job = state["jobs"][key]
            self.check_lease(job, token, now)
            job["draft"] = draft
            self.transition(job, "draft_ready", now, worker=job["worker"])
            job.pop("lease_token", None)

    def fail(self, key, token, reason, *, blocked=False, now=None):
        now = now or utcnow()
        if not reason.strip():
            raise ValueError("failure reason required")
        with self.transaction() as state:
            job = state["jobs"][key]
            self.check_lease(job, token, now)
            self.transition(job, "blocked" if blocked else "retryable_failure", now, reason=reason)
            job.pop("lease_token", None)

    def requeue(self, key, reason, now=None):
        now = now or utcnow()
        if not reason.strip():
            raise ValueError("requeue reason required")
        with self.transaction() as state:
            job = state["jobs"][key]
            if job["status"] not in {"blocked", "retryable_failure", "draft_ready"}:
                raise ValueError("only blocked, failed or returned drafts can be requeued")
            job.pop("draft", None)
            self.transition(job, "queued", now, reason=reason)

    def review(self, key, *, reviewer, disposition, rationale, now=None):
        now = now or utcnow()
        if disposition not in {"accepted", "rejected", "needs_evidence"} or not reviewer or not rationale.strip():
            raise ValueError("reviewer, disposition and rationale required")
        with self.transaction() as state:
            job = state["jobs"][key]
            if job["status"] != "draft_ready" or reviewer == job.get("worker"):
                raise ValueError("a distinct reviewer must review a completed draft")
            job["review"] = {"reviewer": reviewer, "disposition": disposition, "rationale": rationale, "at": iso(now)}
            self.transition(job, "reviewed", now, **job["review"])

    def publish(self, key, output_dir, now=None):
        now = now or utcnow()
        with self.transaction() as state:
            job = state["jobs"][key]
            if job["status"] not in {"reviewed", "published"}:
                raise ValueError("only a reviewed draft can be published")
            record = {k: job[k] for k in ("event_id", "event", "draft", "review")}
            path = Path(output_dir) / f"{key}.json"
            if path.exists() and json.loads(path.read_text()) != record:
                raise ValueError("published decision is immutable")
            if not path.exists():
                atomic_json(path, record)
            if job["status"] != "published":
                self.transition(job, "published", now, decision_file=path.name)
            return path

    def summary(self, now=None):
        now = now or utcnow()
        with self.transaction() as state:
            jobs = []
            for job in state["jobs"].values():
                item = {k: job.get(k) for k in ("event_id", "status", "attempts", "created_at", "updated_at", "worker", "lease_until")}
                item.update(kind=job["event"].get("kind"), route_id=job["event"].get("route_id"),
                            lease_expired=job["status"] == "running" and parse(job["lease_until"]) <= now)
                jobs.append(item)
            return {"schema_version": 1, "generated_at": iso(now),
                    "last_ingest_at": state.get("last_ingest_at"), "jobs": jobs}


def read_events(data_dir):
    events = []
    for directory in (Path(data_dir) / "continuity" / "events", Path(data_dir) / "references" / "events"):
        for path in sorted(directory.glob("*.json")):
            content = json.loads(path.read_text())
            events.extend(content if isinstance(content, list) else [content])
    return events


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--state-dir", type=Path, default=DEFAULT_DIR)
    sub = ap.add_subparsers(dest="command", required=True)
    ingest = sub.add_parser("ingest")
    ingest.add_argument("--data-dir", type=Path, default=ROOT / "data")
    claim = sub.add_parser("claim")
    claim.add_argument("--worker", required=True)
    claim.add_argument("--lease-seconds", type=int, default=3600)
    claim.add_argument("--packet", type=Path, required=True)
    for name in ("submit", "fail"):
        cmd = sub.add_parser(name)
        cmd.add_argument("--packet", type=Path, required=True)
        if name == "submit":
            cmd.add_argument("--draft", type=Path, required=True)
        else:
            cmd.add_argument("--reason", required=True)
            cmd.add_argument("--blocked", action="store_true")
    requeue = sub.add_parser("requeue")
    requeue.add_argument("--event", required=True)
    requeue.add_argument("--reason", required=True)
    review = sub.add_parser("review")
    review.add_argument("--event", required=True)
    review.add_argument("--reviewer", required=True)
    review.add_argument("--disposition", choices=("accepted", "rejected", "needs_evidence"), required=True)
    review.add_argument("--rationale", required=True)
    publish = sub.add_parser("publish")
    publish.add_argument("--event", required=True)
    publish.add_argument("--output-dir", type=Path, default=ROOT / "data" / "reviews" / "decisions")
    status = sub.add_parser("status")
    status.add_argument("--output", type=Path)
    args = ap.parse_args(argv)
    queue = Queue(args.state_dir)
    if args.command == "ingest":
        print(json.dumps({"added": queue.ingest(read_events(args.data_dir))}))
    elif args.command == "claim":
        job = queue.claim(worker=args.worker, lease_seconds=args.lease_seconds)
        if job is None:
            return 4
        atomic_json(args.packet, job)
        os.chmod(args.packet, 0o600)
        print(job["event_id"])
    elif args.command in {"submit", "fail"}:
        packet = json.loads(args.packet.read_text())
        if args.command == "submit":
            queue.submit(packet["event_id"], packet["lease_token"], json.loads(args.draft.read_text()))
        else:
            queue.fail(packet["event_id"], packet["lease_token"], args.reason, blocked=args.blocked)
    elif args.command == "requeue":
        queue.requeue(args.event, args.reason)
    elif args.command == "review":
        queue.review(args.event, reviewer=args.reviewer, disposition=args.disposition, rationale=args.rationale)
    elif args.command == "publish":
        print(queue.publish(args.event, args.output_dir))
    elif args.command == "status":
        summary = queue.summary()
        if args.output:
            atomic_json(args.output, summary)
        print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, KeyError) as exc:
        print(f"review queue: {exc}", file=sys.stderr)
        sys.exit(2)
