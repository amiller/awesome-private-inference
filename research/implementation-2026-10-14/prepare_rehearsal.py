"""Prepare an isolated, explicitly synthetic review packet for a Sol rehearsal.

This never writes into the production review queue or published decisions.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from probes.review_queue import Queue, atomic_json


ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / "local-data" / "review-rehearsal"


def main() -> int:
    evidence = BASE / "evidence"
    evidence.mkdir(parents=True, exist_ok=True)
    old_path = evidence / "synthetic-old-policy.json"
    new_path = evidence / "synthetic-new-policy.json"
    old = {"synthetic": True, "component_id": "private-inference/browser-policy",
           "route_id": "private-inference-private-beta", "accepted_compose_hashes": ["a" * 64],
           "meaning": "Offline fixture only; no claim that Private Inference publishes this policy."}
    new = {**old, "accepted_compose_hashes": ["a" * 64, "b" * 64]}
    for path, value in ((old_path, old), (new_path, new)):
        if path.exists() and json.loads(path.read_text()) != value:
            raise ValueError(f"existing rehearsal evidence differs: {path}")
        if not path.exists():
            atomic_json(path, value)
    basis = {"kind": "synthetic_policy_expansion", "route_id": old["route_id"],
             "old": old, "new": new}
    event_id = "chg-" + hashlib.sha256(json.dumps(basis, sort_keys=True).encode()).hexdigest()[:32]
    event = {
        "event_id": event_id, "kind": "synthetic_policy_expansion",
        "synthetic": True, "priority": "high", "route_id": old["route_id"],
        "affected_routes": [old["route_id"]], "component_id": old["component_id"],
        "old_observation_id": "synthetic-old-policy",
        "new_observation_id": "synthetic-new-policy",
        "old_observation_path": str(old_path.relative_to(ROOT)),
        "new_observation_path": str(new_path.relative_to(ROOT)),
        "old_value": old["accepted_compose_hashes"],
        "new_value": new["accepted_compose_hashes"],
        "uncertainty": "Entire change is a labeled offline fixture; no live provider policy or deployment evidence.",
        "context_only": [
            "research/review-2026-10-13/privateinference.md",
            "data/references/latest.json",
            "data/routes.json",
        ],
        "review_questions": [
            "Does the fixture expand client acceptance, and which exact value was added?",
            "Can any captured public artifact establish that this expansion actually occurred?",
            "What would be needed to map a provider publication to a live plaintext holder and client policy?",
        ],
    }
    event_path = BASE / "event.json"
    if event_path.exists() and json.loads(event_path.read_text()) != event:
        raise ValueError("existing rehearsal event differs")
    if not event_path.exists():
        atomic_json(event_path, event)
    queue = Queue(BASE / "queue")
    queue.ingest([event])
    job = queue.claim(worker="sol-offline-rehearsal", lease_seconds=7200)
    if job is None:
        raise ValueError("no claimable rehearsal job")
    if job["event_id"] != event_id:
        raise ValueError("claimed the wrong rehearsal event")
    packet = BASE / "packet.json"
    atomic_json(packet, job)
    packet.chmod(0o600)
    print(json.dumps({"event_id": event_id, "packet": str(packet),
                      "state": job["status"], "attempt": job["attempts"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
