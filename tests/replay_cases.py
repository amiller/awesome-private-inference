"""Small labeled replay corpus for deterministic continuity detection.

These cases exercise the change detector. They do not evaluate an agent's review
quality or prove provider behavior.
"""
from __future__ import annotations

from probes.continuity import derive_events

A = "a" * 64
B = "b" * 64
ROUTE = "aci-gateway/tee.redpill.ai"


def observation(n: int, *, outcome="verified", reason=None, identity=A,
                component="aci-gateway/shared-workload", policy=True, cell=True,
                verifier="v1", policy_revision="p1", mapping=None, key=None,
                report=True):
    details = {"policy_decisions": {"approved": policy}}
    if mapping is not None:
        details["model_mapping"] = mapping
    identities = [] if identity is None else [{"component_id": component,
        "kind": "compose_hash", "value": identity, "model_scope": "*"}]
    value = {"observation_id": f"run{n}/row", "run_id": f"run{n}",
             "route_id": ROUTE, "provider": "aci-gateway", "model": "tee.redpill.ai",
             "captured_at": f"2026-10-{n+10:02d}T00:00:00Z", "outcome": outcome,
             "reason": reason or ("adapter_accepted" if outcome == "verified" else "adapter_rejected"),
             "identity_trust": "adapter_accepted" if outcome == "verified" else "untrusted_report",
             "verifier_revision": verifier, "policy_revision": policy_revision,
             "identities": identities,
             "evidence": {"adapter_report": {
                 "scorecard": {"nonce_bound": cell}, "details": details,
                 "signing_public_key": key,
             } if report else None}}
    return value


def _case(name, rows, expected, forbidden=(), expected_routes=None):
    return {"name": name, "rows": rows, "expected": expected,
            "forbidden": forbidden, "expected_routes": expected_routes}


CASES = [
    _case("first_identity", [observation(1)], "identity_new"),
    _case("changed_compose", [observation(1), observation(2, identity=B)], "identity_new"),
    _case("known_revisit", [observation(1), observation(2, identity=B), observation(3)], "identity_revisited"),
    _case("shared_keyset_identity", [observation(1, component="aci-gateway/keyset")], "identity_new"),
    _case("generic_component_identity", [observation(1, component="other/component")], "identity_new"),
    _case("rejected_candidate", [observation(1), observation(2, outcome="rejected", identity=B)],
          "untrusted_identity_reported", ("identity_new",)),
    _case("binding_rejection", [observation(1), observation(2, outcome="rejected")], "verification_rejected"),
    _case("evidence_unavailable", [observation(1), observation(2, outcome="unavailable", report=False)], "coverage_lost"),
    _case("credential_not_checked", [observation(1), observation(2, outcome="not_checked", report=False)], "coverage_lost"),
    _case("coverage_recovered", [observation(1, outcome="unavailable", report=False), observation(2)], "coverage_restored"),
    _case("rejection_recovered", [observation(1, outcome="rejected"), observation(2)], "verification_restored"),
    _case("initial_policy_mismatch", [observation(1, policy=False)], "policy_mismatch"),
    _case("new_policy_mismatch", [observation(1), observation(2, policy=False)], "policy_mismatch"),
    _case("rejected_policy_candidate", [observation(1), observation(2, outcome="rejected", policy=False)],
          "untrusted_policy_reported", ("policy_mismatch",)),
    _case("verified_cell_change", [observation(1), observation(2, cell=False)], "cell_changed"),
    _case("rejected_cell_candidate", [observation(1), observation(2, outcome="rejected", cell=False)],
          "untrusted_cell_reported", ("cell_changed",)),
    _case("instrument_revision", [observation(1), observation(2, verifier="v2")], "instrument_changed"),
    _case("policy_revision", [observation(1), observation(2, policy_revision="p2")], "policy_revision_changed"),
    _case("identity_missing", [observation(1), observation(2, identity=None)], "identity_missing"),
    _case("model_mapping", [observation(1, mapping={"alias": "one"}),
                            observation(2, mapping={"alias": "two"})], "model_mapping_changed"),
    _case("key_rotation", [observation(1, key="key-one"), observation(2, key="key-two")], "key_rotated"),
    _case("declared_retirement", [observation(1), observation(2, outcome="not_applicable", reason="retired", report=False)], "route_retired"),
    _case("route_reactivated", [observation(1, outcome="not_applicable", reason="retired", report=False), observation(2)], "route_reactivated"),
    _case("no_attempt", [], "coverage_unknown", expected_routes=[ROUTE]),
]


def evaluate(case):
    events = derive_events(case["rows"], expected_routes=case["expected_routes"])
    target = case["rows"][-1]["observation_id"] if case["rows"] else None
    relevant = [event for event in events if event["new_observation_id"] == target]
    kinds = [event["kind"] for event in relevant]
    passed = case["expected"] in kinds and not any(kind in kinds for kind in case["forbidden"])
    return {"name": case["name"], "passed": passed, "expected": case["expected"],
            "forbidden": list(case["forbidden"]), "observed_kinds": sorted(set(kinds)),
            "event_ids": [e["event_id"] for e in relevant if e["kind"] == case["expected"]]}
