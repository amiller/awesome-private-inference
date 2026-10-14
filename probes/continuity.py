"""Derive immutable, evidence-linked changes from normalized observations."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from probes.observations import digest


def _identity_key(identity: dict) -> tuple[str, str, str]:
    return (identity["component_id"], identity["kind"], identity["model_scope"])


def _report(observation: dict) -> dict:
    return observation.get("evidence", {}).get("adapter_report") or {}


def _policy_decisions(observation: dict) -> dict[str, Any]:
    details = _report(observation).get("details") or {}
    decisions = dict(details.get("policy_decisions") or {})
    for field in ("chain_authorized", "anchored", "digest_audited", "mrtd_audited"):
        if field in details:
            decisions[field] = details[field]
    for item in details.get("model_composes") or []:
        if isinstance(item, dict) and item.get("compose_hash"):
            for field in ("chain_authorized", "anchored"):
                if field in item:
                    decisions[f"model_compose:{item['compose_hash']}:{field}"] = item[field]
    return decisions


def _cells(observation: dict) -> dict:
    return _report(observation).get("scorecard") or {}


def _model_mapping(observation: dict) -> Any:
    details = _report(observation).get("details") or {}
    return details.get("model_mapping", details.get("model_mappings"))


def _session_key(observation: dict) -> str | None:
    report = _report(observation)
    details = report.get("details") or {}
    return details.get("hpke_pubkey") or report.get("signing_public_key") or None


def _event(kind: str, route: str, old: dict | None, new: dict | None, *,
           field: str | None = None, old_value: Any = None, new_value: Any = None,
           component_id: str | None = None, trust: str = "unknown",
           priority: str = "normal") -> dict:
    body = {"kind": kind, "route_id": route,
            "old_observation_id": old["observation_id"] if old else None,
            "new_observation_id": new["observation_id"] if new else None,
            "field": field, "old_value": old_value, "new_value": new_value,
            "component_id": component_id}
    event = {"event_id": "chg-" + digest(body)[:32], **body,
             "old_observation_path": (
                 f"observations/records/{old['observation_id']}.json" if old else None),
             "new_observation_path": (
                 f"observations/records/{new['observation_id']}.json" if new else None),
             "old_raw_evidence_ref": old.get("evidence", {}).get("raw_evidence_ref") if old else None,
             "new_raw_evidence_ref": new.get("evidence", {}).get("raw_evidence_ref") if new else None,
             "first_seen_at": new["captured_at"] if new else (old["captured_at"] if old else None),
             "last_seen_at": new["captured_at"] if new else (old["captured_at"] if old else None),
             "affected_routes": [route], "trust": trust, "priority": priority,
             "uncertainty": "first observed by this sampling process" if kind == "identity_new" else None}
    return event


def derive_events(observations: list[dict], *, expected_routes: list[str] | None = None) -> list[dict]:
    """Compare route attempts; rejected identities are never called deployed facts."""
    ordered = sorted(observations, key=lambda x: (x["captured_at"], x["observation_id"]))
    prior_by_route: dict[str, dict] = {}
    seen: set[tuple[str, str, str, str]] = set()
    events: list[dict] = []
    for obs in ordered:
        route = obs["route_id"]
        if obs.get("legacy"):
            # Imported adapter rows establish the comparison baseline, not
            # retrospective proof or a backlog of newly deployed identities.
            if obs["outcome"] == "verified":
                seen.update((*_identity_key(item), item["value"])
                            for item in obs.get("identities", []))
            prior_by_route[route] = obs
            continue
        prior = prior_by_route.get(route)
        trust = obs.get("identity_trust", "unknown")
        new_ok = obs["outcome"] == "verified"
        old_ok = prior is not None and prior["outcome"] == "verified"
        if obs["reason"] == "retired":
            events.append(_event("route_retired", route, prior, obs,
                                 old_value=prior["outcome"] if prior else None,
                                 new_value="retired", trust="declared", priority="normal"))
        elif prior and prior["reason"] == "retired" and new_ok:
            events.append(_event("route_reactivated", route, prior, obs,
                                 old_value="retired", new_value=obs["outcome"],
                                 trust=trust, priority="high"))
        if prior:
            if old_ok and not new_ok and obs["reason"] != "retired":
                kind = "verification_rejected" if obs["outcome"] == "rejected" else "coverage_lost"
                events.append(_event(kind, route, prior, obs,
                                     old_value=prior["outcome"], new_value=obs["outcome"],
                                     trust=trust, priority="high"))
            elif not old_ok and new_ok:
                kind = "verification_restored" if prior["outcome"] == "rejected" else "coverage_restored"
                events.append(_event(kind, route, prior, obs,
                                     old_value=prior["outcome"], new_value=obs["outcome"], trust=trust))
            if prior.get("policy_revision") != obs.get("policy_revision"):
                events.append(_event("policy_revision_changed", route, prior, obs,
                                     field="policy_revision", old_value=prior.get("policy_revision"),
                                     new_value=obs.get("policy_revision"), trust=trust, priority="high"))
            if prior.get("verifier_revision") != obs.get("verifier_revision"):
                events.append(_event("instrument_changed", route, prior, obs,
                                     field="verifier_revision", old_value=prior.get("verifier_revision"),
                                     new_value=obs.get("verifier_revision"), trust=trust))
            old_policies, new_policies = _policy_decisions(prior), _policy_decisions(obs)
            if (new_ok or old_ok) and _report(obs):
                for field in sorted(new_policies):
                    old_value, new_value = old_policies.get(field), new_policies.get(field)
                    if old_value != new_value:
                        events.append(_event("policy_mismatch" if new_ok else "untrusted_policy_reported",
                                             route, prior, obs, field=field,
                                             old_value=old_value, new_value=new_value,
                                             trust=trust, priority="high"))
            # A transient missing report cannot silently reset the scorecard.
            if new_ok and old_ok:
                old_mapping, new_mapping = _model_mapping(prior), _model_mapping(obs)
                if old_mapping is not None and new_mapping is not None and old_mapping != new_mapping:
                    events.append(_event("model_mapping_changed", route, prior, obs,
                                         field="model_mapping", old_value=old_mapping,
                                         new_value=new_mapping, trust=trust, priority="high"))
                old_key, new_key = _session_key(prior), _session_key(obs)
                if old_key and new_key and old_key != new_key:
                    events.append(_event("key_rotated", route, prior, obs,
                                         field="session_key", old_value=old_key,
                                         new_value=new_key, trust=trust))
                old_cells, new_cells = _cells(prior), _cells(obs)
                for field in sorted(old_cells.keys() | new_cells.keys()):
                    old_value, new_value = old_cells.get(field), new_cells.get(field)
                    if old_value != new_value:
                        events.append(_event("cell_changed", route, prior, obs, field=field,
                                             old_value=old_value, new_value=new_value, trust=trust))
            elif not new_ok and _report(obs):
                for field in sorted(_cells(prior).keys() | _cells(obs).keys()):
                    if _cells(prior).get(field) != _cells(obs).get(field):
                        events.append(_event("untrusted_cell_reported", route, prior, obs,
                                             field=field, old_value=_cells(prior).get(field),
                                             new_value=_cells(obs).get(field), trust="untrusted_report"))
        elif obs["outcome"] == "rejected":
            events.append(_event("verification_rejected", route, None, obs,
                                 new_value="rejected", trust=trust, priority="high"))
        if not prior and new_ok:
            for field, value in _policy_decisions(obs).items():
                if value is False:
                    events.append(_event("policy_mismatch", route, None, obs, field=field,
                                         new_value=value, trust=trust, priority="high"))
        prior_ids = {_identity_key(x): x["value"] for x in prior.get("identities", [])} if prior else {}
        if prior and old_ok and new_ok:
            new_keys = {_identity_key(x) for x in obs.get("identities", [])}
            for key, value in prior_ids.items():
                if key not in new_keys:
                    events.append(_event("identity_missing", route, prior, obs,
                                         field=key[1], old_value=value, new_value=None,
                                         component_id=key[0], trust="unknown", priority="high"))
        for item in obs.get("identities", []):
            key = (*_identity_key(item), item["value"])
            if not new_ok:
                # Keep candidate values for investigation, separate from trusted history.
                if not prior or key not in {(*_identity_key(x), x["value"]) for x in prior.get("identities", [])}:
                    events.append(_event("untrusted_identity_reported", route, prior, obs,
                                         field=item["kind"], old_value=prior_ids.get(_identity_key(item)),
                                         new_value=item["value"], component_id=item["component_id"],
                                         trust="untrusted_report", priority="high"))
                continue
            if key not in seen:
                events.append(_event("identity_new", route, prior, obs, field=item["kind"],
                                     old_value=prior_ids.get(_identity_key(item)), new_value=item["value"],
                                     component_id=item["component_id"], trust=trust, priority="high"))
                seen.add(key)
            elif prior_ids.get(_identity_key(item)) != item["value"]:
                events.append(_event("identity_revisited", route, prior, obs, field=item["kind"],
                                     old_value=prior_ids.get(_identity_key(item)), new_value=item["value"],
                                     component_id=item["component_id"], trust=trust))
        prior_by_route[route] = obs
    for route in sorted(set(expected_routes or []) - prior_by_route.keys()):
        events.append(_event("coverage_unknown", route, None, None,
                             new_value="no recorded attempt", priority="high"))
    # One shared workload can serve several hostnames. Keep each exact
    # observation pair, while exposing every route that may be affected.
    component_routes: dict[tuple[str, str], set[str]] = {}
    for obs in ordered:
        for item in obs.get("identities", []):
            component_routes.setdefault((obs["run_id"], item["component_id"]), set()).add(obs["route_id"])
    for event in events:
        new_id = event["new_observation_id"]
        if new_id and (new_id.split("/")[0], event["component_id"]) in component_routes:
            event["affected_routes"] = sorted(component_routes[(new_id.split("/")[0], event["component_id"])])
    return sorted({event["event_id"]: event for event in events}.values(),
                  key=lambda x: (x["first_seen_at"] or "", x["event_id"]))


def persist_events(data_dir: Path, events: list[dict]) -> list[dict]:
    """Create each event exactly once; reruns cannot rewrite an event payload."""
    directory = Path(data_dir) / "continuity" / "events"
    directory.mkdir(parents=True, exist_ok=True)
    created = []
    for event in events:
        path = directory / f"{event['event_id']}.json"
        if path.exists():
            if json.loads(path.read_text()) != event:
                raise ValueError(f"event ID collision or rewritten event: {event['event_id']}")
            continue
        try:
            with path.open("x") as file:
                json.dump(event, file, indent=2, sort_keys=True)
                file.write("\n")
        except FileExistsError:
            if json.loads(path.read_text()) != event:
                raise
        else:
            created.append(event)
    return created


def load_events(data_dir: Path) -> list[dict]:
    return sorted((json.loads(p.read_text()) for p in
                   (Path(data_dir) / "continuity" / "events").glob("*.json")),
                  key=lambda x: (x["first_seen_at"] or "", x["event_id"]))
