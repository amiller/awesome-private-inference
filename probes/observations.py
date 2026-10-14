"""Immutable probe attempts and a derived, route-complete current view.

Adapter reports are retained as reports, not promoted to independently checked
attestations. A pending attempt exists before its adapter is called. Results,
run completion markers, and historical imports are create-only files.
"""
from __future__ import annotations

import hashlib
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from probes.schema import (OBSERVATION_VERSION, SCHEMA_VERSION, OUTCOMES, REASONS,
                           classify_report, normalize_checks)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode()


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def _write_new(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as file:
        json.dump(value, file, indent=2, sort_keys=True, default=str)
        file.write("\n")
        file.flush()
        os.fsync(file.fileno())


def _replace(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True, default=str) + "\n")
    os.replace(temporary, path)


def route_id(provider: str, model: str) -> str:
    return f"{provider}/{model}"


def new_run_id() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ") + "-" + uuid.uuid4().hex[:12]


def _key(provider: str, model: str) -> str:
    return hashlib.sha256(canonical([provider, model])).hexdigest()[:24]


def start_run(data_dir: Path, requested_models: dict[str, list[str]], *,
              complete: bool = True, run_id: str | None = None,
              captured_at: str | None = None, git_sha: str = "",
              verifier_revision: str = "", policy_revisions: dict | None = None,
              observer: str = "daily-probe", legacy: bool = False,
              source_snapshot: str | None = None, instrument: dict | None = None) -> dict:
    """Persist the run and every pending route attempt before any probe call."""
    data_dir = Path(data_dir)
    run_id = run_id or new_run_id()
    captured_at = captured_at or utc_now()
    run = {
        "schema_version": OBSERVATION_VERSION, "run_id": run_id,
        "started_at": captured_at, "observer": observer, "complete": complete,
        "requested_models": requested_models, "git_sha": git_sha,
        "verifier_revision": verifier_revision or git_sha or "unknown",
        "policy_revisions": policy_revisions or {}, "legacy": legacy,
        "source_snapshot": source_snapshot,
        "instrument": instrument,
    }
    _write_new(data_dir / "observations" / "runs" / f"{run_id}.json", run)
    for provider, models in requested_models.items():
        for model in models:
            attempt = {
                "schema_version": OBSERVATION_VERSION,
                "observation_id": f"{run_id}/{_key(provider, model)}",
                "run_id": run_id, "provider": provider, "model": model,
                "route_id": route_id(provider, model), "started_at": captured_at,
                "observer": observer, "outcome": "not_checked", "reason": "pending",
            }
            _write_new(data_dir / "observations" / "attempts" / run_id / f"{_key(provider, model)}.json", attempt)
    return run


def _identities(provider: str, model: str, details: dict) -> list[dict]:
    """Extract full values with component and model scope; never use prefixes."""
    found: list[dict] = []
    def add(component: str, kind: str, value: Any, scope: str = model) -> None:
        if isinstance(value, str) and value:
            found.append({"component_id": component, "kind": kind, "value": value,
                          "model_scope": scope})
    if provider == "aci-gateway":
        component = "aci-gateway/shared-workload"
        for field in ("compose_hash", "workload_keyset_digest", "os_image", "repo_commit"):
            add(component, field, details.get(field), "*")
    elif provider == "near-ai":
        add("near-ai/cloud-api", "image_digest", details.get("cloud_api_image_digest"), "*")
        add("near-ai/gateway", "compose_hash", details.get("gateway_compose_hash"), "*")
        for item in details.get("model_composes") or []:
            if isinstance(item, dict):
                add("near-ai/model", "compose_hash", item.get("compose_hash"))
    elif provider == "tinfoil":
        add("tinfoil/router", "bundle_digest", details.get("digest"), "*")
        add("tinfoil/router", "measurement", (details.get("sev") or {}).get("measurement"), "*")
    elif provider == "chutes":
        add("chutes/instance", "mrtd", details.get("mrtd"))
    # New monitors may supply scoped identities without modifying this adapter.
    for item in details.get("identities") or []:
        if isinstance(item, dict):
            add(str(item.get("component_id") or provider), str(item.get("kind") or "value"),
                item.get("value"), str(item.get("model_scope") or model))
    return sorted({canonical(x): x for x in found}.values(), key=lambda x: canonical(x))


def finish_attempt(data_dir: Path, run: dict, provider: str, model: str,
                   report: dict | None, *, captured_at: str | None = None,
                   raw_evidence_ref: str | None = None, instance_id: str | None = None,
                   outcome_override: str | None = None, reason_override: str | None = None) -> dict:
    """Write a result once; missing report remains an explicit unavailable result."""
    if model not in run["requested_models"].get(provider, []):
        raise ValueError(f"unrequested route: {provider}/{model}")
    data_dir = Path(data_dir)
    captured_at = captured_at or (report or {}).get("verified_at") or utc_now()
    outcome, reason = classify_report(report, legacy=run["legacy"]) if report is not None else ("unavailable", "missing_response")
    outcome = outcome_override or outcome
    reason = reason_override or reason
    if outcome not in OUTCOMES or reason not in REASONS:
        raise ValueError(f"unsupported observation outcome/reason: {outcome}/{reason}")
    details = (report or {}).get("details") or {}
    stored_report = report
    embedded_raw = details.get("raw_evidence")
    raw_digest = digest(embedded_raw) if embedded_raw is not None else None
    if embedded_raw is not None and not run["legacy"]:
        raw_path = data_dir / "observations" / "evidence" / "sha256" / f"{raw_digest}.json"
        if raw_path.exists():
            if json.loads(raw_path.read_text()) != embedded_raw:
                raise ValueError(f"raw evidence digest collision: {raw_digest}")
        else:
            try:
                _write_new(raw_path, embedded_raw)
            except FileExistsError:
                if json.loads(raw_path.read_text()) != embedded_raw:
                    raise
        raw_evidence_ref = str(raw_path.relative_to(data_dir))
        stored_report = dict(report)
        stored_details = dict(details)
        stored_details.pop("raw_evidence")
        stored_details["raw_evidence_ref"] = raw_evidence_ref
        stored_details["raw_evidence_sha256"] = raw_digest
        stored_report["details"] = stored_details
    result = {
        "schema_version": OBSERVATION_VERSION,
        "observation_id": f"{run['run_id']}/{_key(provider, model)}",
        "run_id": run["run_id"], "provider": provider, "model": model,
        "route_id": route_id(provider, model), "instance_id": instance_id or details.get("instance_id"),
        "captured_at": captured_at, "observer": run["observer"],
        "outcome": outcome, "reason": reason, "legacy": run["legacy"],
        "verification_scope": "legacy_adapter_result" if run["legacy"] else "current_adapter_result",
        "reason_detail": details.get("verification_reason"),
        "verifier_revision": run["verifier_revision"],
        "policy_revision": details.get("policy_revision") or details.get("anchor_policy_revision_sha256") or
                           run["policy_revisions"].get(provider, "unknown"),
        "source_snapshot": run["source_snapshot"],
        "evidence": {
            "adapter_report_sha256": digest(report) if report is not None else None,
            "stored_report_sha256": digest(stored_report) if stored_report is not None else None,
            # Historical snapshots already retain the full report, often with a
            # large quote. Refer to that copy instead of duplicating it per row.
            "adapter_report": None if run["legacy"] and run["source_snapshot"] else stored_report,
            "adapter_report_ref": {
                "path": run["source_snapshot"], "provider": provider, "model": model,
            } if run["legacy"] and run["source_snapshot"] and report is not None else None,
            "raw_evidence_ref": raw_evidence_ref,
            "raw_evidence_sha256": raw_digest,
            "raw_evidence_status": (
                "referenced_in_legacy_snapshot" if embedded_raw is not None and run["legacy"] else
                "stored_separately" if embedded_raw is not None else
                "referenced" if raw_evidence_ref else "not_captured_by_adapter"),
        },
        "identities": _identities(provider, model, details),
        "checks": normalize_checks((report or {}).get("scorecard")),
        "identity_trust": "legacy_adapter_result" if run["legacy"] else
                          ("adapter_accepted" if outcome == "verified" else "untrusted_report"),
    }
    _write_new(data_dir / "observations" / "records" / run["run_id"] / f"{_key(provider, model)}.json", result)
    return result


def record_retirement(data_dir: Path, provider: str, model: str, *,
                      retired_at: str | None = None, policy_revision: str = "unknown") -> dict:
    """Make a deliberate catalog retirement explicit; absence alone never retires."""
    run = start_run(data_dir, {provider: [model]}, complete=False,
                    captured_at=retired_at, observer="route-inventory",
                    policy_revisions={provider: policy_revision})
    result = finish_attempt(data_dir, run, provider, model, None,
                            captured_at=retired_at or run["started_at"],
                            outcome_override="not_applicable", reason_override="retired")
    finish_run(data_dir, run)
    return result


def finish_run(data_dir: Path, run: dict) -> dict:
    records = Path(data_dir) / "observations" / "records" / run["run_id"]
    missing = [(provider, model) for provider, models in run["requested_models"].items()
               for model in models if not (records / f"{_key(provider, model)}.json").exists()]
    if missing:
        raise ValueError(f"cannot complete run with pending attempts: {missing}")
    marker = {"run_id": run["run_id"], "completed_at": utc_now()}
    _write_new(Path(data_dir) / "observations" / "completed" / f"{run['run_id']}.json", marker)
    return marker


def record_run(data_dir: Path, snapshot: dict, requested_models: dict[str, list[str]], *,
               complete: bool = True, legacy: bool = False,
               source_snapshot: str | None = None) -> dict:
    """Import an already completed snapshot, primarily for historical backfill/tests."""
    run_id = ("legacy-" + digest(snapshot)[:24]) if legacy else None
    run = start_run(data_dir, requested_models, complete=complete, run_id=run_id,
                    captured_at=snapshot.get("generated_at"), git_sha=snapshot.get("git_sha", ""),
                    verifier_revision=snapshot.get("verifier_revision", ""),
                    policy_revisions=snapshot.get("policy_revisions"),
                    observer="legacy-snapshot" if legacy else "daily-probe", legacy=legacy,
                    source_snapshot=source_snapshot)
    for provider, models in requested_models.items():
        rows = {r["model"]: r for r in snapshot.get("attestations", {}).get(provider, [])}
        for model in models:
            finish_attempt(data_dir, run, provider, model, rows.get(model),
                           captured_at=(rows.get(model) or {}).get("verified_at") or snapshot.get("generated_at"))
    finish_run(data_dir, run)
    return run


def load_runs(data_dir: Path) -> list[dict]:
    return [json.loads(p.read_text()) for p in sorted((Path(data_dir) / "observations" / "runs").glob("*.json"))]


def load_observations(data_dir: Path) -> list[dict]:
    """Load records, resolving compact legacy references for analysis."""
    records = Path(data_dir) / "observations" / "records"
    snapshots: dict[str, dict] = {}
    loaded = []
    for path in records.glob("*/*.json"):
        obs = json.loads(path.read_text())
        ref = obs["evidence"].get("adapter_report_ref")
        if ref:
            source = (Path(data_dir) / ref["path"]).resolve()
            if not source.is_relative_to(Path(data_dir).resolve()):
                raise ValueError(f"snapshot reference leaves data directory: {ref['path']}")
            if ref["path"] not in snapshots:
                snapshots[ref["path"]] = json.loads(source.read_text())
            rows = snapshots[ref["path"]].get("attestations", {}).get(ref["provider"], [])
            matches = [r for r in rows if r.get("model") == ref["model"]]
            if len(matches) != 1 or digest(matches[0]) != obs["evidence"]["adapter_report_sha256"]:
                raise ValueError(f"legacy snapshot report changed: {ref['path']} {ref['model']}")
            obs["evidence"]["adapter_report"] = matches[0]
        loaded.append(obs)
    return sorted(loaded, key=lambda x: (x["captured_at"], x["observation_id"]))


def resolve_report(data_dir: Path, observation: dict) -> dict | None:
    """Reconstruct the original adapter report and verify local content hashes.

    These hashes detect accidental/local changes; they are not external witness
    signatures or proof that an adapter captured every upstream byte.
    """
    evidence = observation["evidence"]
    stored = evidence.get("adapter_report")
    if stored is None and evidence.get("adapter_report_ref"):
        ref = evidence["adapter_report_ref"]
        source = (Path(data_dir) / ref["path"]).resolve()
        if not source.is_relative_to(Path(data_dir).resolve()):
            raise ValueError("adapter report reference leaves data directory")
        rows = json.loads(source.read_text()).get("attestations", {}).get(ref["provider"], [])
        matches = [row for row in rows if row.get("model") == ref["model"]]
        if len(matches) != 1:
            raise ValueError("referenced adapter report is missing or ambiguous")
        stored = matches[0]
    if stored is None:
        return None
    if evidence.get("stored_report_sha256") and digest(stored) != evidence["stored_report_sha256"]:
        raise ValueError("stored adapter report digest mismatch")
    full = json.loads(json.dumps(stored))
    ref = evidence.get("raw_evidence_ref")
    if ref and evidence.get("raw_evidence_status") == "stored_separately":
        source = (Path(data_dir) / ref).resolve()
        if not source.is_relative_to(Path(data_dir).resolve()):
            raise ValueError("raw evidence reference leaves data directory")
        raw = json.loads(source.read_text())
        if digest(raw) != evidence["raw_evidence_sha256"]:
            raise ValueError("raw evidence digest mismatch")
        full["details"] = dict(full.get("details") or {})
        full["details"].pop("raw_evidence_ref", None)
        full["details"].pop("raw_evidence_sha256", None)
        full["details"]["raw_evidence"] = raw
    if digest(full) != evidence["adapter_report_sha256"]:
        raise ValueError("original adapter report digest mismatch")
    return full


def backfill_snapshots(data_dir: Path) -> int:
    """Import untouched historical daily snapshots as labeled legacy adapter data."""
    data_dir = Path(data_dir)
    count = 0
    for path in sorted((data_dir / "snapshots").glob("*.json")):
        snapshot = json.loads(path.read_text())
        run_id = "legacy-" + digest(snapshot)[:24]
        if (data_dir / "observations" / "runs" / f"{run_id}.json").exists():
            continue
        requested = {p: [r["model"] for r in rows] for p, rows in snapshot.get("attestations", {}).items()}
        # An old daily file does not say whether omitted providers were skipped.
        record_run(data_dir, snapshot, requested, complete=False, legacy=True,
                   source_snapshot=str(path.relative_to(data_dir)))
        count += 1
    return count


def seed_current(data_dir: Path) -> bool:
    """Import only the current legacy view before a first targeted run.

    This protects unprobed routes without requiring a full historical backfill.
    A matching immutable daily snapshot is reused; otherwise one compact seed
    snapshot is retained before latest.json is replaced.
    """
    data_dir = Path(data_dir)
    if load_runs(data_dir) or not (data_dir / "latest.json").exists():
        return False
    snapshot = json.loads((data_dir / "latest.json").read_text())
    if not snapshot.get("attestations"):
        return False
    daily = data_dir / "snapshots" / f"{str(snapshot.get('generated_at', ''))[:10]}.json"
    if daily.exists() and digest(json.loads(daily.read_text())) == digest(snapshot):
        source = daily
    else:
        source = data_dir / "observations" / "seed" / f"{digest(snapshot)}.json"
        if not source.exists():
            _write_new(source, snapshot)
    requested = {p: [r["model"] for r in rows] for p, rows in snapshot["attestations"].items()}
    record_run(data_dir, snapshot, requested, complete=False, legacy=True,
               source_snapshot=str(source.relative_to(data_dir)))
    return True


def derive_latest(data_dir: Path, *, catalog_models: dict[str, list[str]] | None = None) -> dict:
    """Merge routes across runs. A partial run changes only its requested routes."""
    runs = sorted(load_runs(data_dir), key=lambda x: (x["started_at"], x["run_id"]))
    observations = load_observations(data_dir)
    by_run = {r["run_id"]: r for r in runs}
    current: dict[str, dict] = {}
    freshness: dict[str, dict] = {}
    for obs in observations:
        key = obs["route_id"]
        run = by_run.get(obs["run_id"])
        if run is None:
            continue
        prior = freshness.get(key, {})
        clocks = dict(prior)
        clocks["last_attempt_at"] = obs["captured_at"]
        if obs["evidence"]["adapter_report"] is not None and obs["outcome"] not in ("unavailable", "not_checked"):
            clocks["last_capture_at"] = obs["captured_at"]
        if obs["outcome"] == "verified" and not obs["legacy"]:
            clocks["last_adapter_verified_at"] = obs["captured_at"]
        if (obs["outcome"] == "verified" and
                ((obs["evidence"]["adapter_report"] or {}).get("details") or {}).get(
                    "cryptographic_verification_completed") is True):
            clocks["last_cryptographic_verification_at"] = obs["captured_at"]
        clocks.setdefault("last_cryptographic_verification_at", None)
        clocks.setdefault("last_policy_review_at", None)
        clocks.setdefault("last_triage_at", None)
        freshness[key] = clocks
        current[key] = obs
    for path in sorted((Path(data_dir) / "reviews" / "decisions").glob("*.json")):
        decision = json.loads(path.read_text())
        reviewed_at = (decision.get("review") or {}).get("at")
        if not reviewed_at:
            continue
        routes = decision.get("event", {}).get("affected_routes") or [decision.get("event", {}).get("route_id")]
        for route in routes:
            if route not in freshness:
                continue
            clocks = freshness[route]
            if not clocks["last_triage_at"] or reviewed_at > clocks["last_triage_at"]:
                clocks["last_triage_at"] = reviewed_at
            if (decision["review"].get("disposition") in {"accepted", "rejected"} and
                    (not clocks["last_policy_review_at"] or reviewed_at > clocks["last_policy_review_at"])):
                clocks["last_policy_review_at"] = reviewed_at
    # Only a completed full run can establish that a previously known route was
    # omitted from the current catalog. Omission is unknown, not retirement.
    full = [r for r in runs if r["complete"] and
            (Path(data_dir) / "observations" / "completed" / f"{r['run_id']}.json").exists()]
    last_full = full[-1] if full else None
    if last_full:
        requested = {route_id(p, m) for p, models in last_full["requested_models"].items() for m in models}
        for key, obs in current.items():
            if (key not in requested and obs["reason"] != "retired" and
                    obs["captured_at"] <= last_full["started_at"]):
                obs = dict(obs)
                obs["view_status"] = "missing"
                obs["view_reason"] = "not_in_catalog"
                current[key] = obs
    attestations: dict[str, list[dict]] = {}
    rows_meta: dict[str, dict] = {}
    for key, obs in sorted(current.items()):
        provider, model = obs["provider"], obs["model"]
        report = obs["evidence"]["adapter_report"]
        status = obs.get("view_status") or (
            "retired" if obs["reason"] == "retired" else
            "current" if obs["outcome"] == "verified" else "unknown")
        if report is None:
            report = {"provider": provider, "model": model, "valid": False,
                      "verified_at": obs["captured_at"], "attestation_type": "missing",
                      "scorecard": {}, "details": {}, "error": obs["reason"]}
        else:
            report = dict(report)
        report.update({"observation_id": obs["observation_id"], "row_status": status,
                       "outcome": obs["outcome"] if status != "missing" else "unavailable",
                       "outcome_reason": obs.get("view_reason", obs["reason"]),
                       "outcome_reason_detail": obs.get("reason_detail"),
                       "freshness": freshness[key]})
        if status == "missing":
            report["valid"] = False
        attestations.setdefault(provider, []).append(report)
        rows_meta[key] = {"observation_id": obs["observation_id"], "row_status": status,
                          "outcome": report["outcome"], "reason": report["outcome_reason"],
                          "freshness": freshness[key]}
    newest = runs[-1] if runs else None
    return {"schema_version": SCHEMA_VERSION,
            "generated_at": newest["started_at"] if newest else utc_now(),
            "git_sha": newest["git_sha"] if newest else "",
            "run_id": newest["run_id"] if newest else "",
            "attestations": attestations, "pricing": {},
            "route_observations": rows_meta,
            "view_completeness": "complete" if newest and newest["complete"] else "partial"}


def write_latest(data_dir: Path, *, catalog_models: dict[str, list[str]] | None = None,
                 pricing: dict | None = None) -> dict:
    view = derive_latest(data_dir, catalog_models=catalog_models)
    if pricing is not None:
        view["pricing"] = pricing
    elif (Path(data_dir) / "latest.json").exists():
        view["pricing"] = json.loads((Path(data_dir) / "latest.json").read_text()).get("pricing", {})
    _replace(Path(data_dir) / "latest.json", view)
    return view
