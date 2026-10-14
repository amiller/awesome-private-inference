"""Capture immutable attempts, then derive the current registry view.

Usage:
    python -m probes.collect               # attestation only
    python -m probes.collect --pricing     # also sweep catalog pricing (costs cents)
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from probes import attestation, pricing, catalog
from probes.schema import SCHEMA_VERSION
from probes import observations, continuity, instrument

REPO_ROOT = Path(__file__).resolve().parents[1]
SNAPSHOT_DIR = REPO_ROOT / "data" / "snapshots"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pricing", action="store_true",
                    help="also run pricing sweep (costs real $, off by default)")
    ap.add_argument("--providers", default="aci-gateway,near-ai,tinfoil,venice,chutes",
                    help="comma-separated provider slugs")
    ap.add_argument("--backfill", action="store_true",
                    help="import existing daily snapshots as labeled legacy records; no network probes")
    args = ap.parse_args()

    data_dir = REPO_ROOT / "data"
    if args.backfill:
        count = observations.backfill_snapshots(data_dir)
        print(f"imported {count} legacy daily snapshots")
        return 0

    providers = [p.strip() for p in args.providers.split(",") if p.strip()]
    unknown = sorted(set(providers) - attestation.PROVIDERS.keys())
    if unknown:
        print(f"unknown provider(s): {', '.join(unknown)}", file=sys.stderr)
        return 2
    observations.seed_current(data_dir)
    requested = {p: catalog.MODELS.get(p, []) for p in providers}
    complete = set(providers) == set(catalog.MODELS)
    provenance = instrument.capture(REPO_ROOT, os.environ.get("NEARAI_VERIFIER_PATH", ""))
    if "near-ai" in providers and provenance["upstream_actual_revision"] != provenance["upstream_expected_revision"]:
        print("NEAR verifier checkout differs from data/instrument.json; refusing unpinned run", file=sys.stderr)
        return 2
    run = observations.start_run(
        data_dir, requested, complete=complete,
        git_sha=os.environ.get("GITHUB_SHA") or provenance["repository_commit"],
        verifier_revision=provenance["revision"], instrument=provenance,
        policy_revisions={p: os.environ.get(f"{p.upper().replace('-', '_')}_POLICY_REVISION", "unknown")
                          for p in providers},
    )
    snapshot = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": run["started_at"],
        "git_sha": run["git_sha"],
        "run_id": run["run_id"],
        "attestations": {},
        "pricing": {},
    }

    for p in providers:
        print(f"=== attestation: {p} ===", flush=True)
        reports = attestation.probe_provider(p, catalog.MODELS.get(p, []))
        by_model = {r.model: r.as_dict() for r in reports}
        stored_rows = []
        for model in requested[p]:
            result = observations.finish_attempt(data_dir, run, p, model, by_model.get(model))
            stored = result["evidence"]["adapter_report"]
            stored_rows.append(stored if stored is not None else {
                "provider": p, "model": model, "valid": False,
                "verified_at": result["captured_at"], "attestation_type": "missing",
                "scorecard": {}, "details": {}, "error": "missing_response",
            })
        snapshot["attestations"][p] = stored_rows
        ok = sum(1 for r in reports if r.valid)
        print(f"    {ok}/{len(reports)} passed", flush=True)

        if args.pricing:
            print(f"=== pricing: {p} ===", flush=True)
            rows = pricing.sweep(p, catalog.MODELS.get(p, []))
            snapshot["pricing"][p] = [r.as_dict() for r in rows]

    observations.finish_run(data_dir, run)
    view = observations.write_latest(data_dir, catalog_models=catalog.MODELS,
                                     pricing=snapshot["pricing"] if args.pricing else None)
    events = continuity.derive_events(observations.load_observations(data_dir),
                                      expected_routes=[observations.route_id(p, m)
                                                       for p, models in catalog.MODELS.items()
                                                       for m in models])
    created = continuity.persist_events(data_dir, events)
    if complete:
        SNAPSHOT_DIR.mkdir(parents=True, exist_ok=True)
        date = run["started_at"][:10]
        path = SNAPSHOT_DIR / f"{date}.json"
        try:
            with path.open("x") as file:
                json.dump(snapshot, file, indent=2, default=str)
                file.write("\n")
            print(f"\nwrote {path.relative_to(REPO_ROOT)}")
        except FileExistsError:
            print(f"\nretained first daily snapshot {path.relative_to(REPO_ROOT)}")
    print(f"wrote data/latest.json from {len(view['route_observations'])} routes; {len(created)} new change events")

    totals = sum(len(v) for v in snapshot["attestations"].values())
    passes = sum(1 for v in snapshot["attestations"].values() for r in v if r["valid"])
    print(f"summary: {passes}/{totals} attestations valid")
    return 0


if __name__ == "__main__":
    sys.exit(main())
