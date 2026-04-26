"""Top-level orchestrator — runs attestation probe (and optionally pricing sweep),
emits data/snapshots/YYYY-MM-DD.json + updates data/latest.json.

Usage:
    python -m probes.collect               # attestation only
    python -m probes.collect --pricing     # also sweep catalog pricing (costs cents)
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

from probes import attestation, pricing, catalog
from probes.schema import SCHEMA_VERSION

REPO_ROOT = Path(__file__).resolve().parents[1]
SNAPSHOT_DIR = REPO_ROOT / "data" / "snapshots"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pricing", action="store_true",
                    help="also run pricing sweep (costs real $, off by default)")
    ap.add_argument("--providers", default="near-ai,redpill,tinfoil,venice",
                    help="comma-separated provider slugs")
    args = ap.parse_args()

    providers = [p.strip() for p in args.providers.split(",") if p.strip()]
    snapshot = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "git_sha": os.environ.get("GITHUB_SHA", ""),
        "run_id": os.environ.get("GITHUB_RUN_ID", "local"),
        "attestations": {},
        "pricing": {},
    }

    for p in providers:
        if p not in attestation.PROVIDERS:
            print(f"unknown provider: {p}", file=sys.stderr)
            continue
        print(f"=== attestation: {p} ===", flush=True)
        reports = attestation.probe_provider(p, catalog.MODELS.get(p, []))
        snapshot["attestations"][p] = [r.as_dict() for r in reports]
        ok = sum(1 for r in reports if r.valid)
        print(f"    {ok}/{len(reports)} passed", flush=True)

        if args.pricing:
            print(f"=== pricing: {p} ===", flush=True)
            rows = pricing.sweep(p, catalog.MODELS.get(p, []))
            snapshot["pricing"][p] = [r.as_dict() for r in rows]

    SNAPSHOT_DIR.mkdir(parents=True, exist_ok=True)
    date = time.strftime("%Y-%m-%d", time.gmtime())
    path = SNAPSHOT_DIR / f"{date}.json"
    path.write_text(json.dumps(snapshot, indent=2, default=str))
    (REPO_ROOT / "data" / "latest.json").write_text(path.read_text())

    print(f"\nwrote {path.relative_to(REPO_ROOT)}")

    totals = sum(len(v) for v in snapshot["attestations"].values())
    passes = sum(1 for v in snapshot["attestations"].values() for r in v if r["valid"])
    print(f"summary: {passes}/{totals} attestations valid")
    return 0


if __name__ == "__main__":
    sys.exit(main())
