"""Observed identity transitions and legacy adapter outcomes.

A first-seen value is a newly observed identity, not proof of a deployment.
A revisit may be fleet sampling, rollback, recovery or an observation artifact.
Control-plane publications can also revert. No fleet-size or corrected deployment
rate is inferred from these snapshots.

Usage: python -m probes.trajectory
"""
from __future__ import annotations

import collections
import datetime
import json
import re
import sys
from pathlib import Path

SNAPSHOTS = Path(__file__).resolve().parents[1] / "data" / "snapshots"
LATEST = Path(__file__).resolve().parents[1] / "data" / "latest.json"

# What names the running code version, per provider. `None` = the provider
# exposes no version identity, so its trajectory is unmeasurable.
VERSION_FIELD = {
    "near-ai": "cloud_api_image_digest",
    "tinfoil": "digest",
    "chutes": "mrtd",
    "venice": None,
}

TRANSPORT = re.compile(
    r"HTTP [45]\d\d|ConnectionError|SSLError|Timeout|"
    r"no TEE attestation available|catalog-only", re.I)


def load():
    for p in sorted(SNAPSHOTS.glob("*.json")):
        yield p.stem, json.loads(p.read_text())


def main() -> int:
    snapshots = list(load())
    active = json.loads(LATEST.read_text())
    active_providers = set(active.get("attestations", {}))
    outcomes = collections.Counter(
        {k: 0 for k in ("pass", "transport / liveness",
                        "invalid, no error recorded", "verification failure")})
    history = collections.defaultdict(list)

    for date, snap in snapshots:
        for provider, rows in snap.get("attestations", {}).items():
            if provider not in active_providers:
                continue
            for row in rows:
                err = row.get("error") or ""
                if row.get("valid"):
                    outcomes["pass"] += 1
                elif not err:
                    outcomes["invalid, no error recorded"] += 1
                elif TRANSPORT.search(err):
                    outcomes["transport / liveness"] += 1
                else:
                    outcomes["verification failure"] += 1

                field = VERSION_FIELD[provider]
                version = (row.get("details") or {}).get(field) if field else None
                if version:
                    history[(provider, row["model"])].append((date, version))

    total = sum(outcomes.values())
    print(f"=== failure modes: {total} provider-model-days ===")
    for k, v in outcomes.most_common():
        print(f"  {k:28s} {v:5d}  {100 * v / total:5.1f}%")

    print(f"\n=== observed identity transitions ===")
    print(f"{'target':46s} {'obs':>4s} {'days':>5s} {'uniq':>4s} "
          f"{'novel':>5s} {'revisit':>7s} {'days/new-id':>11s}")
    fmt = "%Y-%m-%d"
    for (provider, model), obs in sorted(history.items()):
        seen, novel, revisit, prev = set(), 0, 0, None
        for _, version in obs:
            if prev is not None and version != prev:
                if version in seen:
                    revisit += 1
                else:
                    novel += 1
            seen.add(version)
            prev = version
        span = (datetime.datetime.strptime(obs[-1][0], fmt)
                - datetime.datetime.strptime(obs[0][0], fmt)).days
        cadence = f"{span / novel:.1f}" if novel else "not observed"
        print(f"{provider + '/' + model:46.46s} {len(obs):4d} {span:5d} "
              f"{len(seen):4d} {novel:5d} {revisit:7d} {cadence:>11s}")

    untracked = [p for p in active_providers if VERSION_FIELD[p] is None]
    print(f"\nno version identity exposed, trajectory unmeasurable: {', '.join(untracked)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
