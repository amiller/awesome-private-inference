"""Quality control for the registry itself.

The registry grades providers. Nothing graded the registry. This does, from the
snapshot series on disk, and writes data/quality.json for the dashboard to render.
Coverage is scoped to the providers in data/latest.json. Outcome history is not:
a retired integration keeps its observations, so removing one cannot improve the
registry's own grade (see RETIRED_VERSION_IDENTITY).

Five questions, all answered from data rather than asserted in prose:

  coverage    — for each target, can we even measure it? A provider that exposes
                no version identity is not "passing", it is unmeasured.
  calibration — has the instrument ever fired? A detector that has never fired in
                111 days is either reporting perfect safety or is not connected.
  audit debt  — how many observed builds has a human/agent pair actually reviewed?
  freshness   — how old is the newest observation, and the newest audit?
  density     — what fraction of published cells carry signal rather than a dash?

Usage:
    python -m probes.quality            # print report
    python -m probes.quality --write    # also write data/quality.json
"""
from __future__ import annotations

import argparse
import collections
import datetime
import json
import math
import re
import sys
from pathlib import Path

from verifiers.common import REQUIRED_LAYERS_BY_SHAPE

REPO_ROOT = Path(__file__).resolve().parents[1]
DATA = REPO_ROOT / "data"
SNAPSHOTS = DATA / "snapshots"
LEDGER = DATA / "audits" / "near-ai_cloud-api.json"

# What string names the running code version, per provider, whether it is a content
# hash (a real audit unit) or a mutable tag (names nothing), and — critically — where
# the string comes from.
#
# `control-plane` means the version is read from a single document (near-ai regexes it
# out of the gateway's app_compose; tinfoil reads GitHub releases/latest), so it cannot
# reveal fleet structure and a repeated value is guaranteed by construction, not
# observed. `instance-sampled` means the value comes from whichever backend instance
# answered, so repeats are real evidence about the fleet. Only chutes is the latter,
# and conflating the two is how a load balancer gets reported as 20 deploys.
VERSION_IDENTITY = {
    "aci-gateway": ("compose_hash", "content-hash", "control-plane"),
    "near-ai": ("cloud_api_image_digest", "content-hash", "control-plane"),
    "tinfoil": ("digest", "content-hash", "control-plane"),
    "chutes": ("mrtd", "content-hash", "instance-sampled"),
    "venice": (None, "absent", "none"),
}

# Providers we no longer probe, kept so their observations still count in the
# outcome history. Retiring an integration must not retroactively improve the
# registry's own grade: redpill alone is 123 of the 130 `no-error-invalid` rows
# ever recorded, and dropping it would quietly rewrite the one statistic on this
# page that tracks the verification path rejecting something.
RETIRED_VERSION_IDENTITY = {
    "redpill": ("os_image", "mutable-tag", "control-plane"),
}

ALL_VERSION_IDENTITY = {**VERSION_IDENTITY, **RETIRED_VERSION_IDENTITY}

TRANSPORT = re.compile(
    r"HTTP [45]\d\d|ConnectionError|SSLError|Timeout|"
    r"no TEE attestation available|catalog-only", re.I)

# Rendered on the public matrix today. Six further scorecard fields are collected
# and never shown, which is why Tinfoil's row is blank; tracked as a gap below.
PUBLISHED_COLUMNS = [
    "nonce_bound", "tdx_verified", "report_data_binds_key", "gpu_attested",
    "key_derives_to_address", "compose_hash_committed", "prod_os_image",
    "serving_code_attested", "backend_attested", "attested_serving_enforced",
]


def _snapshots():
    for p in sorted(SNAPSHOTS.glob("*.json")):
        yield p.stem, json.loads(p.read_text())


def _classify(row):
    """reachable / verifies / sufficient — the three axes the board collapses into one."""
    err = row.get("error") or ""
    if err and TRANSPORT.search(err):
        return "unreachable"
    if not row.get("valid"):
        return "invalid"
    required = REQUIRED_LAYERS_BY_SHAPE.get(row.get("attestation_type", ""), set())
    if not required:
        return "uncharacterized"
    return "verified" if all(
        (row.get("scorecard") or {}).get(x) is True for x in required) else "partial"


def compute(latest: dict | None = None) -> dict:
    """Grade the registry. `latest` overrides which snapshot counts as current, so the
    renderer grades the page it is actually building rather than whatever is on disk."""
    snapshots = list(_snapshots())
    current = latest if latest is not None else json.loads((DATA / "latest.json").read_text())
    active_providers = set(current.get("attestations", {}))

    dates, outcomes = [], collections.Counter(
        {k: 0 for k in ("pass", "transport", "no-error-invalid", "verification-failure")})
    no_error_invalid = collections.Counter()
    versions = collections.defaultdict(list)

    for date, snap in snapshots:
        dates.append(date)
        for provider, rows in snap.get("attestations", {}).items():
            identity = ALL_VERSION_IDENTITY.get(provider)
            if identity is None:
                continue
            field = identity[0]
            for row in rows:
                err = row.get("error") or ""
                if row.get("valid"):
                    outcomes["pass"] += 1
                elif not err:
                    outcomes["no-error-invalid"] += 1
                    no_error_invalid[provider] += 1
                elif TRANSPORT.search(err):
                    outcomes["transport"] += 1
                else:
                    outcomes["verification-failure"] += 1
                v = (row.get("details") or {}).get(field) if field else None
                if v:
                    versions[(provider, row["model"])].append((date, v))

    # --- coverage: what can we actually measure, per live target ---
    coverage, cells = [], collections.Counter()
    for provider, rows in current.get("attestations", {}).items():
        field, kind, source = VERSION_IDENTITY[provider]
        for row in rows:
            shape = row.get("attestation_type", "")
            required = REQUIRED_LAYERS_BY_SHAPE.get(shape, set())
            sc = row.get("scorecard") or {}
            proven = sorted(x for x in required if sc.get(x) is True)
            missing = sorted(x for x in required if sc.get(x) is not True)
            coverage.append({
                "provider": provider, "model": row["model"], "shape": shape,
                "status": _classify(row),
                "proven": len(proven), "required": len(required),
                "missing": missing,
                "version_identity": kind,
                "version_source": source,
                "error": next(iter((row.get("error") or "").splitlines()), "")[:80] or None,
                # a required layer that no published column shows is invisible to a reader
                "hidden_layers": sorted(set(required) - set(PUBLISHED_COLUMNS)),
            })
            for key in PUBLISHED_COLUMNS:
                v = sc.get(key)
                cells["signal" if v is not None else "dash"] += 1

    # --- audit debt ---
    ledger = json.loads(LEDGER.read_text())
    entries = [e["image_digest"].lower() for e in ledger["audits"]]
    observed = {v for (p, _), obs in versions.items() if p == "near-ai" for _, v in obs}
    audited = {v for v in observed if any(v.startswith(e) for e in entries)}
    last_audit = max(e["audited_at"] for e in ledger["audits"])
    today = datetime.date.fromisoformat(dates[-1])

    # --- deploy cadence, novel vs revisit ---
    cadence = []
    for (provider, model), obs in sorted(versions.items()):
        seen, novel, revisit, prev = set(), 0, 0, None
        for _, v in obs:
            if prev is not None and v != prev:
                revisit += 1 if v in seen else 0
                novel += 0 if v in seen else 1
            seen.add(v)
            prev = v
        span = (datetime.date.fromisoformat(obs[-1][0])
                - datetime.date.fromisoformat(obs[0][0])).days
        # A deploy that starts and ends between two probes is invisible. With T novel
        # transitions over n-1 daily intervals, the MLE for the deploy rate is
        # lambda = -ln(1 - T/(n-1))/delta, which corrects the naive figure upward ~15%.
        intervals = len(obs) - 1
        corrected = None
        if novel and intervals and novel < intervals:
            rate = -math.log(1 - novel / intervals) / (span / intervals)
            corrected = round(1 / rate, 1)
        cadence.append({
            "provider": provider, "model": model, "observations": len(obs),
            "span_days": span, "distinct": len(seen), "novel": novel,
            "revisit": revisit,
            "version_source": ALL_VERSION_IDENTITY[provider][2],
            "retired": provider in RETIRED_VERSION_IDENTITY,
            "days_per_deploy": round(span / novel, 1) if novel else None,
            "days_per_deploy_corrected": corrected,
        })

    total_obs = sum(outcomes.values())
    return {
        "generated_at": current.get("generated_at"),
        "window": {"first": dates[0], "last": dates[-1], "days": len(dates)},
        "calibration": {
            "observations": total_obs,
            **{k: v for k, v in outcomes.items()},
            "red_cells_that_were_verification_failures": outcomes["verification-failure"],
            "no_error_invalid_by_provider": dict(sorted(no_error_invalid.items())),
            "note": (
                f"{outcomes['no-error-invalid']} of {total_obs} observations were invalid "
                "with no error attached — the verifier rejecting a row (a required layer "
                "came back False), not failing to reach it: "
                + ", ".join(f"{p} {n}" for p, n in sorted(no_error_invalid.items()))
                + ". Every other red cell was a transport error. Retired providers stay in "
                "this history; removing an integration must not improve the registry's grade."),
        },
        "coverage": coverage,
        "coverage_summary": collections.Counter(c["status"] for c in coverage),
        "unmeasurable_providers": sorted(
            p for p in active_providers if VERSION_IDENTITY[p][1] != "content-hash"),
        "audit_debt": {
            "builds_observed": len(observed),
            "builds_reviewed": len(audited),
            "backlog": len(observed) - len(audited),
            "last_audit": last_audit,
            "days_since_last_audit": (today - datetime.date.fromisoformat(last_audit)).days,
        },
        "density": {
            "published_cells": sum(cells.values()),
            "carrying_signal": cells["signal"],
            "dashes": cells["dash"],
            "signal_fraction": round(cells["signal"] / sum(cells.values()), 3),
        },
        "hidden_layer_targets": sorted(
            f"{c['provider']}/{c['model']}" for c in coverage if c["hidden_layers"]),
        "cadence": cadence,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true", help="write data/quality.json")
    args = ap.parse_args()
    q = compute()

    w, c, a, d = q["window"], q["calibration"], q["audit_debt"], q["density"]
    print(f"window        {w['first']} .. {w['last']}  ({w['days']} days)")
    print(f"calibration   {c['observations']} observations, "
          f"{c['verification-failure']} verification failures, "
          f"{c['transport']} transport, {c['no-error-invalid']} invalid-no-error")
    print(f"audit debt    {a['builds_reviewed']}/{a['builds_observed']} builds reviewed, "
          f"backlog {a['backlog']}, last audit {a['last_audit']} "
          f"({a['days_since_last_audit']}d ago)")
    print(f"density       {d['carrying_signal']}/{d['published_cells']} published cells "
          f"carry signal ({100 * d['signal_fraction']:.0f}%)")
    print(f"unmeasurable  {', '.join(q['unmeasurable_providers'])}")
    print(f"\ncoverage      " + ", ".join(
        f"{k}={v}" for k, v in sorted(q["coverage_summary"].items())))
    if q["hidden_layer_targets"]:
        print(f"\nrows whose required layers are not on any published column:")
        for t in q["hidden_layer_targets"]:
            print(f"  {t}")

    if args.write:
        (DATA / "quality.json").write_text(json.dumps(q, indent=2, default=str))
        print(f"\nwrote data/quality.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
