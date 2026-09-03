"""Diff-alert brain for the devproof watcher.

Compares the current probe/on-chain state against an acked state file and
prints one line per NEW finding. The shell wrapper spawns a review agent on
findings and acks only after the spawn succeeds.

Findings:
  valid:{provider}/{model}   — row validity flips. "down" requires >=2
                               consecutive failing daily snapshots (flap damping).
  cell:{provider}/{model}/{cell} — any scorecard cell change (only while the
                               row is valid; probe outages don't churn cells).
  digest:near-ai/cloud-api   — gateway image digest changed (audit unit of the
                               analyst-pair ledger).
  anchor-drift:{contract}    — on-chain compose hashes not in the hermes
                               anchor, reported as a delta vs last ack.
  stale:{file}               — latest.json / onchain-status.json older than 26h.

Usage:
    python -m probes.diffalert --state PATH          # print new findings, exit 3 if any
    python -m probes.diffalert --state PATH --ack    # write current values into state
"""
from __future__ import annotations

import argparse
import glob
import json
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DATA = REPO_ROOT / "data"
STALE_SECONDS = 26 * 3600
DAMP_RUNS = 2  # consecutive failing snapshots before a "down" finding


def parse_ts(ts: str) -> float:
    return time.mktime(time.strptime(ts, "%Y-%m-%dT%H:%M:%SZ")) - time.timezone


def recent_snapshots(n: int = 4) -> list[dict]:
    paths = sorted(glob.glob(str(DATA / "snapshots" / "*.json")))[-n:]
    return [json.load(open(p)) for p in paths]


def current_values() -> dict[str, str]:
    latest = json.load(open(DATA / "latest.json"))
    onchain = json.load(open(DATA / "onchain-status.json"))
    snaps = recent_snapshots()
    vals: dict[str, str] = {}

    for fname, ts in [("latest.json", latest["generated_at"]),
                      ("onchain-status.json", onchain["generated_at"])]:
        stale = time.time() - parse_ts(ts) > STALE_SECONDS
        vals[f"stale:{fname}"] = f"stale@{ts}" if stale else "fresh"

    for provider, rows in latest["attestations"].items():
        for row in rows:
            rid = f"{provider}/{row['model']}"
            history = [r["valid"] for s in snaps for r in s["attestations"].get(provider, [])
                       if r["model"] == row["model"]]
            if not row["valid"] and len(history) >= DAMP_RUNS and not any(history[-DAMP_RUNS:]):
                vals[f"valid:{rid}"] = "down"
            elif row["valid"]:
                vals[f"valid:{rid}"] = "up"
            # single-snapshot failure: emit nothing yet (damping); acked value persists

            if row["valid"]:
                for cell, v in row["scorecard"].items():
                    vals[f"cell:{rid}/{cell}"] = json.dumps(v)
                details = row.get("details") or {}
                digest = details.get("cloud_api_image_digest")
                if digest:
                    vals["digest:near-ai/cloud-api"] = digest
                # tinfoil: per-model control-plane digest — every change is a real
                # deploy; fire the review agent on each.
                if provider == "tinfoil" and details.get("digest"):
                    vals[f"version:tinfoil/{row['model']}"] = details["digest"]
                # chutes: mrtd is instance-sampled and flip-flops between known
                # fleet values, so only a value NOT in our reviewed ledger is a
                # finding — the loop stays quiet on the known flip.
                if provider == "chutes" and details.get("mrtd") \
                        and not details.get("mrtd_audited", False):
                    vals[f"unaudited-mrtd:chutes/{row['model']}"] = details["mrtd"]

    for c in onchain["contracts"]:
        if c["anchor_relevant"] and c["new_since_anchor"] is not None:
            hashes = sorted(h["compose_hash"] for h in c["new_since_anchor"])
            vals[f"anchor-drift:{c['label']}"] = ",".join(hashes)

    return vals


def describe(key: str, old: str | None, new: str) -> str:
    if key.startswith("anchor-drift:"):
        added = sorted(set(new.split(",")) - set((old or "").split(",")) - {""})
        removed = sorted(set((old or "").split(",")) - set(new.split(",")) - {""})
        # A hash leaves the unanchored set for exactly one good reason: it is now
        # in the anchor. Anything else that disappears is our records losing an
        # authorized hash — a reorg or a bug — and must never read as resolved.
        # The old sliding-window sweep evicted history and this printed the
        # evictions as "cleared (now anchored)" (issue #10).
        anchored = set(json.load(open(DATA / "onchain-status.json"))
                       .get("anchored_compose_hashes", []))
        cleared = [h for h in removed if h in anchored]
        vanished = [h for h in removed if h not in anchored]
        parts = []
        if added:
            parts.append(f"new unanchored compose hashes: {', '.join(added)}")
        if cleared:
            parts.append(f"cleared (now anchored): {', '.join(cleared)}")
        if vanished:
            parts.append("VANISHED from our on-chain records without being anchored "
                         f"(reorg or sweep bug — investigate): {', '.join(vanished)}")
        return f"[{key}] {'; '.join(parts)}"
    return f"[{key}] {old} -> {new}"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--state", required=True)
    ap.add_argument("--ack", action="store_true")
    args = ap.parse_args()

    state_path = Path(args.state)
    state = json.loads(state_path.read_text()) if state_path.exists() else {}
    vals = current_values()

    if args.ack:
        state.update(vals)  # merge: keys not computable this run keep acked values
        state_path.parent.mkdir(parents=True, exist_ok=True)
        state_path.write_text(json.dumps(state, indent=1, sort_keys=True))
        print(f"acked {len(vals)} keys -> {state_path}")
        return 0

    if not state:
        print(f"no state at {state_path}; run --ack to initialize baseline")
        return 2

    findings = [describe(k, state.get(k), v) for k, v in sorted(vals.items())
                if state.get(k) != v]
    for f in findings:
        print(f)
    return 3 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
