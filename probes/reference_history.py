"""Evidence-derived history, not a deployment clock or an audit-effort estimate."""
from __future__ import annotations
from collections import defaultdict
from datetime import date, timedelta
import difflib
import fnmatch
import hashlib
import json
from pathlib import Path
import re

from probes.observations import _identities, load_observations, digest

HEX = re.compile(r"(?:sha256:)?[a-fA-F0-9]{40,}")


def reference_leaves(value, path=""):
    """Keep paths as well as values: identical digests in different fields differ."""
    found = []
    if isinstance(value, dict):
        for key, child in value.items():
            if HEX.fullmatch(key):
                found.append(f"{path}/policy-key={key}")
            found.extend(reference_leaves(child, f"{path}/{key}"))
    elif isinstance(value, list):
        for child in value:
            # Lists are compared as sets, without mistaking a reorder for a change.
            found.extend(reference_leaves(child, path + "/*"))
    elif isinstance(value, str) and HEX.fullmatch(value):
        found.append(f"{path}={value}")
    return sorted(set(found))


def text_delta(old, new):
    if old is None or new is None:
        return None
    before, after = old.splitlines(), new.splitlines()
    added = removed = 0
    for kind, a, b, c, d in difflib.SequenceMatcher(None, before, after, autojunk=False).get_opcodes():
        if kind in ("insert", "replace"):
            added += d - c
        if kind in ("delete", "replace"):
            removed += b - a
    return {"added": added, "removed": removed, "unit": "captured document lines, not deployed code LOC"}


def build(root: Path):
    points = defaultdict(list)
    metadata = {}
    routes_path = root / "data/routes.json"
    routes = json.loads(routes_path.read_text()).get("routes", []) if routes_path.exists() else []
    snapshots = sorted((root / "data/snapshots").glob("*.json"))
    observed_days = set()

    def add(provider, component, field, family, when, values, evidence, scope, aliases=(), text=None):
        key = f"{provider}|{component}|{field}|{family}"
        matched = [r["id"] for r in routes if r.get("provider") == provider and
                   (not aliases or any(fnmatch.fnmatchcase(a, pattern) for a in aliases
                    for pattern in r.get("observation_aliases", [])))]
        metadata.setdefault(key, {"id": key, "provider": provider, "component": component,
                                  "field": field, "family": family, "routes": set()})["routes"].update(matched)
        points[key].append({"at": when, "values": sorted(set(values)), "evidence": evidence,
                            "scope": scope, "text": text})

    def report(provider, row, when, path, scope):
        model = row.get("model", "unknown")
        ids = _identities(provider, model, row.get("details") or {})
        if provider == "redpill" and row.get("details", {}).get("os_image"):
            ids.append({"component_id": "legacy RedPill", "kind": "os_image_tag",
                        "value": row["details"]["os_image"], "model_scope": model})
        groups = defaultdict(list)
        for item in ids:
            component = item["component_id"]
            # Historical Tinfoil rows include model enclaves, not just the router.
            if provider == "tinfoil":
                component = f"tinfoil/{model}"
            elif item["model_scope"] != "*":
                component += "/" + item["model_scope"]
            groups[component, item["kind"]].append(item["value"])
        for (component, field), values in groups.items():
            add(provider, component, field, "reported workload", when, values, path,
                scope, [f"{provider}/{model}"])

    for path in snapshots:
        snap = json.loads(path.read_text())
        when = snap.get("generated_at") or path.stem + "T00:00:00Z"
        observed_days.add(when[:10])
        for provider, rows in snap.get("attestations", {}).items():
            for row in rows:
                report(provider, row, when, str(path.relative_to(root)), "historical adapter report; not independently verified")
    run_times = {p.stem: json.loads(p.read_text())["started_at"] for p in
                 (root / "data/observations/runs").glob("*.json")}
    for obs in load_observations(root / "data"):
        if obs.get("legacy"):
            continue
        row = obs.get("evidence", {}).get("adapter_report")
        if row:
            report(obs["provider"], row, run_times.get(obs["run_id"], obs["captured_at"]),
                   f"data/observations/records/{obs['observation_id']}.json", "adapter outcome: " + obs["outcome"])
        raw_ref = obs.get("evidence", {}).get("raw_evidence_ref")
        if not raw_ref:
            continue
        raw_path = (root / "data" / raw_ref).resolve()
        if not raw_path.is_relative_to((root / "data").resolve()):
            raise ValueError("raw observation path escapes data")
        raw = json.loads(raw_path.read_text())
        if digest(raw) != obs["evidence"]["raw_evidence_sha256"]:
            raise ValueError("raw observation evidence hash mismatch")
        stamp = run_times.get(obs["run_id"], obs["captured_at"])
        evidence = "data/" + raw_ref
        for field, component, family in (("golden_measurements", "Chutes golden measurements", "published reference set"),
                                         ("anchor_policy", "NEAR client anchor", "client policy")):
            if field in raw:
                value = raw[field]
                entries = [json.dumps(v, sort_keys=True) for v in value] if isinstance(value, list) else reference_leaves(value)
                if entries:
                    add(obs["provider"], component, "reference entries", family, stamp, entries,
                        evidence, "captured policy input; enforcement and workload coverage require separate checks")
        if isinstance(raw.get("app_compose"), str):
            body = raw["app_compose"]
            add(obs["provider"], "gateway compose", "document SHA-256", "published document", stamp,
                [hashlib.sha256(body.encode()).hexdigest()], evidence,
                "measured compose preimage captured by adapter; not a full source tree", text=body)

    for path in sorted((root / "data/references/observations").glob("*.json")):
        capture = json.loads(path.read_text())
        for item in capture.get("observations", []):
            if item.get("status") != "observed" or item.get("kind") == "model_catalog":
                continue
            raw = (path.parent / item.get("raw_path", "missing")).resolve()
            if not raw.is_relative_to((root / "data/references").resolve()):
                raise ValueError("publication path escapes reference archive")
            if not raw.is_file():
                continue
            body = raw.read_bytes()
            if hashlib.sha256(body).hexdigest() != item["sha256"]:
                raise ValueError(f"corrupt reference capture: {raw}")
            text = body.decode("utf-8", errors="replace")
            when = item.get("observed_at", capture.get("captured_at"))
            provider, component = item["provider"], item["source_id"]
            source = str(raw.relative_to(root))
            add(provider, component, "document SHA-256", "published document", when,
                [item["sha256"]], source, "publication bytes only; no signature or runtime verification", text=text)
            try:
                parsed = json.loads(text)
            except ValueError:
                continue
            values = reference_leaves(parsed)
            if values:
                add(provider, component, "reference entries", "published reference set", when,
                    values, source, "digest-shaped entries in captured JSON; not proof of client acceptance")

    # Ledger dates are declared review dates, not observation/deployment dates.
    # Cumulative admission is not inferred: each dated record is a review event.
    reviews = []
    for path in sorted((root / "data/audits").glob("*.json")):
        doc = json.loads(path.read_text())
        for audit in doc.get("audits", []):
            full = {k: v for k, v in audit.items() if k in ("image_digest", "bundle_digest", "mrtd")
                    and isinstance(v, str) and HEX.fullmatch(v) and not audit.get(k + "_truncated")}
            if full:
                reviews.append({"at": audit.get("audited_at"), "provider": path.stem.split("_")[0], "values": list(full.values()),
                                "evidence": str(path.relative_to(root)), "verdict": audit.get("verdict"),
                                "scope": doc.get("_comment", "")})

    lanes, events = [], []
    for key in sorted(points):
        lane = metadata[key]
        lane["routes"] = sorted(lane["routes"])
        # Concurrent host/model samples form a set. They are not ordered rollouts.
        merged = {}
        for point in points[key]:
            token = point["at"]
            if token in merged:
                merged[token]["values"] = sorted(set(merged[token]["values"]) | set(point["values"]))
            else:
                merged[token] = dict(point)
        samples = sorted(merged.values(), key=lambda p: p["at"])
        previous = None
        seen = set()
        lane_events = []
        for point in samples:
            values = frozenset(point["values"])
            if previous is None or values != frozenset(previous["values"]):
                old = set(previous["values"]) if previous else set()
                kind = "baseline" if previous is None else "revisit" if values in seen else "new set"
                matches = [r for r in reviews if r["provider"] == lane["provider"] and
                           lane["family"] == "reported workload" and
                           (lane["provider"] != "tinfoil" or lane["component"] == "tinfoil/router") and
                           set(point["values"]) & set(r["values"])]
                event = {"id": hashlib.sha256((key + point["at"]).encode()).hexdigest()[:20],
                         "lane": key, "provider": lane["provider"], "at": point["at"], "kind": kind,
                         "old": sorted(old), "new": point["values"],
                         "added": sorted(values - old), "removed": sorted(old - values),
                         "previous_at": previous["at"] if previous else None,
                         "evidence": point["evidence"], "previous_evidence": previous["evidence"] if previous else None,
                         "scope": point["scope"], "reviews": matches,
                         "text_delta": text_delta(previous["text"], point["text"]) if previous else None,
                         "code_delta": None}
                events.append(event); lane_events.append(event["id"])
            seen.add(values)
            previous = point
        lane.update(first=samples[0]["at"], last=samples[-1]["at"], latest=samples[-1]["values"],
                    evidence=samples[-1]["evidence"], scope=samples[-1]["scope"],
                    sample_days=sorted({p["at"][:10] for p in samples}), samples=len(samples),
                    unique_values=len(set(v for p in samples for v in p["values"])),
                    events=lane_events, changes=max(0, len(lane_events) - 1))
        lanes.append(lane)
    times = sorted(e["at"] for e in events)
    gaps = []
    if observed_days:
        cursor, last = date.fromisoformat(min(observed_days)), date.fromisoformat(max(observed_days))
        while cursor <= last:
            if cursor.isoformat() not in observed_days:
                gaps.append(cursor.isoformat())
            cursor += timedelta(days=1)
    return {"schema_version": 1, "lanes": lanes, "events": sorted(events, key=lambda e: (e["at"], e["id"])),
            "reviews": reviews, "first": times[0] if times else None, "last": times[-1] if times else None,
            "snapshot_gap_days": gaps, "inventory_providers": sorted({r["provider"] for r in routes}),
            "limits": ["All extracted tracked values, not all provider values or models.",
                       "First observed is not deployment time; absence is not retirement.",
                       "Digest changes do not measure code size, risk, or audit effort.",
                       "Raw publication and historical adapter reports are not verified client acceptance.",
                       "Source-to-deployed-code diff is unknown unless separately established."]}
