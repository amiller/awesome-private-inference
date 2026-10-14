"""Render route, change, publication and adapter evidence as a static site."""
from __future__ import annotations

import fnmatch
import hashlib
import json
import re
import sys
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from probes.quality import compute as compute_quality
from probes.schema import classify_report
from probes.reference_history import build as build_reference_history
from probes.assessments import build as build_assessments, AXES, STATES
from probes.directory import validate as validate_directory, reference_export

REPO_ROOT = Path(__file__).resolve().parents[1]
DATA_LATEST = REPO_ROOT / "data/latest.json"
ROUTES_PATH = REPO_ROOT / "data/routes.json"
REFERENCES_PATH = REPO_ROOT / "data/references/latest.json"
DOCS_DIR = REPO_ROOT / "docs"
TEMPLATE_DIR = REPO_ROOT / "site/templates"
REPO_URL = "https://github.com/amiller/awesome-private-inference/blob/main/"

SCORECARD_LABELS = {
    "nonce_bound": "Fresh nonce", "tdx_verified": "TDX appraisal",
    "report_data_binds_key": "Key binding", "gpu_attested": "GPU evidence",
    "key_derives_to_address": "Address binding", "compose_hash_committed": "Compose binding",
    "prod_os_image": "Production OS", "serving_code_attested": "Serving code",
    "backend_attested": "Backend check", "gateway_reference_audited": "Gateway review",
    "catalog_serves": "Catalog serving", "sessions_publish_evidence_digests": "Session digest listing",
    "catalog_nonempty": "Catalog nonempty", "os_image_archive_declares_production": "OS archive metadata",
    "code_measurement_reproducible": "Reproduced build", "release_provenance_verified": "Release provenance",
    "measurement_matches_release": "Release measurement", "hardware_signature_verified": "Hardware signature",
    "tls_pubkey_pinned": "TLS key pin", "hpke_pubkey_attested": "HPKE key",
    "client_nonce_supported": "Client nonce", "runtime_config_fully_attested": "Runtime config",
    "attested_serving_enforced": "TEE route enforced",
}

MATRIX_KEYS = (
    "nonce_bound", "tdx_verified", "report_data_binds_key", "gpu_attested",
    "key_derives_to_address", "compose_hash_committed", "backend_attested",
)

OUTCOME_STYLE = {
    "verified": ("Adapter accepted", "bg-slate-100 text-slate-700", "The adapter accepted its scoped checks; this is not a full route verdict."),
    "rejected": ("Adapter rejected", "bg-rose-100 text-rose-800", "The adapter checked evidence and rejected it."),
    "not_checked": ("Not checked", "bg-amber-100 text-amber-800", "Complete verification is unavailable; individual checks may have passed. Consult the stated missing proof."),
    "unsupported": ("Unsupported", "bg-slate-200 text-slate-700", "The adapter cannot check this evidence surface."),
    "unavailable": ("Unavailable", "bg-slate-200 text-slate-700", "Evidence or endpoint was unavailable; this is not a cryptographic rejection."),
    "stale": ("Stale", "bg-amber-100 text-amber-800", "The latest evidence is too old for the stated freshness policy."),
    "not_applicable": ("Not applicable", "bg-slate-100 text-slate-500", "This check does not apply to this route."),
}


def source_link(source: str) -> str:
    return source if source.startswith("https://") else REPO_URL + source.lstrip("/")


def check_cell(value) -> dict:
    if value is True:
        return {"mark": "✓", "meaning": "Adapter pass", "css": "bg-emerald-100 text-emerald-800"}
    if value is False:
        return {"mark": "×", "meaning": "Adapter rejection", "css": "bg-rose-100 text-rose-800"}
    if value == "audit_pending":
        return {"mark": "○", "meaning": "Review pending", "css": "bg-amber-100 text-amber-800"}
    if value is None:
        return {"mark": "—", "meaning": "Not checked or not applicable; consult route", "css": "bg-slate-100 text-slate-500"}
    return {"mark": "?", "meaning": "Unsupported cell value", "css": "bg-slate-200 text-slate-700"}


def _load_optional(path: Path, default):
    return json.loads(path.read_text()) if path.exists() else default


def _publish_reference_archives(references: dict) -> dict:
    """Put hash-checked current raw captures inside the docs-only Pages artifact."""
    archive_dir = DOCS_DIR / "evidence"
    archive_dir.mkdir(parents=True, exist_ok=True)
    visible = []
    wanted = set()
    for original in references.get("observations", []):
        source = dict(original)
        last = source if source.get("status") == "observed" else source.get("last_success") or {}
        base, raw_path, digest = source.get("raw_base") or last.get("raw_base"), last.get("raw_path"), last.get("sha256")
        if base and raw_path and isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest):
            candidate = (REPO_ROOT / base / raw_path).resolve()
            # The data index may be malformed or produced outside this checkout.
            # Never publish arbitrary local files or paths escaping the repository.
            if candidate.is_relative_to(REPO_ROOT.resolve()) and candidate.is_file():
                body = candidate.read_bytes()
                if hashlib.sha256(body).hexdigest() != digest:
                    raise ValueError(f"reference archive hash mismatch: {source['source_id']}")
                name = re.sub(r"[^a-zA-Z0-9_.-]", "_", source["source_id"]) + "-" + digest + ".bin"
                target = archive_dir / name
                if target.exists() and hashlib.sha256(target.read_bytes()).hexdigest() != digest:
                    raise ValueError(f"published archive hash mismatch: {name}")
                if not target.exists():
                    target.write_bytes(body)
                source["archive_url"] = "./evidence/" + name
                wanted.add(name)
        visible.append(source)
    for stale in archive_dir.glob("*.bin"):
        if stale.name not in wanted:
            stale.unlink()  # generated copy; immutable original remains under data/references/
    return {**references, "observations": visible}


def _timeline() -> list[dict]:
    events = []
    for family, directory in (("route", REPO_ROOT / "data/continuity/events"),
                              ("publication", REPO_ROOT / "data/references/events")):
        for path in directory.glob("*.json"):
            event = json.loads(path.read_text())
            decision_path = REPO_ROOT / "data/reviews/decisions" / (str(event.get("event_id")) + ".json")
            if decision_path.is_file():
                decision = json.loads(decision_path.read_text())
                if decision.get("event") != event:
                    raise ValueError("review decision does not match immutable event")
                event = {**event, "review": decision["review"], "draft": decision["draft"],
                         "review_url": source_link(str(decision_path.relative_to(REPO_ROOT)))}
            when = event.get("first_seen_at") or event.get("timestamp") or ""
            events.append({**event, "family": family, "when": when,
                           "source_url": source_link(str(path.relative_to(REPO_ROOT)))})
    return sorted(events, key=lambda e: (e["when"], e.get("event_id", "")), reverse=True)


def _rows(snapshot: dict) -> list[dict]:
    rows = []
    for provider, reports in snapshot.get("attestations", {}).items():
        for report in reports:
            outcome = report.get("outcome") or classify_report(report)[0]
            label, css, description = OUTCOME_STYLE.get(outcome, ("Unknown", "bg-slate-200 text-slate-700", "Unknown outcome"))
            legacy = (report.get("outcome_reason") == "legacy_adapter_result" or
                      (not report.get("observation_id") and not report.get("outcome")))
            if legacy and outcome in ("verified", "rejected"):
                label = "Legacy adapter accepted" if outcome == "verified" else "Legacy adapter rejected"
                description = "Historical adapter valid flag; this predates typed observations and is not a complete route verdict."
            scorecard = report.get("scorecard") or {}
            rows.append({"provider": provider, "model": report.get("model", ""),
                         "route_id": f"{provider}/{report.get('model', '')}",
                         "outcome": outcome, "outcome_label": label, "outcome_css": css,
                         "outcome_title": description,
                         "reason": "legacy_adapter_result" if legacy and outcome in ("verified", "rejected") else
                                   (report.get("outcome_reason") or classify_report(report)[1]),
                         "error": report.get("error"), "checked_at": report.get("verified_at"),
                         "observation_id": report.get("observation_id"),
                         "freshness": report.get("freshness") or {},
                         "attestation_type": report.get("attestation_type", ""),
                         "matrix_cells": {key: check_cell(scorecard.get(key)) for key in MATRIX_KEYS},
                         "checks": [{"key": key, "label": SCORECARD_LABELS.get(key, key.replace("_", " ").title()), **check_cell(value)}
                                    for key, value in sorted(scorecard.items())],
                         "checked_count": sum(value is True or value is False for value in scorecard.values())})
    rows.sort(key=lambda row: (row["provider"], row["model"]))
    for index, row in enumerate(rows):
        row["evidence_id"] = f"observation-{index + 1}"
    return rows


def _route_cards(routes: dict, rows: list[dict], references: dict) -> list[dict]:
    source_rows = references.get("observations", [])
    cards = []
    for route in routes.get("routes", []):
        aliases = route.get("observation_aliases", [])
        matched = [row for row in rows if any(fnmatch.fnmatchcase(row["route_id"], alias) for alias in aliases)]
        publications = [source for source in source_rows if source.get("provider") == route.get("provider")]
        cards.append({**route, "sources_linked": [{"label": source, "url": source_link(source)} for source in route.get("sources", [])],
                      "matched_rows": matched, "publications": publications,
                      "latest_publication": max((source.get("observed_at", "") for source in publications), default="")})
    return cards


def _render(snapshot: dict) -> None:
    routes = _load_optional(ROUTES_PATH, {"routes": [], "as_of": None})
    DOCS_DIR.mkdir(exist_ok=True)
    references = _publish_reference_archives(_load_optional(REFERENCES_PATH, {"observations": [], "summaries": {}, "mirror_agreements": {}}))
    rows = _rows(snapshot)
    quality = compute_quality(snapshot)
    timeline = _timeline()
    cards = _route_cards(routes, rows, references)
    pricing_rows = [row for group in snapshot.get("pricing", {}).values() for row in group]
    env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)), autoescape=select_autoescape(["html", "j2"]))
    ctx = {"snapshot": snapshot, "generated_at": snapshot.get("generated_at", ""),
           "run_id": snapshot.get("run_id", "local"), "git_sha": snapshot.get("git_sha", ""),
           "rows": rows, "route_cards": cards, "routes_as_of": routes.get("as_of"),
           "references": references, "timeline": timeline[:20], "timeline_total": len(timeline),
           "reviewed_events": [event for event in timeline if event.get("review")][:5],
           "quality": quality, "pricing_rows": pricing_rows,
           "matrix_keys": MATRIX_KEYS,
           "candidate_providers": sorted({r["provider"] for r in cards} - {r["provider"] for r in rows}),
           "scorecard_labels": SCORECARD_LABELS, "outcome_style": OUTCOME_STYLE,
           "repo_url": REPO_URL}
    ctx["history"] = build_reference_history(REPO_ROOT)
    catalog = _load_optional(REPO_ROOT / "data/verifiers.json", None)
    if catalog is not None:
        validate_directory(catalog, routes)
    else:
        catalog = {"schema_version": 1, "source_revision": "", "providers": [],
                   "review_scope": "No curated directory is available in this evidence checkout."}
    ctx["verifier_catalog"] = {**catalog, "providers": [
        {**item, "implementations": [{**impl, "source_url": impl["source"] if impl["source"].startswith("https://") else
          REPO_URL.replace("/main/", "/" + catalog["source_revision"] + "/") + impl["source"]}
          for impl in item["implementations"]],
         "evidence_linked": [{"label": source, "url": REPO_URL.replace("/main/", "/" + catalog["source_revision"] + "/") + source}
                             for source in item["evidence"]]}
        for item in catalog["providers"]]}
    for name, value in (("verifiers.json", catalog), ("reference-values.json", reference_export(ctx["history"]))):
        (DOCS_DIR / name).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    assessment_data = _load_optional(REPO_ROOT / "data/assessments/routes.json", {"rubric_version": 1, "routes": []})
    ctx["assessment_groups"] = build_assessments(assessment_data, cards, ctx["history"], ctx["generated_at"])
    ctx["assessment_axes"] = AXES
    ctx["assessment_states"] = STATES
    for page, template in (("index.html", "index.html.j2"),
                           ("verifiers.html", "verifiers.html.j2"),
                           ("stages.html", "stages.html.j2"),
                           ("assessments.html", "assessments.html.j2"),
                           ("measurements.html", "measurements.html.j2"),
                           ("evidence.html", "evidence.html.j2"),
                           ("methodology.html", "methodology.html.j2"),
                           ("pricing.html", "pricing.html.j2"),
                           ("history.html", "history.html.j2")):
        rendered = env.get_template(template).render(**ctx)
        (DOCS_DIR / page).write_text("\n".join(line.rstrip() for line in rendered.splitlines()) + "\n")
    print(f"wrote dashboard, directory, stage criteria and reference exports to {DOCS_DIR}")


def main() -> int:
    if not DATA_LATEST.exists():
        print(f"no snapshot at {DATA_LATEST}; run `python -m probes.collect` first", file=sys.stderr)
        return 1
    _render(json.loads(DATA_LATEST.read_text()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
