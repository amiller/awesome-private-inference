"""Render data/latest.json → docs/ static dashboard.

Pure-Python, Tailwind via CDN. No Node build step.

Usage:
    python -m probes.render
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

REPO_ROOT = Path(__file__).resolve().parents[1]
DATA_LATEST = REPO_ROOT / "data" / "latest.json"
DOCS_DIR = REPO_ROOT / "docs"
TEMPLATE_DIR = REPO_ROOT / "site" / "templates"


SCORECARD_LABELS = {
    "nonce_bound": "Nonce bound",
    "tdx_verified": "TDX quote",
    "report_data_binds_key": "report_data binds key",
    "gpu_attested": "GPU attested",
    "key_derives_to_address": "Key derives to addr",
    "compose_hash_committed": "compose_hash committed",
    "backend_attested": "Backend attested",
    "catalog_serves": "Catalog serves",
}

SCORECARD_TOOLTIPS = {
    "nonce_bound": "Client-supplied nonce appears in TDX report_data",
    "tdx_verified": "Intel TDX quote accepted by Phala's public verifier",
    "report_data_binds_key": "report_data commits to signing address + nonce",
    "gpu_attested": "NVIDIA NRAS returned PASS on the GPU payload",
    "key_derives_to_address": "keccak(signing_public_key) == signing_address",
    "compose_hash_committed": "mr_config starts with 0x01 || sha256(app_compose)",
    "backend_attested": "Gateway cryptographically verified the backend TDX quote",
    "catalog_serves": "Model advertised in /models returns 2xx on chat completion",
}


def cell(value):
    """Render a scorecard cell: ✅ / ❌ / — (None = not applicable / not tested)."""
    if value is True:
        return {"mark": "✅", "class": "bg-emerald-500/20 text-emerald-700"}
    if value is False:
        return {"mark": "❌", "class": "bg-rose-500/20 text-rose-700"}
    return {"mark": "—", "class": "text-slate-400"}


def _render(snapshot):
    # Aggregate: per-provider summary
    rows = []
    for provider, reports in snapshot.get("attestations", {}).items():
        for r in reports:
            sc = r.get("scorecard") or {}
            rows.append({
                "provider": provider,
                "model": r["model"],
                "valid": r.get("valid", False),
                "error": r.get("error"),
                "attestation_type": r.get("attestation_type", ""),
                "signing_address": r.get("signing_address", ""),
                "latency_s": r.get("latency_s", 0),
                "cells": {k: cell(sc.get(k)) for k in SCORECARD_LABELS},
            })

    provider_summary = {}
    for p, reports in snapshot.get("attestations", {}).items():
        total = len(reports)
        passed = sum(1 for r in reports if r.get("valid"))
        provider_summary[p] = {"total": total, "passed": passed}

    pricing_rows = []
    for p, rows_ in snapshot.get("pricing", {}).items():
        pricing_rows.extend(rows_)

    env = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=select_autoescape(["html"]),
    )
    env.globals.update({
        "SCORECARD_LABELS": SCORECARD_LABELS,
        "SCORECARD_TOOLTIPS": SCORECARD_TOOLTIPS,
    })

    ctx = {
        "snapshot": snapshot,
        "generated_at": snapshot.get("generated_at", ""),
        "git_sha": snapshot.get("git_sha", ""),
        "run_id": snapshot.get("run_id", "local"),
        "rows": rows,
        "provider_summary": provider_summary,
        "pricing_rows": pricing_rows,
    }

    DOCS_DIR.mkdir(exist_ok=True)
    for page, tmpl in [("index.html", "index.html.j2"),
                      ("methodology.html", "methodology.html.j2"),
                      ("pricing.html", "pricing.html.j2")]:
        rendered = env.get_template(tmpl).render(**ctx)
        (DOCS_DIR / page).write_text(rendered)
    print(f"wrote {DOCS_DIR}/{{index,methodology,pricing}}.html")


def main() -> int:
    if not DATA_LATEST.exists():
        print(f"no snapshot at {DATA_LATEST}; run `python -m probes.collect` first",
              file=sys.stderr)
        return 1
    snap = json.loads(DATA_LATEST.read_text())
    _render(snap)
    return 0


if __name__ == "__main__":
    sys.exit(main())
