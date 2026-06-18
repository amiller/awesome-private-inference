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

from verifiers.common import is_layer_required, is_stage1_ready

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
    "prod_os_image": "Prod OS image",
    "model_bound_to_quote": "Model bound to quote",
    "backend_attested": "Backend attested",
}

SCORECARD_TOOLTIPS = {
    "nonce_bound": "Client-supplied nonce appears in TDX report_data",
    "tdx_verified": "Intel TDX quote accepted by Phala's public verifier",
    "report_data_binds_key": "report_data commits to signing address + nonce",
    "gpu_attested": "NVIDIA NRAS returned PASS on the GPU payload",
    "key_derives_to_address": "keccak(signing_public_key) == signing_address",
    "compose_hash_committed": "mr_config starts with 0x01 || sha256(app_compose)",
    "prod_os_image": (
        "vm_config.image is the production dstack OS image, not dstack-nvidia-dev. "
        "The dev image ships sshd + debug-tweaks + tools-profile; with "
        "DSTACK_AUTHORIZED_KEYS it gives the operator host-network-namespace root SSH "
        "inside the CVM (prompts in /proc/<vllm>/mem exfiltratable). Flips ✅ when the "
        "fleet runs dstack-nvidia-* prod."
    ),
    "model_bound_to_quote": (
        "The served model + serving code are committed to a measured register "
        "(RTMR or report_data). Red on Chutes: MRTD/RTMRs are identical across "
        "different -TEE models and serve.py is CFSV-excluded, so a verified quote "
        "proves a genuine TDX+GPU running a Chutes base image, not which model on "
        "which code (chutesai/chutes#75)."
    ),
    "backend_attested": (
        "Tri-state: ✅ gateway code self-attests + compose_hash is on-chain authorized + "
        "image digest is in our analyst-pair audit ledger. ○ chain-authorized + self-consistent "
        "but the audit ledger hasn't caught up (analyst backlog, NOT a provider fault). "
        "❌ quote not self-consistent or compose not on the on-chain authorized set."
    ),
}


def cell(value, required: bool = False):
    """Render a scorecard cell.

    ✅ — checked, passed.
    ○ — chain-authorized and self-consistent, but the analyst pair hasn't audited
        this image revision yet (our backlog, not the provider's fault).
    ❌ — checked, rejected.
    — (red) — required for this shape's Stage 1 surface but not exposed; fails the same as ❌.
    — (grey) — not applicable to this shape; benign.
    """
    if value is True:
        return {"mark": "✅", "class": "bg-emerald-500/20 text-emerald-700",
                "title": "Verified"}
    if value == "audit_pending":
        return {"mark": "○", "class": "bg-amber-100 text-amber-800 ring-1 ring-amber-300",
                "title": "Provider's code is chain-authorized and the gateway quote self-attests, "
                         "but the analyst pair hasn't reviewed this revision yet. This is our "
                         "backlog, not a provider fault."}
    if value is False:
        return {"mark": "❌", "class": "bg-rose-500/20 text-rose-700",
                "title": "Rejected by verifier"}
    if required:
        return {"mark": "—", "class": "bg-rose-500/10 text-rose-700 ring-1 ring-rose-200",
                "title": "Required for this shape but not exposed by the attestation response"}
    return {"mark": "—", "class": "text-slate-400",
            "title": "Not applicable to this attestation shape"}


def _render(snapshot):
    # Aggregate: per-provider summary
    rows = []
    for provider, reports in snapshot.get("attestations", {}).items():
        for r in reports:
            sc = r.get("scorecard") or {}
            shape = r.get("attestation_type", "")
            rows.append({
                "provider": provider,
                "model": r["model"],
                "valid": r.get("valid", False),
                "error": r.get("error"),
                "attestation_type": shape,
                "signing_address": r.get("signing_address", ""),
                "latency_s": r.get("latency_s", 0),
                "cells": {k: cell(sc.get(k), is_layer_required(k, shape)) for k in SCORECARD_LABELS},
                "stage1_ready": is_stage1_ready(sc, shape),
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
