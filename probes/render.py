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

from probes.quality import compute as compute_quality
from verifiers.common import bar_note, is_layer_required, is_stage1_ready

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
    "serving_code_attested": "Serving code attested",
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
    "serving_code_attested": (
        "The code on the prompt-plaintext path (serve.py) and the served model are "
        "committed to a measured register. Red on Chutes: serve.py is CFSV-excluded "
        "and in no RTMR, so the operator (or Chutes) can read or exfiltrate the "
        "decrypted prompt AND silently substitute the model — neither detectable from "
        "the quote. Live proof: all -TEE models share one MRTD. chutesai/chutes#75."
    ),
    "backend_attested": (
        "Tri-state: ✅ gateway code self-attests + compose_hash is on-chain authorized + "
        "image digest is in our analyst-pair audit ledger. ○ chain-authorized + self-consistent "
        "but the audit ledger hasn't caught up (analyst backlog, NOT a provider fault). "
        "❌ quote not self-consistent or compose not on the on-chain authorized set."
    ),
}


# Hand-written claims. Each carries the date it was last checked against the data,
# so a reader can tell how much of the page is measurement and how much is opinion.
# A claim here that the probe can check belongs in a scorecard column instead.
EDITORIAL_NOTES = [
    {"checked": "2026-06-18", "title": "RedPill phala-simple host-SSH path is closed.",
     "body": "The fleet moved off dstack-nvidia-dev to prod dstack-nvidia-0.5.9, removing the "
             "operator host-SSH route. Now machine-tracked by the Prod OS image column, which "
             "flips on any regression. Residual gaps (mutable image tags, unpinned runtime "
             "weights) are unaddressed."},
    {"checked": "2026-06-18", "title": "Chutes' serving code is not measured.",
     "body": "serve.py on the prompt-plaintext path is CFSV-excluded and in no RTMR, and the "
             "model name is not bound to the quote. A passing quote proves genuine TDX running "
             "a Chutes base image, not which model on which code."},
    {"checked": "2026-05-09", "title": "NEAR's gateway gap depends on the client.",
     "body": "ALLOWED_COMPOSE_HASHES is unset server-side, so the gateway alone does not pin "
             "code. A closed-chain client that checks compose_hash against the on-chain set on "
             "Base closes it; a client that trusts the gateway does not."},
    {"checked": "2026-04-26", "title": "Upstream verifier decodes JWTs without checking signatures.",
     "body": "Phala's private-ai-verifier passes verify_signature=False on NVIDIA and Intel "
             "Trust Authority tokens, and every reseller routing through it inherits that."},
    {"checked": "2026-08-10", "title": "The bar is hand-set, and one entry was wrong.",
     "body": "REQUIRED_LAYERS_BY_SHAPE is a hand-edited dict with no changelog. Venice's set "
             "excluded the two layers where its prompt-path exposure actually lives, so Venice "
             "scored a full row until an outside audit pointed at them; corrected 2026-08-10. "
             "Denominators still differ per architecture, so compare the unproven layers rather "
             "than the fractions, and treat the bar as editorial until it is derived from "
             "provider claims (issue #6)."},
]


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


STATUS_STYLE = {
    "verified": ("verified", "bg-emerald-500/20 text-emerald-700",
                 "Every layer this provider's architecture should be able to prove, it proves."),
    "partial": ("partial", "bg-amber-100 text-amber-800 ring-1 ring-amber-300",
                "Reachable and internally consistent, but at least one required layer is unproven."),
    "unreachable": ("unreachable", "bg-slate-200 text-slate-600",
                    "We could not get a response. This says nothing about the provider's privacy properties."),
    "invalid": ("invalid", "bg-rose-500/20 text-rose-700",
                "A response arrived but did not verify."),
    "uncharacterized": ("uncharacterized", "bg-slate-200 text-slate-600",
                        "We have not defined what this attestation shape should be able to prove."),
}


def _render(snapshot):
    quality = compute_quality(snapshot)
    status_by_target = {(c["provider"], c["model"]): c for c in quality["coverage"]}

    rows = []
    for provider, reports in snapshot.get("attestations", {}).items():
        for r in reports:
            sc = r.get("scorecard") or {}
            shape = r.get("attestation_type", "")
            cov = status_by_target[(provider, r["model"])]
            label, css, tip = STATUS_STYLE[cov["status"]]
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
                "status": cov["status"],
                "status_label": label,
                "status_class": css,
                "status_title": tip,
                "proven": cov["proven"],
                "required": cov["required"],
                "missing": cov["missing"],
                # required layers with no column on the matrix — invisible to a reader
                "hidden_layers": cov["hidden_layers"],
                "bar": bar_note(shape),
            })
    # disputed bars sort below sound ones at the same status, so a contested full row
    # never sits at the top of the page looking like the best provider on offer
    rows.sort(key=lambda r: (r["status"] != "verified", bool(r["bar"]["disputed"]),
                             r["status"] == "unreachable", r["provider"], r["model"]))

    provider_summary = {}
    for p, reports in snapshot.get("attestations", {}).items():
        targets = [status_by_target[(p, r["model"])] for r in reports]
        provider_summary[p] = {
            "total": len(targets),
            "verified": sum(1 for t in targets if t["status"] == "verified"),
            "partial": sum(1 for t in targets if t["status"] == "partial"),
            "unreachable": sum(1 for t in targets if t["status"] in ("unreachable", "invalid")),
            "measurable": next(t["version_identity"] for t in targets) == "content-hash",
        }

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
        "EDITORIAL_NOTES": EDITORIAL_NOTES,
    })

    # Rule of three: with zero events in n trials, the 95% upper bound on the
    # per-observation rate is 3/n. Turns "never fired" into a quantified claim.
    n = quality["calibration"]["observations"]
    quality["calibration"]["rate_upper_bound_95"] = round(100 * 3 / n, 3) if n else None

    ctx = {
        "snapshot": snapshot,
        "generated_at": snapshot.get("generated_at", ""),
        "git_sha": snapshot.get("git_sha", ""),
        "run_id": snapshot.get("run_id", "local"),
        "rows": rows,
        "provider_summary": provider_summary,
        "pricing_rows": pricing_rows,
        "quality": quality,
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
