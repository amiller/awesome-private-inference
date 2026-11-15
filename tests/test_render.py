"""Smoke test: render.py produces valid HTML from a fabricated snapshot."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from probes import render


def test_render_produces_html(tmp_path, monkeypatch):
    snapshot = {
        "schema_version": "0.1",
        "generated_at": "2026-04-21T00:00:00Z",
        "run_id": "local",
        "git_sha": "deadbeef",
        "attestations": {
            "near-ai": [
                {
                    "provider": "near-ai", "model": "openai/gpt-oss-120b",
                    "valid": True, "verified_at": "…",
                    "attestation_type": "tdx+gpu",
                    "signing_address": "0xabc", "latency_s": 0.5,
                    "scorecard": {
                        "tdx_verified": True, "gpu_attested": True,
                        "key_derives_to_address": True,
                        "report_data_binds_key": True,
                        "nonce_bound": True,
                        "compose_hash_committed": True,
                        "backend_attested": None,
                        "catalog_serves": True,
                    },
                    "details": {}, "error": None,
                }
            ]
        },
        "pricing": {},
    }
    docs = tmp_path / "docs"
    snap_path = tmp_path / "latest.json"
    snap_path.write_text(json.dumps(snapshot))

    monkeypatch.setattr(render, "DATA_LATEST", snap_path)
    monkeypatch.setattr(render, "DOCS_DIR", docs)
    # Keep real template dir

    rc = render.main()
    assert rc == 0
    html = (docs / "index.html").read_text()
    assert ">Comparison</h1>" in html
    assert "What makes inference private?" in html
    assert "What the companion audits establish" in html
    history = (docs / "history.html").read_text()
    assert "Expected reference" in history
    assert "Observed identity" in history
    assert "Document fingerprint" in history
    assert 'aria-label="Primary"' in html
    measurements = (docs / "measurements.html").read_text()
    assert "Attestation checks across providers and models" in measurements
    assert (docs / "assessments.html").exists()
    assert html.count("Not assessed — dated source review only (2026-10-14)") == 13
    assert html.count('colspan="7" class="unassessed"') == 13
    assert 'href="./assessments.html#route-private-inference-private">Not assessed — dated source review only (2026-10-14)</a> · 3 findings' in html
    assert 'href="./assessments.html#route-privatemode-proxy-pinned">Not assessed — dated source review only (2026-10-14)</a></td>' in html
    assert "#rubric-recipient" in html and "#rubric-reply" in html and '-session"' not in html
    assessments = (docs / "assessments.html").read_text()
    assert 'id="private-inference-private-reply"' in assessments and '-session"' not in assessments
    assert not (docs / "verifiers.html").exists()
    assert not (docs / "verifiers.json").exists()
    assert "verifiers.html" not in html
    assert "Private Inference Beat" in html
    assert "no stages awarded" in (docs / "stages.html").read_text()
    feed = json.loads((docs / "reference-values.json").read_text())
    assert feed["schema_version"] == 1
    assert all(s["client_acceptance"] is None for s in feed["surfaces"])
    evidence = (docs / "evidence.html").read_text()
    assert "openai/gpt-oss-120b" in evidence
    assert "Public reference observatory" in evidence
    assert (docs / "methodology.html").exists()
    assert (docs / "pricing.html").exists()

    assert "Legacy adapter accepted" in measurements
    assert "not full provider verdicts" in measurements
    assert "Compose binding" in evidence
    assert "rule of three" not in html.lower()


def test_every_required_layer_has_a_display_name():
    """Every required check can be named in the adapter detail, including SNP fields."""
    from probes.render import SCORECARD_LABELS
    from verifiers.common import REQUIRED_LAYERS_BY_SHAPE

    assert all(required <= set(SCORECARD_LABELS) for required in REQUIRED_LAYERS_BY_SHAPE.values())


def test_every_scored_shape_states_what_it_excludes():
    """Rubric R3: exclusions are the dangerous edit, so every shape must justify its bar.

    An inclusion is a line you can read in a diff. An exclusion is an absence from a set
    literal — nothing to review and nothing to date. Requiring a note per shape is the
    cheap half of the exhaustive-classification lint in issue #6.
    """
    from verifiers.common import BAR_NOTES, REQUIRED_LAYERS_BY_SHAPE, bar_note

    assert set(BAR_NOTES) == set(REQUIRED_LAYERS_BY_SHAPE), \
        "every scored shape must state what it excludes and why"
    assert all(len(n["note"]) > 40 for n in BAR_NOTES.values()), "notes must be substantive"
    assert bar_note("no-such-shape")["disputed"] is True  # unknown shapes are never sound


def test_venice_requires_its_prompt_path_layers():
    """Regression guard for the 2026-08-10 correction.

    Venice's bar excluded prod_os_image and serving_code_attested on the grounds that the
    backend belongs to NEAR/Phala. An independent audit showed those are precisely where
    Venice's prompt-path exposure lives — an operator root-SSH key on an unpublished dev
    image, and an unmeasured last hop. Excluding them made Venice the only full row on the
    board. Whatever else changes about this bar, a reseller must not be excused the layers
    that decide whether its users' prompts are readable.
    """
    from verifiers.common import REQUIRED_LAYERS_BY_SHAPE

    for layer in ("prod_os_image", "serving_code_attested", "code_measurement_reproducible"):
        assert layer in REQUIRED_LAYERS_BY_SHAPE["venice"], \
            f"{layer} was excluded from Venice's bar once; it must stay required"


def _cell(value, shape, layer, checked_count=2, retired=False):
    return render.check_cell(value, shape=shape, layer=layer, checked_count=checked_count, retired=retired)


def test_none_cells_render_distinct_states():
    ours = _cell(None, "tdx+gpu", "backend_attested")
    assert ours["mark"] == "?" and "Not checked by us" in ours["meaning"]
    assert ours["issue_url"].endswith("/issues/29")
    provider = _cell(None, "venice", "prod_os_image")
    assert provider["mark"] == "∅" and "Not exposed by provider" in provider["meaning"]
    assert "issue_url" not in _cell(None, "venice", "gpu_attested")
    na = _cell(None, "chutes-tee", "gpu_attested")
    assert na["mark"] == "n/a" and "Not applicable" in na["meaning"]
    empty = _cell(None, "chutes-tee", "tdx_verified", checked_count=0)
    assert empty["mark"] == "—" and "No evidence captured" in empty["meaning"]
    retired = _cell(None, "retired", "tdx_verified", checked_count=0, retired=True)
    assert retired["mark"] == "n/a" and "retired" in retired["meaning"]
    assert {c["mark"] for c in (ours, provider, na, empty)} == render.NONE_MARKS
    assert _cell(True, "venice", "prod_os_image", checked_count=0)["mark"] == "✓"


def test_unclassified_required_gap_raises():
    with pytest.raises(KeyError):
        _cell(None, "venice", "tdx_verified")
    with pytest.raises(KeyError):
        _cell(None, "unknown-shape", "tdx_verified")


def test_retired_row_shows_its_reason_not_a_provider_failure():
    rows = render._rows({"attestations": {"near-ai": [
        {"provider": "near-ai", "model": "gone", "valid": False, "verified_at": "2026-11-15T01:02:03Z",
         "attestation_type": "retired", "scorecard": {}, "details": {}, "error": "retired",
         "row_status": "retired", "outcome": "not_applicable", "outcome_reason": "retired",
         "retirement_evidence": {"retired_at": "2026-11-15T00:00:00Z", "summary": "gateway stopped serving it"}},
        {"provider": "near-ai", "model": "down", "valid": False, "verified_at": "2026-11-15T01:02:03Z",
         "attestation_type": "tdx+gpu", "scorecard": {}, "details": {}, "error": "HTTP 503",
         "row_status": "unknown", "outcome": "unavailable", "outcome_reason": "http_error"},
    ]}})
    down, gone = rows
    assert gone["outcome_label"] == "Retired" and down["outcome_label"] == "Unavailable"
    assert gone["error"] == "Removed from the probe catalog on 2026-11-15: gateway stopped serving it"
    assert gone["matrix_cells"]["nonce_bound"]["mark"] == "n/a"
    assert down["matrix_cells"]["nonce_bound"]["mark"] == "—"


def test_venice_legacy_shape_required_layers_render():
    for layer in ("event_log_replayed", "tee_boot_config", "tee_hardware_config"):
        assert _cell(None, "venice", layer)["mark"] == "∅"
