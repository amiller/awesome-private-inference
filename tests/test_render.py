"""Smoke test: render.py produces valid HTML from a fabricated snapshot."""
from __future__ import annotations

import json
from pathlib import Path

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
                        "compose_hash_committed": None,
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
    assert "openai/gpt-oss-120b" in html
    assert "Current RedPill uses ACI." in html
    assert (docs / "methodology.html").exists()
    assert (docs / "pricing.html").exists()

    # The row is missing compose_hash_committed, which tdx+gpu requires, so it
    # must read as partial rather than verified.
    assert "partial" in html
    # Required-but-unproven layers are named, not left as a dash the reader must decode.
    assert "compose_hash_committed" in html
    # Calibration is stated on the page, not buried.
    assert "verification failures" in html


def test_every_required_layer_is_reachable_by_a_reader():
    """Rubric R2: a verdict computed from a layer no column shows cannot be reconstructed.

    Rows whose required layers are absent from the matrix must surface them some other
    way. render.py carries them per row as `hidden_layers`; this pins that they are
    accounted for rather than silently dropped, which is how Tinfoil's row went blank.
    """
    from probes.render import SCORECARD_LABELS
    from verifiers.common import REQUIRED_LAYERS_BY_SHAPE

    unrendered = {
        shape: sorted(required - set(SCORECARD_LABELS))
        for shape, required in REQUIRED_LAYERS_BY_SHAPE.items()
    }
    # tinfoil-sev-snp-v2 is the known offender: all five of its layers are off-matrix.
    assert unrendered["tinfoil-sev-snp-v2"], "expected the known gap to still be detected"
    assert not unrendered["tdx+gpu"], "tdx+gpu layers should all be on the matrix"


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
