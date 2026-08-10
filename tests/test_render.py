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
            "redpill": [
                {
                    "provider": "redpill", "model": "phala/gpt-oss-20b",
                    "valid": True, "verified_at": "…",
                    "attestation_type": "phala-simple",
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
    assert "phala/gpt-oss-20b" in html
    assert (docs / "methodology.html").exists()
    assert (docs / "pricing.html").exists()

    # The row is missing compose_hash_committed, which phala-simple requires, so it
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


def test_disputed_bars_are_labelled():
    """Rubric R3: a required set that omits the layers a provider would fail must say so.

    Venice scores a full row only because its bar excludes serving_code_attested,
    prod_os_image and backend_attested. That has to be visible, or the row reads as
    the best provider on the board.
    """
    from verifiers.common import BAR_NOTES, REQUIRED_LAYERS_BY_SHAPE, bar_note

    assert set(BAR_NOTES) == set(REQUIRED_LAYERS_BY_SHAPE), \
        "every scored shape must state what it excludes and why"
    assert bar_note("venice")["disputed"] is True
    assert bar_note("no-such-shape")["disputed"] is True  # unknown shapes are never sound
