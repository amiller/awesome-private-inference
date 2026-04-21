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
    assert "Stage 0" in html
    assert "0 / 0" not in html  # provider_summary should show 1/1
    assert (docs / "methodology.html").exists()
    assert (docs / "pricing.html").exists()
