"""deployment-drift and unauthorized-compose come from what NEAR's model CVMs serve."""
from __future__ import annotations

import json
import time

from probes import diffalert

A, B = "a" * 64, "b" * 64


def _latest(tmp_path, composes):
    row = {"model": "m", "valid": True, "scorecard": {}, "details": {"model_composes": composes}}
    (tmp_path / "latest.json").write_text(json.dumps({
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "attestations": {"near-ai": [row]}}))
    (tmp_path / "snapshots").mkdir()
    return tmp_path


def test_unaged_deployments_and_unauthorized_hashes_fire(tmp_path, monkeypatch):
    monkeypatch.setattr(diffalert, "DATA", _latest(tmp_path, [
        {"compose_hash": A, "chain_authorized": True,
         "deployments": {"deployments": [{"commit": "c1", "file": "f.yaml", "aged": True}]}},
        {"compose_hash": B, "chain_authorized": False,
         "deployments": {"deployments": [{"commit": "c2", "file": "f.yaml", "aged": False}]}}]))
    v = diffalert.current_values()
    assert v["deployment-drift:near-ai/models"] == "c2:f.yaml"
    assert v["unauthorized-compose:near-ai/m"] == B
    assert v["stale:latest.json"] == "fresh"


def test_drift_delta_names_added_and_gone():
    msg = diffalert.describe("deployment-drift:near-ai/models", "c1:f", "c2:f")
    assert "new deployments not yet aged in the archive: c2:f" in msg
    assert "aged or no longer running: c1:f" in msg
