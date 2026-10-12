"""anchor-drift and unauthorized-compose come from the compose hashes NEAR's model CVMs serve."""
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


def test_unanchored_and_unauthorized_served_hashes_fire(tmp_path, monkeypatch):
    monkeypatch.setattr(diffalert, "DATA", _latest(tmp_path, [
        {"compose_hash": A, "chain_authorized": True, "anchored": True},
        {"compose_hash": B, "chain_authorized": False, "anchored": False}]))
    v = diffalert.current_values()
    assert v["anchor-drift:near-ai/models"] == B
    assert v["unauthorized-compose:near-ai/m"] == B
    assert v["stale:latest.json"] == "fresh"


def test_drift_delta_names_added_and_gone():
    msg = diffalert.describe("anchor-drift:near-ai/models", A, B)
    assert f"new unanchored compose hashes in service: {B}" in msg
    assert f"no longer served unanchored (anchored or retired): {A}" in msg
