"""A hash leaving the unanchored set means one of two very different things."""
from __future__ import annotations

import json

from probes import diffalert

CLEARED = "a" * 64
VANISHED = "b" * 64


def _status(tmp_path, anchored):
    (tmp_path / "onchain-status.json").write_text(json.dumps(
        {"anchored_compose_hashes": anchored}))
    return tmp_path


def test_anchored_hash_reads_as_cleared(tmp_path, monkeypatch):
    monkeypatch.setattr(diffalert, "DATA", _status(tmp_path, [CLEARED]))
    msg = diffalert.describe("anchor-drift:near-ai/models", CLEARED, "")
    assert "cleared (now anchored)" in msg
    assert "VANISHED" not in msg


def test_unanchored_disappearance_is_not_reported_as_resolved(tmp_path, monkeypatch):
    """The old sliding-window sweep evicted authorized hashes as the window slid, and
    this printed every eviction as 'cleared (now anchored)' — a reassuring message for
    evidence that had merely aged out. 30 hashes were reported cleared into a 4-entry
    anchor before anyone noticed. See issue #10."""
    monkeypatch.setattr(diffalert, "DATA", _status(tmp_path, []))
    msg = diffalert.describe("anchor-drift:near-ai/models", VANISHED, "")
    assert "VANISHED" in msg
    assert "cleared (now anchored)" not in msg


def test_cleared_and_vanished_are_separated_in_one_delta(tmp_path, monkeypatch):
    monkeypatch.setattr(diffalert, "DATA", _status(tmp_path, [CLEARED]))
    msg = diffalert.describe("anchor-drift:near-ai/models", f"{CLEARED},{VANISHED}", "")
    assert f"cleared (now anchored): {CLEARED}" in msg
    assert VANISHED in msg.split("VANISHED")[1]
