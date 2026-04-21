"""Dispatch tests — stub the provider verify() functions so we don't hit live endpoints."""
from __future__ import annotations

from probes import attestation
from verifiers.common import AttestationReport, ScoreCard, now_iso


def _stub(provider, model, valid=True):
    return AttestationReport(
        provider=provider, model=model, valid=valid,
        verified_at=now_iso(),
        scorecard=ScoreCard(tdx_verified=valid),
    )


def test_probe_provider_returns_skipped_when_no_key(monkeypatch):
    monkeypatch.delenv("REDPILL_API_KEY", raising=False)
    rows = attestation.probe_provider("redpill", ["phala/gpt-oss-20b"])
    assert len(rows) == 1
    assert rows[0].valid is False
    assert "REDPILL_API_KEY" in (rows[0].error or "")


def test_probe_provider_swallows_verifier_exception(monkeypatch):
    monkeypatch.setenv("REDPILL_API_KEY", "test")
    def boom(*_a, **_kw):
        raise RuntimeError("transport down")
    monkeypatch.setitem(attestation.PROVIDERS, "redpill", boom)
    rows = attestation.probe_provider("redpill", ["phala/x"])
    assert len(rows) == 1
    assert rows[0].valid is False
    assert "transport down" in (rows[0].error or "")


def test_probe_provider_parallel(monkeypatch):
    monkeypatch.setenv("REDPILL_API_KEY", "test")
    monkeypatch.setitem(
        attestation.PROVIDERS, "redpill",
        lambda k, b, m: _stub("redpill", m, valid=True),
    )
    rows = attestation.probe_provider("redpill", ["a", "b", "c"])
    assert [r.model for r in rows] == ["a", "b", "c"]
    assert all(r.valid for r in rows)
