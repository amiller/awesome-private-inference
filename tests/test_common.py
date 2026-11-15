"""Unit tests for verifiers/common.py — address derivation and report_data layouts."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from verifiers.common import (
    AttestationReport,
    ScoreCard,
    audit_match,
    keccak_eth_address,
    load_audit_ledger,
    phala_report_data_binds_addr_nonce,
    sha256_nonce_pubkey_binding,
)


# Known ECDSA secp256k1 keypair (vitalik-style example).
PUBKEY = (
    "045f3f4fc1f7a3dc9d98f7b2c7c5c62ac75bcc0cb64b6f6fe1e2a2e8b7c24f2c7a"
    "ec8b0e1a2d07e3d5e8cd6a9f3a2f1b6c6e9f3a7d2e5c8b1a4d7f2e5c8b1a4d7e2"
)


def test_keccak_eth_address_accepts_04_prefix_or_raw():
    # Derive once with 0x04-prefixed, once with raw; must match.
    from eth_keys.datatypes import PublicKey
    import secrets
    # Generate a valid pair for round-trip
    from eth_keys.datatypes import PrivateKey
    priv = PrivateKey(secrets.token_bytes(32))
    pub = priv.public_key
    addr = pub.to_canonical_address().hex()
    pub_uncompressed = "04" + pub.to_hex()[2:]
    assert keccak_eth_address(pub_uncompressed).lower() == "0x" + addr
    assert keccak_eth_address(pub.to_hex()[2:]).lower() == "0x" + addr


def test_keccak_eth_address_rejects_bad_length():
    with pytest.raises(ValueError):
        keccak_eth_address("aa" * 10)


def test_phala_report_data_binding_positive():
    addr = "0x" + "ab" * 20
    nonce = "cd" * 32
    rd = bytes.fromhex("ab" * 20).ljust(32, b"\x00").hex() + nonce
    assert phala_report_data_binds_addr_nonce(rd, addr, nonce) is True


def test_phala_report_data_binding_wrong_nonce():
    addr = "0x" + "ab" * 20
    rd = bytes.fromhex("ab" * 20).ljust(32, b"\x00").hex() + "00" * 32
    assert phala_report_data_binds_addr_nonce(rd, addr, "cd" * 32) is False


def test_sha256_nonce_pubkey_binding_positive():
    nonce = "aa" * 16
    pk = "04deadbeef"
    expected = hashlib.sha256((nonce + pk).encode()).hexdigest()
    rd = expected + "00" * 32
    assert sha256_nonce_pubkey_binding(rd, nonce, pk) is True


def test_sha256_nonce_pubkey_binding_negative():
    assert sha256_nonce_pubkey_binding("00" * 64, "aa", "bb") is False


def test_attestation_report_as_dict_includes_scorecard():
    r = AttestationReport(
        provider="near-ai", model="x", valid=True,
        verified_at="2026-01-01T00:00:00Z",
        scorecard=ScoreCard(tdx_verified=True),
    )
    d = r.as_dict()
    assert d["scorecard"]["tdx_verified"] is True
    assert d["provider"] == "near-ai"


def test_audit_match_exact_and_case(tmp_path):
    full = "abcdef0123456789" * 4  # 64 hex
    led = tmp_path / "led.json"
    led.write_text(json.dumps({"audits": [{"k": full}]}))
    ids, meta = load_audit_ledger(led, "k")
    # exact match only
    assert audit_match(full, ids) == full
    # keys are lowercased; an uppercase live value still matches
    assert audit_match(full.upper(), ids) == full
    # a tampered digest (one hex char changed) must not match
    tampered = ("b" if full[0] != "b" else "c") + full[1:]
    assert audit_match(tampered, ids) is None
    # a value that merely starts with a ledger key does not match
    assert audit_match(full + "aa", ids) is None
    assert audit_match(full[:-1], ids) is None
    assert audit_match("", ids) is None
    assert full in meta


def test_load_audit_ledger_rejects_short_or_nonhex_key(tmp_path):
    # "22763fe4" is 8 hex chars and was previously accepted as a prefix key
    for bad in ("", "abc", "nothexxx", "22763fe4", "a" * 63, "a" * 65, "g" * 64):
        led = tmp_path / "bad.json"
        led.write_text(json.dumps({"audits": [{"k": bad}]}))
        with pytest.raises(ValueError):
            load_audit_ledger(led, "k")


def test_load_audit_ledger_enforces_declared_key_length(tmp_path):
    mrtd = "2a" * 48  # chutes MRTD: 96 hex
    led = tmp_path / "chutes.json"
    led.write_text(json.dumps({"audits": [{"mrtd": mrtd}]}))
    ids, _ = load_audit_ledger(led, "mrtd", key_length=96)
    assert ids == {mrtd}
    # a 64-hex digest is not a full MRTD and must be rejected at 96
    led.write_text(json.dumps({"audits": [{"mrtd": "a" * 64}]}))
    with pytest.raises(ValueError):
        load_audit_ledger(led, "mrtd", key_length=96)


def test_repo_ledgers_hold_only_full_length_keys():
    root = Path(__file__).resolve().parents[1] / "data" / "audits"
    near_ids, near_meta = load_audit_ledger(root / "near-ai_cloud-api.json")
    assert all(len(k) == 64 for k in near_ids)
    assert len(near_ids) == 4
    # the retired 8-hex row is history-only and cannot authorize anything
    assert "22763fe4" not in near_ids
    assert "22763fe4" not in near_meta
    assert audit_match("22763fe4" + "ab" * 28, near_ids) is None
    # tamper control on real evidence: mutate one hex char of a real key
    real = next(iter(near_ids))
    flipped = ("0" if real[0] != "0" else "1") + real[1:]
    assert audit_match(flipped, near_ids) is None
    tin_ids, _ = load_audit_ledger(root / "tinfoil_confidential-model-router.json",
                                   "bundle_digest")
    assert all(len(k) == 64 for k in tin_ids)
    ch_ids, _ = load_audit_ledger(root / "chutes_tee.json", "mrtd", key_length=96)
    assert all(len(k) == 96 for k in ch_ids)
