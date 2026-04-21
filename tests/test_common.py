"""Unit tests for verifiers/common.py — address derivation and report_data layouts."""
from __future__ import annotations

import hashlib

import pytest

from verifiers.common import (
    AttestationReport,
    ScoreCard,
    keccak_eth_address,
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
        provider="redpill", model="x", valid=True,
        verified_at="2026-01-01T00:00:00Z",
        scorecard=ScoreCard(tdx_verified=True),
    )
    d = r.as_dict()
    assert d["scorecard"]["tdx_verified"] is True
    assert d["provider"] == "redpill"
