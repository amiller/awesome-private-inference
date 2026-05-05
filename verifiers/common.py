"""Shared primitives for attestation verifiers.

ScoreCard maps to the dimensions we show on the dashboard. Each verifier returns
an AttestationReport whose `scorecard` populates one row of the matrix.
"""
from __future__ import annotations

import base64
import hashlib
import json
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Set


# Per attestation-shape Stage-1-required layers. A null cell on a required layer
# fails Stage 1 the same way ❌ does — the provider's protocol elects not to
# expose the check, so the audit surface is too thin. A null on an unrequired
# layer is benign ("architecturally not applicable" — e.g. backend_attested for
# a single-TD direct-TEE provider with no gateway hop).
#
# To onboard a new shape: enumerate which scorecard fields the provider's
# attestation response *should* let a verifier check, given what the provider
# claims (GPU inference → gpu_attested required; gateway+backend hop →
# backend_attested required; OHTTP/HPKE E2EE → hpke_pubkey_attested required).
REQUIRED_LAYERS_BY_SHAPE: Dict[str, Set[str]] = {
    # NEAR-direct: cloud-api gateway + per-model TDX+GPU. Stage 1 needs every
    # hop attested and the model-CVM compose committed in mr_config.
    "tdx+gpu": {
        "tdx_verified", "nonce_bound", "report_data_binds_key",
        "gpu_attested", "key_derives_to_address", "compose_hash_committed",
        "backend_attested",
    },
    # RedPill phala-direct: single-TD, no gateway hop.
    "phala-simple": {
        "tdx_verified", "nonce_bound", "report_data_binds_key",
        "gpu_attested", "key_derives_to_address", "compose_hash_committed",
    },
    # RedPill via NEAR: same shape as NEAR-direct.
    "near-relay": {
        "tdx_verified", "nonce_bound", "report_data_binds_key",
        "gpu_attested", "key_derives_to_address", "compose_hash_committed",
        "backend_attested",
    },
    # RedPill via Chutes: TDX-only shape. The provider claims GPU inference
    # per the catalog, so missing NRAS evidence and compose binding are fails,
    # not architectural N/As.
    "chutes": {
        "tdx_verified", "nonce_bound", "report_data_binds_key",
        "gpu_attested", "compose_hash_committed",
    },
    # Venice: TDX+GPU+compose; sits downstream of Phala/NEAR (no own
    # gateway→backend hop to attest from this side).
    "venice": {
        "tdx_verified", "nonce_bound", "report_data_binds_key",
        "gpu_attested", "key_derives_to_address", "compose_hash_committed",
    },
    # Tinfoil SEV-SNP: different attestation flavor (no Intel TDX). Stage 1
    # surface is OHTTP/HPKE binding + measured-config + live TLS pinning +
    # client-supplied nonce + no operator-injected runtime config.
    "tinfoil-sev-snp-v2": {
        "code_measurement_reproducible", "tls_pubkey_pinned",
        "hpke_pubkey_attested", "client_nonce_supported",
        "runtime_config_fully_attested",
    },
}


def is_stage1_ready(scorecard: Dict[str, Optional[bool]], shape: str) -> bool:
    """A row passes Stage 1 iff every required layer for its shape is True.
    Unknown shapes return False — we can't claim Stage 1 for something we
    haven't characterized."""
    required = REQUIRED_LAYERS_BY_SHAPE.get(shape, set())
    if not required:
        return False
    return all(scorecard.get(layer) is True for layer in required)


def is_layer_required(layer: str, shape: str) -> bool:
    return layer in REQUIRED_LAYERS_BY_SHAPE.get(shape, set())


@dataclass
class ScoreCard:
    """Per-capability booleans surfaced on the dashboard matrix."""

    nonce_bound: Optional[bool] = None       # client nonce appears in report_data
    tdx_verified: Optional[bool] = None      # quote accepted by Phala TDX verifier
    report_data_binds_key: Optional[bool] = None  # report_data commits to signing addr
    gpu_attested: Optional[bool] = None      # NRAS returned PASS
    key_derives_to_address: Optional[bool] = None  # keccak(pubkey) == signing_address
    compose_hash_committed: Optional[bool] = None  # mr_config starts with 0x01||sha256(app_compose)
    backend_attested: Optional[bool] = None  # gateway verified model backend's quote
    catalog_serves: Optional[bool] = None    # model returns 2xx on a chat call
    code_measurement_reproducible: Optional[bool] = None  # sigstore-signed measurement matches enclave
    tls_pubkey_pinned: Optional[bool] = None  # report_data binds to a live TLS SPKI hash
    hpke_pubkey_attested: Optional[bool] = None  # report_data carries a non-zero HPKE pubkey
    client_nonce_supported: Optional[bool] = None  # provider accepts a client-supplied nonce
    runtime_config_fully_attested: Optional[bool] = None  # no env/secret values come from unattested external config

    def as_dict(self) -> Dict[str, Optional[bool]]:
        return asdict(self)


@dataclass
class AttestationReport:
    """Output of a verifier run."""

    provider: str
    model: str
    valid: bool
    verified_at: str
    attestation_type: str = ""
    signing_address: str = ""
    signing_public_key: str = ""
    signing_algo: str = "ecdsa"
    scorecard: ScoreCard = field(default_factory=ScoreCard)
    details: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    latency_s: float = 0.0

    def as_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["scorecard"] = self.scorecard.as_dict()
        return d


def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def keccak_eth_address(signing_public_key_hex: str) -> str:
    """Derive an Ethereum-style address from an uncompressed ECDSA pubkey.

    Accepts 0x04-prefixed or bare 64-byte hex. Returns '0x' + last 20 bytes of
    keccak256(pubkey_xy).
    """
    from eth_keys.datatypes import PublicKey  # imported lazily

    raw = bytes.fromhex(signing_public_key_hex.removeprefix("0x"))
    if len(raw) == 65 and raw[0] == 0x04:
        raw = raw[1:]
    if len(raw) != 64:
        raise ValueError(f"unexpected pubkey length {len(raw)}")
    return "0x" + PublicKey(raw).to_canonical_address().hex()


def phala_report_data_binds_addr_nonce(
    report_data_hex: str, signing_address: str, nonce: str
) -> bool:
    """report_data layout = addr.ljust(32, \\x00) || nonce_bytes (32).

    This is the canonical Phala/NEAR TDX binding used by RedPill and NEAR AI.
    """
    try:
        rd = bytes.fromhex(report_data_hex.removeprefix("0x"))
        addr = bytes.fromhex(signing_address.removeprefix("0x"))
        return rd[:32] == addr.ljust(32, b"\x00") and rd[32:64].hex() == nonce
    except Exception:
        return False


def sha256_nonce_pubkey_binding(
    report_data_hex: str, nonce: str, e2e_pubkey: str
) -> bool:
    """Chutes-style anti-tamper binding: report_data[0:32] == sha256(nonce || pubkey)."""
    try:
        rd = report_data_hex.removeprefix("0x").lower()
        expected = hashlib.sha256((nonce + e2e_pubkey).encode()).hexdigest().lower()
        return rd[:64] == expected
    except Exception:
        return False


def decode_nvidia_jwt_verdict(jwt_token: str) -> str:
    """Extract x-nvidia-overall-att-result from a NRAS JWT (without signature check)."""
    payload_b64 = jwt_token.split(".")[1]
    padded = payload_b64 + "=" * ((4 - len(payload_b64) % 4) % 4)
    payload = json.loads(base64.urlsafe_b64decode(padded).decode())
    return payload.get("x-nvidia-overall-att-result", "UNKNOWN")


def sha256_hex(s: str | bytes) -> str:
    if isinstance(s, str):
        s = s.encode()
    return hashlib.sha256(s).hexdigest()
