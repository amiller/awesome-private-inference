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
from pathlib import Path
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
    # Chutes direct (api.chutes.ai): crypto core is sound, but the serve.py on the
    # prompt-plaintext path (and the model) are unmeasured, so serving_code_attested
    # is False by construction and the shape never reaches Stage 1 — the operator can
    # read/exfiltrate prompts and substitute the model undetectably.
    # ACI gateway (spec/aci.md): one attested workload fronting several hostnames.
    # gpu_attested and key_derives_to_address are genuinely N/A — this TD has no GPU
    # (num_gpus: 0; the GPUs are upstream) and ACI identity is a keyset digest, not an
    # eth address. attested_serving_enforced is required because the same quote,
    # keyset and Compose serve hosts where attested serving is NOT forced, and that
    # difference is the whole risk the row exists to show.
    "aci-gateway": {
        "tdx_verified", "nonce_bound", "report_data_binds_key",
        "compose_hash_committed", "prod_os_image", "attested_serving_enforced",
    },
    "chutes-tee": {
        "tdx_verified", "nonce_bound", "report_data_binds_key",
        "serving_code_attested",
    },
    # Venice: TDX+GPU+compose, plus the three layers that were wrongly excluded
    # until 2026-08-10. Venice resells NEAR/Phala backends, and the old set left
    # out prod_os_image, serving_code_attested and code_measurement_reproducible
    # on the grounds that the backend "belongs to" the upstream operator. That
    # asks whose fault a gap is rather than whether the user is exposed: a prompt
    # sent to Venice is decrypted in a Phala enclave, so a dev image with root SSH
    # exposes it no matter whose invoice it lands on. Venice's /tee/attestation
    # does not report any of the three, which makes them required-and-unexposed
    # (a fail), not architecturally N/A (benign). See providers/venice.md.
    "venice": {
        "tdx_verified", "nonce_bound", "report_data_binds_key",
        "gpu_attested", "key_derives_to_address", "compose_hash_committed",
        "prod_os_image", "serving_code_attested", "code_measurement_reproducible",
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


# Every required set is a judgment about what a provider *should* be able to prove,
# and the dangerous edit is an exclusion, not an inclusion — omitting a layer silently
# raises a provider's score. Each shape therefore has to say out loud what it leaves
# out and why, and whether that reasoning is currently contested. `disputed` rows are
# rendered with a warning and must not be compared across providers.
BAR_NOTES: Dict[str, Dict[str, object]] = {
    "tdx+gpu": {"disputed": False, "note":
        "Gateway plus per-model TD, so every hop is required. Excludes the Tinfoil-specific "
        "SEV layers, which do not exist in this architecture."},
    "aci-gateway": {"disputed": False, "note":
        "One workload, several hostnames. Excludes gpu_attested and key_derives_to_address "
        "(no GPU in this TD, and ACI identity is a keyset digest rather than an eth address) "
        "and backend_attested is scored but not required, since a client can accept the "
        "passing sessions and reject the rest. attested_serving_enforced is required: it is "
        "the only layer that differs between hostnames on one shared attestation."},
    "chutes-tee": {"disputed": False, "note":
        "serving_code_attested is required and is False by construction, so this shape cannot "
        "reach a full row. That is the intended reading, not a scoring bug."},
    "venice": {"disputed": False, "note":
        "Corrected 2026-08-10. This set previously omitted prod_os_image, "
        "serving_code_attested and code_measurement_reproducible because Venice resells "
        "NEAR and Phala backends, which let it score a full row while providers exposing "
        "more of their stack scored less. An independent audit showed the two omitted "
        "layers are exactly where Venice's prompt-path exposure lives, so they are now "
        "required and read as unproven rather than not-applicable. backend_attested stays "
        "excluded and is reported False: Venice has no gateway hop of its own, and the "
        "upstream backend's own row carries that check."},
    "tinfoil-sev-snp-v2": {"disputed": False, "note":
        "SEV-SNP rather than TDX, so the Intel-specific layers are N/A and the bar is the "
        "OHTTP/HPKE binding, measured config, live TLS pinning and client nonce."},
}


def bar_note(shape: str) -> Dict[str, object]:
    return BAR_NOTES.get(shape, {"disputed": True, "note":
        "No required-layer set is defined for this shape, so nothing is scored."})


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
    prod_os_image: Optional[bool] = None     # vm_config.image is the prod dstack OS image, not dstack-nvidia-dev (no host-SSH/debug-tweaks)
    serving_code_attested: Optional[bool] = None  # the code on the prompt-plaintext path (serve.py) + served model are in a measured register; if not, the operator can read/exfiltrate prompts AND substitute the model undetectably
    backend_attested: Optional[bool] = None  # gateway verified model backend's quote
    catalog_serves: Optional[bool] = None    # model returns 2xx on a chat call
    code_measurement_reproducible: Optional[bool] = None  # sigstore-signed measurement matches enclave
    tls_pubkey_pinned: Optional[bool] = None  # report_data binds to a live TLS SPKI hash
    hpke_pubkey_attested: Optional[bool] = None  # report_data carries a non-zero HPKE pubkey
    client_nonce_supported: Optional[bool] = None  # provider accepts a client-supplied nonce
    runtime_config_fully_attested: Optional[bool] = None  # no env/secret values come from unattested external config
    attested_serving_enforced: Optional[bool] = None  # ACI: this hostname is in the measured tee_only_domains, so the gateway refuses to serve it from a non-TEE upstream. False means a verified workload will forward the prompt to an ordinary commercial API unless the client opts in per request (spec 5.3)

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

    This is the canonical Phala/NEAR TDX binding used by NEAR AI and Venice.
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


def load_audit_ledger(path, key_field: str = "image_digest"):
    """Read an analyst-pair audit ledger (data/audits/*.json). Returns
    (identity_set, metadata_by_identity). Keys are lowercased; a truncated key
    matches a live value by startswith (see audit_match)."""
    data = json.loads(Path(path).read_text())
    ids: Set[str] = set()
    meta: Dict[str, Dict] = {}
    for row in data["audits"]:
        k = str(row[key_field]).lower()
        # A short/empty key would startswith-match unrelated digests; reject it
        # rather than silently mark everything audited.
        if len(k) < 8 or any(c not in "0123456789abcdef" for c in k):
            raise ValueError(f"{Path(path).name}: invalid {key_field} {k!r} "
                             "(need >=8 hex chars)")
        ids.add(k)
        meta[k] = row
    return ids, meta


def audit_match(value: str, audit_set: Set[str]) -> Optional[str]:
    """Return the matching audit key (full or truncated prefix) if any, else None."""
    if not value:
        return None
    value = value.lower()
    for entry in audit_set:
        if value.startswith(entry):
            return entry
    return None
