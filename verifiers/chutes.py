"""Chutes direct confidential-inference verifier (api.chutes.ai, Bittensor subnet 64).

Distinct from RedPill's `chutes` relay shape: this hits the chutes control plane
directly via the E2E discovery + evidence endpoints.

Per `-TEE` chute, we verify the crypto core (live-confirmed sound):
  - report_data[0:32] == SHA256(nonce || e2e_pubkey)      (E2E key binding, fresh)
  - report_data[32:64] == SHA256(SPKI of evidence cert)   (attestation-svc cert binding)
  - td_attributes bit0 == 0                                (debug mode disabled)
  - MRTD ∈ published /servers/tee/measurements golden set
  - TDX quote accepted by Phala's DCAP verifier

…and the headline gap: nothing binds *which model* or *which serving code* to the
quote (MRTD/RTMRs are identical across different models; serve.py is CFSV-excluded,
in no RTMR). So `model_bound_to_quote` is False by construction — a verified quote
proves a genuine TDX+GPU running a Chutes base image, not which model on which code.
See providers/chutes.md and chutesai/chutes#75.

Quote offsets per chutes-api/api/server/quote.py (td_report = quote[48:]).
"""
from __future__ import annotations

import base64
import hashlib
import secrets
import time
from typing import Any, Dict

import requests

from .common import AttestationReport, ScoreCard, now_iso, sha256_nonce_pubkey_binding
from . import phala_tdx

DEFAULT_BASE_URL = "https://api.chutes.ai"

# Model label → chute_id. Add/prune as the catalog rotates.
CHUTE_IDS: Dict[str, str] = {
    "Qwen3-32B-TEE": "ac059e33-eb27-541c-b9a9-24b214036475",
    "gemma-4-31B-TEE": "42ee92ba-a537-5a73-8741-876067750db7",
    "GLM-5-TEE": "e51e818e-fa63-570d-9f68-49d7d1b4d12f",
    "DeepSeek-V3.2-TEE": "398651e1-5f85-5e50-a513-7c5324e8e839",
    "Kimi-K2.6-TEE": "aac09863-35b4-5d9b-9b67-6e6a9d54273a",
}


def _parse_quote(quote_b64: str) -> Dict[str, str]:
    body = base64.b64decode(quote_b64)[48:]
    return {
        "td_attributes": body[120:128].hex(),
        "mrtd": body[136:184].hex().lower(),
        "report_data": body[520:584].hex(),  # 64 bytes
    }


def _cert_spki_sha256(cert_der_b64: str) -> str:
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    cert = x509.load_der_x509_certificate(base64.b64decode(cert_der_b64))
    spki = cert.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha256(spki).hexdigest().lower()


def verify(api_key: str, base_url: str, model: str) -> AttestationReport:
    started = time.time()
    api_base = base_url.rstrip("/")
    headers = {"Authorization": f"Bearer {api_key}"}
    nonce = secrets.token_hex(32)

    def _fail(err: str, **details) -> AttestationReport:
        return AttestationReport(
            provider="chutes", model=model, valid=False,
            verified_at=now_iso(), attestation_type="chutes-tee",
            error=err, details=details,
            latency_s=round(time.time() - started, 2),
        )

    chute_id = CHUTE_IDS.get(model)
    if not chute_id:
        return _fail(f"unknown chute_id for model {model!r}")

    def _get(path: str) -> Any:
        r = requests.get(f"{api_base}{path}", headers=headers, timeout=90)
        if r.status_code != 200:
            raise RuntimeError(f"HTTP {r.status_code} on {path}: {r.text[:160]}")
        return r.json()

    try:
        golden = {c["mrtd"].lower() for c in _get("/servers/tee/measurements")}
        inst = _get(f"/e2e/instances/{chute_id}")["instances"][0]
        instance_id, e2e_pubkey = inst["instance_id"], inst["e2e_pubkey"]
        ev = _get(f"/instances/{instance_id}/evidence?nonce={nonce}")
    except (requests.RequestException, RuntimeError, KeyError, IndexError) as exc:
        return _fail(f"{type(exc).__name__}: {exc}")

    q = _parse_quote(ev["quote"])
    sc = ScoreCard(gpu_attested=None)
    details: Dict[str, Any] = {
        "shape": "chutes-tee", "instance_id": instance_id,
        "mrtd": q["mrtd"], "gpu_evidence_count": len(ev.get("gpu_evidence") or []),
    }

    sc.report_data_binds_key = sha256_nonce_pubkey_binding(q["report_data"], nonce, e2e_pubkey)
    sc.nonce_bound = sc.report_data_binds_key
    details["cert_spki_bound"] = q["report_data"][64:128] == _cert_spki_sha256(ev["certificate"])
    details["debug_disabled"] = (int(q["td_attributes"], 16) & 1) == 0
    details["mrtd_in_golden_set"] = q["mrtd"] in golden

    tdx = phala_tdx.verify_tdx_quote(base64.b64decode(ev["quote"]).hex())
    sc.tdx_verified = phala_tdx.is_verified(tdx)

    # Headline gap: model + serving code are in no measured register. MRTD/RTMRs are
    # shared across different -TEE models, and serve.py is CFSV-excluded. A verified
    # quote cannot establish which model or code answered. False by construction.
    sc.model_bound_to_quote = False

    valid = bool(
        sc.tdx_verified and sc.report_data_binds_key
        and details["cert_spki_bound"] and details["debug_disabled"]
        and details["mrtd_in_golden_set"]
    )

    return AttestationReport(
        provider="chutes", model=model, valid=valid,
        verified_at=now_iso(), attestation_type="chutes-tee",
        signing_address=instance_id, signing_public_key=e2e_pubkey,
        scorecard=sc, details=details,
        latency_s=round(time.time() - started, 2),
    )
