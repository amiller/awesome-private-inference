"""Venice attestation verifier.

Venice exposes an undocumented /api/v1/tee/attestation endpoint that returns:
  {
    "nonce_source": "client" | "server",
    "model": "<id>",
    "tee_provider": "phala" | "nearai" | ...,
    "tee_hardware": "intel-tdx",
    "quote": "<hex>",                   # string, not a parsed struct
    "nvidia_payload": {...},             # optional
    "server_verification": {             # Venice-side re-verification
        "tdx": {"verified": true, ...},
        "gpu": {"verdict": "PASS", ...},
        ...
    },
    "signing_address": "0x…",
    "signing_public_key": "04…",
    ...
  }

We re-run TDX against Phala's verifier (not Venice's server_verification) and
re-run GPU against NRAS to avoid trusting Venice's self-report.
"""
from __future__ import annotations

import json
import secrets
import time
from typing import Any, Dict

import requests

from .common import (
    AttestationReport,
    ScoreCard,
    keccak_eth_address,
    now_iso,
    phala_report_data_binds_addr_nonce,
    sha256_hex,
)
from . import phala_tdx, nvidia_nras

DEFAULT_BASE_URL = "https://api.venice.ai/api/v1"


def verify(api_key: str, base_url: str, model: str) -> AttestationReport:
    started = time.time()
    base = base_url.rstrip("/")
    nonce = secrets.token_hex(32)
    url = f"{base}/tee/attestation"

    def _fail(err: str, **details) -> AttestationReport:
        return AttestationReport(
            provider="venice", model=model, valid=False,
            verified_at=now_iso(), attestation_type="venice",
            error=err, details=details,
            latency_s=round(time.time() - started, 2),
        )

    try:
        resp = requests.get(
            url, params={"model": model, "nonce": nonce},
            headers={"Authorization": f"Bearer {api_key}"}, timeout=60,
        )
    except requests.RequestException as exc:
        return _fail(f"transport: {exc}")

    if resp.status_code == 404:
        return _fail("no TEE attestation available for this model (404)")
    if resp.status_code != 200:
        return _fail(f"HTTP {resp.status_code}: {resp.text[:200]}")

    att = resp.json()
    sc = ScoreCard(backend_attested=False)  # Venice sits downstream of Phala/NEAR
    details: Dict[str, Any] = {
        "tee_provider": att.get("tee_provider"),
        "tee_hardware": att.get("tee_hardware"),
        "nonce_source": att.get("nonce_source"),
    }

    # Nonce binding — Venice should report nonce_source == "client" when we sent one.
    sc.nonce_bound = att.get("nonce_source") == "client"

    quote_hex = att.get("quote") or ""
    if isinstance(quote_hex, dict):
        # Some responses may nest; handle defensively.
        quote_hex = quote_hex.get("hex") or quote_hex.get("intel_quote") or ""
    if not quote_hex:
        return _fail("no TDX quote in response", keys=sorted(att.keys())[:20])

    tdx = phala_tdx.verify_tdx_quote(quote_hex)
    sc.tdx_verified = phala_tdx.is_verified(tdx)
    body = phala_tdx.quote_body(tdx)

    signing_addr = att.get("signing_address", "")
    spk = att.get("signing_public_key", "")

    sc.report_data_binds_key = phala_report_data_binds_addr_nonce(
        body.get("reportdata", ""), signing_addr, nonce,
    )

    if spk and signing_addr:
        try:
            sc.key_derives_to_address = (
                keccak_eth_address(spk).lower() == signing_addr.lower()
            )
        except Exception:
            sc.key_derives_to_address = False

    # compose hash
    tcb_info = att.get("tcb_info") or (att.get("info") or {}).get("tcb_info") or {}
    if isinstance(tcb_info, str):
        try:
            tcb_info = json.loads(tcb_info)
        except Exception:
            tcb_info = {}
    app_compose = tcb_info.get("app_compose")
    mr_config = body.get("mrconfig", "")
    if app_compose and mr_config:
        expected = ("0x01" + sha256_hex(app_compose)).lower()
        sc.compose_hash_committed = mr_config.lower().startswith(expected)

    nvidia_payload = att.get("nvidia_payload")
    if nvidia_payload:
        if isinstance(nvidia_payload, str):
            nvidia_payload = json.loads(nvidia_payload)
        try:
            verdict = nvidia_nras.attest_gpu(nvidia_payload)
            sc.gpu_attested = verdict in ("PASS", True)
            details["gpu_verdict"] = verdict
        except Exception as exc:
            details["gpu_error"] = str(exc)
            sc.gpu_attested = False

    required = [sc.tdx_verified, sc.report_data_binds_key]
    if spk:
        required.append(sc.key_derives_to_address)
    if nvidia_payload:
        required.append(sc.gpu_attested)
    valid = all(required) and sc.tdx_verified is True

    return AttestationReport(
        provider="venice", model=model, valid=valid,
        verified_at=now_iso(), attestation_type="venice",
        signing_address=signing_addr, signing_public_key=spk,
        scorecard=sc, details=details,
        latency_s=round(time.time() - started, 2),
    )
