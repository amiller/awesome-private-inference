"""RedPill attestation verifier — dispatches across 4 backend shapes.

Shapes observed in practice (2026-04):
  - Phala simple:   top-level {intel_quote, nvidia_payload, signing_*} (phala/*).
  - NEAR AI relay:  {gateway_attestation, model_attestations[]} (phala/gpt-oss-120b, deepseek-v3.1, …).
  - Chutes:         attestation_type="chutes" + all_attestations[] with e2e_pubkey binding.
  - Tinfoil:        404 today (catalog-only entries).
"""
from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
from typing import Any, Dict, List, Optional

import requests

from .common import (
    AttestationReport,
    ScoreCard,
    keccak_eth_address,
    now_iso,
    phala_report_data_binds_addr_nonce,
    sha256_hex,
    sha256_nonce_pubkey_binding,
)
from . import phala_tdx, nvidia_nras

DEFAULT_BASE_URL = "https://api.red-pill.ai/v1"


def verify(api_key: str, base_url: str, model: str) -> AttestationReport:
    """Top-level entrypoint. Dispatches to one of four shapes."""
    started = time.time()
    api_base = base_url.rstrip("/")
    if api_base.endswith("/v1"):
        api_base = api_base[:-3]
    url = f"{api_base}/v1/attestation/report"
    nonce = secrets.token_hex(32)

    def _fail(err: str, **details) -> AttestationReport:
        return AttestationReport(
            provider="redpill", model=model, valid=False,
            verified_at=now_iso(), attestation_type="redpill",
            error=err, details=details,
            latency_s=round(time.time() - started, 2),
        )

    try:
        resp = requests.get(
            url, params={"model": model, "nonce": nonce},
            headers={"Authorization": f"Bearer {api_key}"}, timeout=90,
        )
    except requests.RequestException as exc:
        return _fail(f"transport: {exc}")

    if resp.status_code == 404:
        return _fail("catalog-only (404 on attestation endpoint)",
                     hint="Tinfoil-routed entries advertised in /models but not served.")
    if resp.status_code != 200:
        return _fail(f"HTTP {resp.status_code}: {resp.text[:200]}")

    report = resp.json()

    if report.get("attestation_type") == "chutes":
        return _verify_chutes(report, model, nonce, started)
    if "gateway_attestation" in report:
        return _verify_near_relay(report, model, nonce, started)
    if "intel_quote" in report:
        return _verify_phala_simple(report, model, nonce, started)

    return _fail("unknown attestation shape", keys=sorted(list(report.keys()))[:10])


def _verify_phala_simple(
    att: Dict[str, Any], model: str, nonce: str, started: float
) -> AttestationReport:
    sc = ScoreCard(backend_attested=None)  # no hop to check on this shape
    details: Dict[str, Any] = {"shape": "phala-simple"}

    tdx = phala_tdx.verify_tdx_quote(att["intel_quote"])
    sc.tdx_verified = phala_tdx.is_verified(tdx)
    body = phala_tdx.quote_body(tdx)

    signing_addr = att.get("signing_address", "")
    spk = att.get("signing_public_key", "")

    sc.report_data_binds_key = phala_report_data_binds_addr_nonce(
        body.get("reportdata", ""), signing_addr, nonce,
    )
    sc.nonce_bound = sc.report_data_binds_key

    if spk and signing_addr:
        try:
            sc.key_derives_to_address = (
                keccak_eth_address(spk).lower() == signing_addr.lower()
            )
        except Exception:
            sc.key_derives_to_address = False

    info = att.get("info", {})
    tcb_info = info.get("tcb_info") or {}
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

    required = [sc.tdx_verified, sc.report_data_binds_key, sc.key_derives_to_address]
    if nvidia_payload:
        required.append(sc.gpu_attested)
    valid = all(required) and sc.tdx_verified is True

    return AttestationReport(
        provider="redpill", model=model, valid=valid,
        verified_at=now_iso(), attestation_type="phala-simple",
        signing_address=signing_addr, signing_public_key=spk,
        scorecard=sc, details=details,
        latency_s=round(time.time() - started, 2),
    )


def _verify_near_relay(
    report: Dict[str, Any], model: str, nonce: str, started: float
) -> AttestationReport:
    """RedPill routing through NEAR — gateway + model_attestations. We re-verify what
    we can; the inner-boundary gap (gateway trusts model JSON) is still present."""
    gateway = report["gateway_attestation"]
    models = report.get("model_attestations") or []
    sc = ScoreCard()
    details: Dict[str, Any] = {"shape": "near-relay", "inner_models": len(models)}

    gw_tdx = phala_tdx.verify_tdx_quote(gateway["intel_quote"])
    sc.tdx_verified = phala_tdx.is_verified(gw_tdx)
    gw_body = phala_tdx.quote_body(gw_tdx)
    gw_addr = gateway.get("signing_address", "")
    sc.report_data_binds_key = phala_report_data_binds_addr_nonce(
        gw_body.get("reportdata", ""), gw_addr, nonce,
    )
    sc.nonce_bound = sc.report_data_binds_key

    model_spk = ""
    if models:
        m0 = models[0]
        spk = m0.get("signing_public_key", "")
        addr = m0.get("signing_address", "")
        if spk and addr:
            try:
                sc.key_derives_to_address = (
                    keccak_eth_address(spk).lower() == addr.lower()
                )
                model_spk = spk
            except Exception:
                sc.key_derives_to_address = False
        nvidia_payload = m0.get("nvidia_payload")
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
    # Inner-boundary: the gateway does not verify the backend TDX quote. This is
    # the canonical gap (NEAR issue #224). We mark it False explicitly.
    sc.backend_attested = False

    required = [sc.tdx_verified, sc.report_data_binds_key]
    if models:
        required.append(sc.key_derives_to_address)
    valid = all(required) and sc.tdx_verified is True

    return AttestationReport(
        provider="redpill", model=model, valid=valid,
        verified_at=now_iso(), attestation_type="near-relay",
        signing_address=gw_addr, signing_public_key=model_spk,
        scorecard=sc, details=details,
        latency_s=round(time.time() - started, 2),
    )


def _verify_chutes(
    report: Dict[str, Any], model: str, nonce: str, started: float
) -> AttestationReport:
    atts: List[Dict[str, Any]] = report.get("all_attestations") or []
    sc = ScoreCard(gpu_attested=None)  # Chutes shape doesn't include NVIDIA
    details: Dict[str, Any] = {"shape": "chutes", "instance_count": len(atts)}

    if not atts:
        return AttestationReport(
            provider="redpill", model=model, valid=False,
            verified_at=now_iso(), attestation_type="chutes",
            error="no all_attestations", details=details,
            latency_s=round(time.time() - started, 2),
        )

    tdx_ok = True
    binding_ok = True
    for i, att in enumerate(atts):
        quote_b64 = att.get("intel_quote", "")
        e2e_pubkey = att.get("e2e_pubkey", "")
        inst_nonce = att.get("nonce") or nonce
        if not quote_b64 or not e2e_pubkey:
            tdx_ok = False
            binding_ok = False
            continue
        try:
            quote_hex = base64.b64decode(quote_b64).hex()
        except Exception:
            tdx_ok = False
            continue
        tdx = phala_tdx.verify_tdx_quote(quote_hex)
        if not phala_tdx.is_verified(tdx):
            tdx_ok = False
            continue
        body = phala_tdx.quote_body(tdx)
        if not sha256_nonce_pubkey_binding(body.get("reportdata", ""), inst_nonce, e2e_pubkey):
            binding_ok = False

    sc.tdx_verified = tdx_ok
    sc.nonce_bound = binding_ok
    sc.report_data_binds_key = binding_ok  # sha256(nonce||pubkey) is Chutes's key binding
    valid = tdx_ok and binding_ok

    return AttestationReport(
        provider="redpill", model=model, valid=valid,
        verified_at=now_iso(), attestation_type="chutes",
        signing_address=f"{len(atts)} instances", signing_public_key="",
        scorecard=sc, details=details,
        latency_s=round(time.time() - started, 2),
    )
