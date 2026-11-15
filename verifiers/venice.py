"""Venice attestation verifier.

Venice's /api/v1/tee/attestation serves two shapes:

  legacy: quote/intel_quote + tcb_info.app_compose at the top level
  aci/1 (observed live 2026-11-05): an ACI-style document whose
    attestation.evidence carries quote, event_log, vm_config and app_compose,
    with signing fields and nonce_source at the top level. The attested CVM is
    the private-ai-gateway (serving=aggregator, num_gpus=0, a downstream TLS
    pin), so aci/1 rows are never valid: the gateway does not cover the model
    host. The keyset digest, the signing key's membership in it and the
    report_data echo are still checked so the gateway layer reads correctly.
  any other api_version fails closed.

We re-run TDX against Phala's verifier (not Venice's server_verification) to
avoid trusting Venice's self-report, retain whatever TCB verdict that verifier
returns (observed: none), and additionally appraise the quote locally with
dcap-qvl so the real Intel PCS status and advisory IDs reach the row. On the
aci/1 shape the event log is replayed to the quote's RTMRs and MRTD/RTMR0-2
are checked against dstack-mr-derived pins; the TD debug bit must be clear. GPU evidence is re-run
against NRAS, with the returned JWTs signature-verified against NVIDIA's JWKS and
their nonces bound to our request (verifiers/nvidia_nras.py).
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
from . import aci, dstack_tdx, dstack_boot_registers, nvidia_nras, phala_tdx

DEFAULT_BASE_URL = "https://api.venice.ai/api/v1"
GATEWAY_ONLY = "gateway attestation does not cover the model host"


def _measurement_view(evidence: Dict, quote_hex: str) -> Dict[str, Any]:
    """Replay the aci/1 event log and bind the detached claims to it."""
    event_log = json.loads(evidence["event_log"])
    vm_config = json.loads(evidence["vm_config"]) if evidence.get("vm_config") else None
    measurements = dstack_tdx.attestation_measurements(quote_hex, event_log)
    claims = {
        "os_image_hash": str((vm_config or {}).get("os_image_hash") or "")
        .lower().removeprefix("0x"),
        "compose_hash": sha256_hex(evidence["app_compose"]) if evidence.get("app_compose") else "",
    }
    disagreements = {key: {"log": measurements[f"log_{key}"], "detached": value}
                     for key, value in claims.items()
                     if value and value != measurements[f"log_{key}"]}
    boot = dstack_boot_registers.check_boot_registers(
        measurements["log_os_image_hash"], measurements["registers"])
    return {**measurements, "ok": not disagreements,
            "detached_json_disagreements": disagreements, "vm_config": vm_config,
            "boot_registers": boot}


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
    api_version = att.get("api_version")
    if api_version not in (None, "aci/1"):
        return _fail(f"unsupported attestation api_version: {api_version!r}")
    aci1 = api_version == "aci/1"
    sc = ScoreCard(backend_attested=False)  # Venice sits downstream of Phala/NEAR
    details: Dict[str, Any] = {
        "tee_provider": att.get("tee_provider"),
        "tee_hardware": att.get("tee_hardware"),
        "nonce_source": att.get("nonce_source"),
        "candidates_available": att.get("candidates_available"),
        "candidates_evaluated": att.get("candidates_evaluated"),
        "model_name": att.get("model_name"),
        "api_version": api_version,
        "upstream_model": att.get("upstream_model"),
        "serving": (att.get("service_capabilities") or {}).get("serving"),
        "gpu_evidence_omitted": att.get("gpu_evidence_omitted"),
    }

    quote_hex = att.get("intel_quote") or att.get("quote") or ""
    if isinstance(quote_hex, dict):
        quote_hex = quote_hex.get("hex") or quote_hex.get("intel_quote") or ""
    if aci1:
        evidence = att["attestation"]["evidence"]
        # the evidence copy is the one bound to the event log; a top-level
        # duplicate that disagrees with it is a rejection, not a tiebreak
        duplicate = att.get("intel_quote") or att.get("quote")
        if duplicate and duplicate != evidence["quote"]:
            return _fail("top-level quote disagrees with attestation.evidence.quote")
        quote_hex = evidence["quote"]
    if not quote_hex:
        return _fail("no TDX quote in response", keys=sorted(att.keys())[:20])

    tdx = phala_tdx.verify_tdx_quote(quote_hex)
    sc.tdx_verified = phala_tdx.is_verified(tdx)
    body = phala_tdx.quote_body(tdx)
    reportdata = body.get("reportdata", "").removeprefix("0x").lower()
    sc.nonce_bound = (att.get("nonce_source") == "client" and reportdata[64:128] == nonce
                      and (not aci1 or att["nonce"] == nonce))
    details["phala_tcb_status"] = (tdx.get("quote") or {}).get("tcb_status")

    dcap = dstack_tdx.dcap_verify(quote_hex)
    details["dcap_appraisal"] = {"tcb_status": dcap.status, "advisory_ids": list(dcap.advisory_ids)}
    sc.tcb_current = dcap.status in dstack_tdx.TCB_CURRENT_STATUSES
    sc.tee_debug_disabled = dstack_tdx.quote_debug_disabled(quote_hex)

    if aci1:
        try:
            measurements = _measurement_view(evidence, quote_hex)
        except dstack_tdx.EventLogError as exc:
            measurements = {"ok": False, "error": str(exc), "boot_registers": {
                "boot_config": False, "hardware_config": False, "reasons": [
                    f"quote/event-log binding failed ({exc}); image identity unauthenticated"]}}
        details["measurements"] = {k: v for k, v in measurements.items() if k != "vm_config"}
        details["vm_config"] = measurements.get("vm_config")
        sc.event_log_replayed = measurements["ok"]
        sc.tee_boot_config = measurements["boot_registers"]["boot_config"]
        sc.tee_hardware_config = measurements["boot_registers"]["hardware_config"]
    else:
        details["measurements"] = {"reason": "legacy response carries no event log; "
                                   "replay and boot-register derivation unavailable"}

    signing_addr = att.get("signing_address", "")
    spk = att.get("signing_public_key", "")

    sc.report_data_binds_key = phala_report_data_binds_addr_nonce(reportdata, signing_addr, nonce)
    if aci1:
        block = att["attestation"]
        keyset = block["workload_keyset"]
        binding = {
            "keyset_digest_recomputes":
                att["workload_keyset_digest"] == "sha256:" + sha256_hex(aci._jcs(keyset)),
            "signing_key_in_keyset": spk in [k["public_key"] for k in keyset["e2ee_public_keys"]],
            "report_data_echo_matches_quote":
                block["report_data"].removeprefix("0x").lower() == reportdata,
        }
        details["keyset_binding"] = binding
        details["downstream_tls_binding"] = evidence.get("downstream_tls_binding")
        details["source_repo"] = (block.get("source_provenance") or {}).get("repo_url")
        sc.report_data_binds_key = sc.report_data_binds_key and all(binding.values())

    if spk and signing_addr:
        try:
            sc.key_derives_to_address = keccak_eth_address(spk).lower() == signing_addr.lower()
        except ValueError as exc:
            sc.key_derives_to_address = False
            details["key_derivation_error"] = str(exc)

    # compose hash
    if aci1 and measurements["ok"]:
        sc.compose_hash_committed = (
            measurements["mrconfigid"].lower().startswith(
                ("01" + measurements["log_compose_hash"]).lower())
            and not measurements["detached_json_disagreements"]
            and bool(evidence.get("app_compose"))
        )
    else:
        tcb_info = att.get("tcb_info") or (att.get("info") or {}).get("tcb_info") or {}
        if isinstance(tcb_info, str):
            tcb_info = json.loads(tcb_info)
        app_compose = tcb_info.get("app_compose")
        mr_config = body.get("mrconfig", "")
        if app_compose and mr_config:
            expected = ("0x01" + sha256_hex(app_compose)).lower()
            sc.compose_hash_committed = mr_config.lower().startswith(expected)

    nvidia_payload = att.get("nvidia_payload")
    if nvidia_payload:
        if isinstance(nvidia_payload, str):
            nvidia_payload = json.loads(nvidia_payload)
        # The payload's nonce must be OUR fresh nonce — the same one bound into
        # the TDX quote's report_data — or the GPU evidence belongs to another
        # session and cannot count for this row.
        if nvidia_payload.get("nonce") != nonce:
            details["gpu_error"] = "nvidia_payload_nonce_is_not_the_request_nonce"
            sc.gpu_attested = False
        else:
            try:
                jwks = nvidia_nras.fetch_jwks()
                result = nvidia_nras.appraise_gpu_attestation(
                    nvidia_payload.get("evidence_list"), nonce, jwks,
                    None, allow_unknown_count=True)
                sc.gpu_attested = result["gpu_attested"]
                details["gpu_appraisal"] = result
                details["gpu_count_pinned"] = False  # policy gap: no published GPU count, any count passes
            except requests.RequestException as exc:
                details["gpu_error"] = f"nras_unreachable: {type(exc).__name__}: {exc}"
                sc.gpu_attested = None

    required = [sc.tdx_verified, sc.report_data_binds_key]
    if spk:
        required.append(sc.key_derives_to_address)
    if nvidia_payload:
        required.append(sc.gpu_attested)
    valid = all(required) and sc.tdx_verified is True
    if aci1:
        # the only CVM aci/1 attests is the private-ai-gateway, which forwards
        # to a downstream API; nothing in it is evidence about the model host
        details["rejection_reason"] = GATEWAY_ONLY
        valid = False

    return AttestationReport(
        provider="venice", model=model, valid=valid,
        verified_at=now_iso(), attestation_type="venice",
        signing_address=signing_addr, signing_public_key=spk,
        scorecard=sc, details=details,
        latency_s=round(time.time() - started, 2),
    )
