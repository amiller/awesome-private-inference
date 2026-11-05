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

Since 2026-08 some models answer with the ACI/1 gateway format
(api_version == "aci/1"), whose only attested CVM is the private-ai-gateway
(an aggregator that forwards to a downstream inference API — see
docs/tasks/glm-venice-20261105.md and teep's venice_aci_gateway.md). That
format is dispatched to _verify_aci1, which reuses the aci.py helpers; any
other api_version fails closed instead of falling through to the dstack
path. The dstack REPORTDATA layout (keccak address || zero pad || client
nonce) is shared by both formats, so the gateway quote binds the same way.

We re-run TDX against Phala's verifier (not Venice's server_verification) and
re-run GPU against NRAS to avoid trusting Venice's self-report.
"""
from __future__ import annotations

import json
import secrets
import time
from typing import Any, Dict, Optional

import requests

from .common import (
    AttestationReport,
    ScoreCard,
    keccak_eth_address,
    now_iso,
    phala_report_data_binds_addr_nonce,
    sha256_hex,
)
from . import aci, phala_tdx, nvidia_nras

DEFAULT_BASE_URL = "https://api.venice.ai/api/v1"


def verify(
    api_key: str, base_url: str, model: str, nonce: Optional[str] = None
) -> AttestationReport:
    started = time.time()
    base = base_url.rstrip("/")
    nonce = nonce or secrets.token_hex(32)
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
    if api_version is not None:
        if api_version == "aci/1":
            return _verify_aci1(att, model, nonce, started)
        return _fail(f"unsupported attestation api_version: {api_version!r}")

    sc = ScoreCard(backend_attested=False)  # Venice sits downstream of Phala/NEAR
    details: Dict[str, Any] = {
        "tee_provider": att.get("tee_provider"),
        "tee_hardware": att.get("tee_hardware"),
        "nonce_source": att.get("nonce_source"),
        "candidates_available": att.get("candidates_available"),
        "candidates_evaluated": att.get("candidates_evaluated"),
        "model_name": att.get("model_name"),
    }

    # Nonce binding — Venice reports nonce_source == "client" when we sent one.
    sc.nonce_bound = att.get("nonce_source") == "client"

    quote_hex = att.get("intel_quote") or att.get("quote") or ""
    if isinstance(quote_hex, dict):
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


def _verify_aci1(
    att: Dict[str, Any], model: str, nonce: str, started: float
) -> AttestationReport:
    """The ACI/1 gateway format: one attested CVM, the private-ai-gateway.

    Bindings mirror verifiers/aci.py: quote appraisal through phala_tdx,
    REPORTDATA binding, keyset digest over the JCS keyset, and the event-log
    replay into the quote's RTMR3. The attested CVM is a forwarding gateway
    (serving=aggregator, num_gpus=0, a downstream TLS pin), so backend_attested
    stays False and the layers this format cannot prove are reported unproven
    with their reasons rather than inherited from the echo fields.
    """
    sc = ScoreCard(backend_attested=False)
    block = att.get("attestation") or {}
    evidence = block.get("evidence") or {}
    quote_hex = evidence.get("quote") or ""
    if not quote_hex:
        return _aci1_fail(model, started, "no gateway quote in ACI/1 evidence",
                          keys=sorted(att.keys())[:20])

    details: Dict[str, Any] = {
        "aci_api_version": att.get("api_version"),
        "format": "aci/1 gateway",
        "tee_provider": att.get("tee_provider"),
        "tee_hardware": att.get("tee_hardware"),
        "nonce_source": att.get("nonce_source"),
        "candidates_available": att.get("candidates_available"),
        "candidates_evaluated": att.get("candidates_evaluated"),
    }

    if att.get("intel_quote") not in (None, quote_hex):
        # teep's rule: the nested evidence field is the attested source.
        details["intel_quote_diverges_from_evidence"] = True

    try:
        tdx = phala_tdx.verify_tdx_quote(quote_hex)
    except requests.RequestException as exc:
        return _aci1_fail(model, started, f"tdx appraisal transport: {exc}")
    sc.tdx_verified = phala_tdx.is_verified(tdx)
    body = phala_tdx.quote_body(tdx)
    reportdata = body.get("reportdata", "")

    sc.nonce_bound = (
        att.get("nonce") == nonce
        and att.get("nonce_source") == "client"
        and reportdata.removeprefix("0x")[64:128] == nonce
    )

    signing_addr = att.get("signing_address", "")
    spk = att.get("signing_public_key", "")
    keyset = block.get("workload_keyset") or {}
    served_digest = att.get("workload_keyset_digest") or ""
    keyset_recomputes = (
        bool(keyset)
        and served_digest == "sha256:" + sha256_hex(aci._jcs(keyset))
    )
    signing_key_in_keyset = spk in [
        k.get("public_key") for k in keyset.get("e2ee_public_keys", [])
    ]
    echo_matches_quote = (
        block.get("report_data", "").removeprefix("0x").lower()
        == reportdata.removeprefix("0x").lower()
    )
    sc.report_data_binds_key = (
        phala_report_data_binds_addr_nonce(reportdata, signing_addr, nonce)
        and keyset_recomputes
        and signing_key_in_keyset
        and echo_matches_quote
    )

    if spk and signing_addr:
        try:
            sc.key_derives_to_address = (
                keccak_eth_address(spk).lower() == signing_addr.lower()
            )
        except Exception:
            sc.key_derives_to_address = False

    try:
        event_log = json.loads(evidence["event_log"]) if evidence.get("event_log") else []
        vm_config = json.loads(evidence["vm_config"]) if evidence.get("vm_config") else {}
    except (json.JSONDecodeError, TypeError) as exc:
        return _aci1_fail(model, started, f"malformed ACI/1 evidence: {exc}")

    compose = evidence.get("app_compose") or ""
    mr_config = body.get("mrconfig", "")
    payloads_bound = aci._events_bind_payloads(event_log)
    event_log_bound = (
        payloads_bound
        and aci._replayed_rtmr3(event_log) == body.get("rtmr3", "").removeprefix("0x").lower()
    )
    compose_event = aci._unique_event(event_log, "compose-hash")
    sc.compose_hash_committed = (
        bool(compose and mr_config)
        and mr_config.lower().startswith(("0x01" + sha256_hex(compose)).lower())
        and event_log_bound
        and compose_event is not None
        and aci._event_precedes_boot_boundary(event_log, compose_event)
        and aci._event_payload(compose_event).hex() == sha256_hex(compose)
    )
    details.update({
        "event_payloads_bound": payloads_bound,
        "event_log_bound_to_rtmr3": event_log_bound,
        "keyset_digest_recomputes": keyset_recomputes,
        "signing_key_in_keyset": signing_key_in_keyset,
        "report_data_echo_matches_quote": echo_matches_quote,
        "workload_keyset_digest": served_digest,
    })

    app_id_event = aci._unique_event(event_log, "app-id")
    details.update({
        "attested_cvm": "gateway",
        "serving": (att.get("service_capabilities") or {}).get("serving"),
        "num_gpus": vm_config.get("num_gpus"),
        "downstream_tls_binding": evidence.get("downstream_tls_binding"),
        "source_repo": (block.get("source_provenance") or {}).get("repo_url"),
        "gateway_app_id_event": (
            aci._event_payload(app_id_event).hex() if app_id_event is not None else None
        ),
    })

    nvidia_payload = att.get("nvidia_payload")
    unproven: Dict[str, str] = {
        "backend_attested": (
            "the only attested CVM is the private-ai-gateway; ACI/1 evidence "
            "names no model host (serving=%r, num_gpus=%r, downstream pin %r)"
            % (details["serving"], details["num_gpus"],
               (details["downstream_tls_binding"] or {}).get("domain"))
        ),
        "prod_os_image": (
            "no boot-measurement comparison is possible from this response "
            "(vm_config.image=%r)" % vm_config.get("image")
        ),
        "serving_code_attested": (
            "no measured register covers the inference host's serving software"
        ),
        "code_measurement_reproducible": (
            "source_provenance.image_digest is %r; no reproducible-build evidence"
            % (block.get("source_provenance") or {}).get("image_digest")
        ),
    }
    if not nvidia_payload:
        unproven["gpu_attested"] = (
            "gateway response carries no GPU evidence "
            "(gpu_evidence_omitted=%r)" % att.get("gpu_evidence_omitted")
        )
    else:
        if isinstance(nvidia_payload, str):
            nvidia_payload = json.loads(nvidia_payload)
        try:
            verdict = nvidia_nras.attest_gpu(nvidia_payload)
            sc.gpu_attested = verdict in ("PASS", True)
            details["gpu_verdict"] = verdict
        except Exception as exc:
            details["gpu_error"] = str(exc)
            sc.gpu_attested = False
    details["unproven_reasons"] = unproven

    required = [sc.tdx_verified, sc.nonce_bound, sc.report_data_binds_key,
                sc.compose_hash_committed]
    if spk:
        required.append(sc.key_derives_to_address)
    if nvidia_payload:
        required.append(sc.gpu_attested)
    valid = all(value is True for value in required)

    return AttestationReport(
        provider="venice", model=model, valid=valid,
        verified_at=now_iso(), attestation_type="venice",
        signing_address=signing_addr, signing_public_key=spk,
        scorecard=sc, details=details,
        latency_s=round(time.time() - started, 2),
    )


def _aci1_fail(model: str, started: float, err: str, **details) -> AttestationReport:
    return AttestationReport(
        provider="venice", model=model, valid=False,
        verified_at=now_iso(), attestation_type="venice",
        error=err, details=details,
        latency_s=round(time.time() - started, 2),
    )
