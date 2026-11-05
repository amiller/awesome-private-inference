"""Venice attestation verifier.

Venice's /api/v1/tee/attestation serves two shapes:

  legacy: quote/intel_quote + tcb_info.app_compose at the top level
  aci/1 (observed live 2026-11-05): an ACI-style document whose
    attestation.evidence carries quote, event_log, vm_config and app_compose,
    with signing fields and nonce_source at the top level

We re-run TDX against Phala's verifier (not Venice's server_verification) to
avoid trusting Venice's self-report, retain whatever TCB verdict that verifier
returns (observed: none), and additionally appraise the quote locally with
dcap-qvl so the real Intel PCS status and advisory IDs reach the row. Boot
registers are checked against dstack-mr-derived pins (vm_config exposed since
the aci/1 format), the event log is replayed to the quote's RTMRs, and the
TD debug bit must be clear. The GPU path re-runs NRAS (untouched by this
change).
"""
from __future__ import annotations

import asyncio
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
from . import dstack_tdx, dstack_boot_registers, nvidia_nras, phala_tdx

DEFAULT_BASE_URL = "https://api.venice.ai/api/v1"
TCB_CURRENT_STATUSES = frozenset({"UpToDate"})


def _sync(coro):
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    from concurrent.futures import ThreadPoolExecutor
    def _worker():
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(coro)
        finally:
            loop.close()
    with ThreadPoolExecutor(max_workers=1) as ex:
        return ex.submit(_worker).result()


async def _local_dcap_appraisal(quote_hex: str) -> Dict[str, Any]:
    """Real Intel PCS verdict for the quote (Phala's verifier returns none)."""
    import dcap_qvl

    result = await dcap_qvl.get_collateral_and_verify(bytes.fromhex(quote_hex))
    return {"tcb_status": result.status,
            "advisory_ids": list(result.advisory_ids)}


def _aci1_evidence(att: Dict) -> Dict | None:
    evidence = (att.get("attestation") or {}).get("evidence")
    return evidence if isinstance(evidence, dict) and evidence.get("quote") else None


def _measurement_view(att: Dict, quote_hex: str) -> Dict[str, Any]:
    """Replay the event log (aci/1 shape) and bind the detached claims to it."""
    evidence = _aci1_evidence(att)
    if evidence is None:
        return {"format": "legacy",
                "reason": "legacy response carries no event log or vm_config; "
                          "event-log replay and boot-register derivation unavailable"}
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
        measurements["log_os_image_hash"], measurements["registers"], vm_config)
    return {"format": "aci/1", **measurements, "ok": not disagreements,
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
    sc = ScoreCard(backend_attested=False)  # Venice sits downstream of Phala/NEAR
    details: Dict[str, Any] = {
        "tee_provider": att.get("tee_provider"),
        "tee_hardware": att.get("tee_hardware"),
        "nonce_source": att.get("nonce_source"),
        "candidates_available": att.get("candidates_available"),
        "candidates_evaluated": att.get("candidates_evaluated"),
        "model_name": att.get("model_name"),
        "api_version": att.get("api_version"),
    }

    # Nonce binding — Venice reports nonce_source == "client" when we sent one.
    sc.nonce_bound = att.get("nonce_source") == "client"

    quote_hex = att.get("intel_quote") or att.get("quote") or ""
    if isinstance(quote_hex, dict):
        quote_hex = quote_hex.get("hex") or quote_hex.get("intel_quote") or ""
    evidence = _aci1_evidence(att)
    if evidence is not None:
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
    details["phala_tcb_status"] = (tdx.get("quote") or {}).get("tcb_status")

    try:
        details["dcap_appraisal"] = _sync(_local_dcap_appraisal(quote_hex))
        tcb_status = details["dcap_appraisal"]["tcb_status"]
        if tcb_status:
            sc.tcb_current = tcb_status in TCB_CURRENT_STATUSES
        else:
            sc.tcb_current = None
            details["tcb_policy"] = {"reason": "dcap appraisal returned no status"}
    except Exception as exc:  # collateral unavailable is a missing check, not a pass
        sc.tcb_current = None
        details["dcap_appraisal"] = {"error": f"{type(exc).__name__}: {exc}"}

    try:
        measurements = _measurement_view(att, quote_hex)
    except (dstack_tdx.EventLogError, ValueError, TypeError) as exc:
        measurements = {"format": "aci/1", "ok": False,
                        "error": f"{type(exc).__name__}: {exc}",
                        "boot_registers": {"ok": False, "per_register": {}, "reasons": [
                            f"quote/event-log binding failed ({exc}); "
                            "registers not checked against pins"]}}
    details["measurements"] = {k: v for k, v in measurements.items()
                               if k != "vm_config"}
    if measurements.get("vm_config") is not None:
        details["vm_config"] = measurements["vm_config"]
    aci1 = measurements.get("format") == "aci/1"
    sc.event_log_replayed = measurements["ok"] if aci1 else None
    sc.tee_debug_disabled = (measurements["ok"] and measurements["debug_disabled"]) \
        if aci1 else dstack_tdx.tee_debug_disabled(
            dstack_tdx.parse_quote(quote_hex)["td_attributes"])
    sc.boot_registers_derived = measurements["boot_registers"]["ok"] if aci1 else None
    if not aci1:
        details["measurements"]["reason"] = measurements.get("reason")

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
    if aci1 and measurements["ok"]:
        evidence = _aci1_evidence(att)
        sc.compose_hash_committed = (
            measurements["mrconfigid"].lower().startswith(
                ("01" + measurements["log_compose_hash"]).lower())
            and not measurements["detached_json_disagreements"]
            and bool(evidence.get("app_compose"))
        )
    else:
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
