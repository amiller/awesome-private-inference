"""NEAR AI attestation verifier.

Relies on the vendored nearai-cloud-verifier modules (`model_verifier`,
`domain_verifier`). These live in a local clone at `_nearai-verifier/py`
(gitignored; CI clones it), which is the default search path; set
`NEARAI_VERIFIER_PATH` to override before importing `verify()`.
"""
from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import re
import secrets
import sys
import threading
import time
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, Optional, Set, Tuple
from urllib.parse import urlparse

import requests

_vendor = os.environ.get("NEARAI_VERIFIER_PATH") or str(
    Path(__file__).resolve().parents[1] / "_nearai-verifier" / "py")
if _vendor and _vendor not in sys.path:
    sys.path.insert(0, _vendor)

from .common import (
    AttestationReport,
    ScoreCard,
    audit_match,
    keccak_eth_address,
    load_audit_ledger,
    now_iso,
    public_compose_preimage,
    sha256_hex,
)
from . import dstack_tdx
from . import dstack_boot_registers
from . import near_deployments

DEFAULT_BASE_URL = "https://cloud-api.near.ai"
_STDOUT_LOCK = threading.Lock()

_REPO_ROOT = Path(__file__).resolve().parents[1]
_BASE_RPC = "https://mainnet.base.org"
_CLOUD_API_AUDITS = _REPO_ROOT / "data" / "audits" / "near-ai_cloud-api.json"

_CLOUD_API_IMAGE_RE = re.compile(
    r"nearaidev/cloud-api@sha256:([0-9a-f]{64})"
)

@lru_cache(maxsize=1)
def _cloud_api_audit_set() -> Tuple[Set[str], Dict[str, Dict]]:
    """Read the analyst-pair audit ledger. Returns (digest_set, metadata_by_digest).
    Keys are full 64-hex image digests; matching is exact (see audit_match)."""
    return load_audit_ledger(_CLOUD_API_AUDITS, "image_digest")


_MODELS_APP = "0x2c0a0c96cb6dbd659bf1446e2f3fce58172ff91b"  # DstackApp shared by every NEAR AI model CVM
_EIP1967_IMPLEMENTATION_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
_MAX_INSTANCES = 8  # teep's cap on model_attestations entries for one model
_INSTANCE_ID_RE = re.compile(r"(?:[0-9a-f]{2}){1,32}")
# A deployment counts only after our archive has seen its public file this long.
DEPLOYMENT_MIN_AGE_S = 24 * 3600
_INSTANCE_LIMIT = ("every listed instance must pass every layer; the instances share one signing "
                   "key and the gateway picks one per request. Any holder of that key that the "
                   "gateway does not list is invisible to this check.")
def _rpc(method: str, params: list) -> Any:
    r = requests.post(_BASE_RPC, timeout=20, json={"jsonrpc": "2.0", "id": 1,
                                            "method": method, "params": params})
    r.raise_for_status()
    body = r.json()
    if "error" in body or "result" not in body:
        raise ValueError(f"Base RPC {method} failed: {body.get('error')}")
    return body["result"]


def _chain_snapshot() -> dict:
    """A single numbered Base block pins every authorization query in one run."""
    block = _rpc("eth_getBlockByNumber", ["latest", False])
    if not block or not block.get("number") or not block.get("hash"):
        raise ValueError("Base RPC returned no pinned block")
    return {"chain_id": int(_rpc("eth_chainId", []), 16),
            "block_number": int(block["number"], 16), "block_hash": block["hash"],
            "block_tag": block["number"]}


def _assert_same_block(snapshot: dict) -> None:
    observed = _rpc("eth_getBlockByNumber", [snapshot["block_tag"], False])
    if not observed or observed.get("hash", "").lower() != snapshot["block_hash"].lower():
        raise ValueError("Base block changed during authorization queries")


def _allowed_on_chain(app: str, compose_hash: str, block_tag: str) -> bool:
    """Query the DstackApp at the captured Base block, never moving `latest`."""
    return int(_rpc("eth_call", [{"to": app, "data": "0x2f6622e5" + compose_hash},
                                  block_tag]), 16) == 1


def _contract_evidence(app: str, block_tag: str) -> dict:
    """Capture code and EIP-1967 implementation identity at the query block."""
    code = _rpc("eth_getCode", [app, block_tag])
    slot = _rpc("eth_getStorageAt", [app, _EIP1967_IMPLEMENTATION_SLOT, block_tag])
    implementation = "0x" + slot[-40:] if int(slot, 16) else None
    result = {"contract": app, "code_sha256": sha256_hex(bytes.fromhex(code.removeprefix("0x"))),
              "implementation": implementation}
    if implementation:
        impl_code = _rpc("eth_getCode", [implementation, block_tag])
        result["implementation_code_sha256"] = sha256_hex(bytes.fromhex(
            impl_code.removeprefix("0x")))
    return result


def _public_attestation_fields(att: dict) -> dict:
    """Keep only protocol evidence; no HTTP headers, no compose preimage with a literal secret."""
    raw = {key: att[key] for key in (
        "intel_quote", "nvidia_payload", "signing_algo", "signing_public_key",
        "signing_address", "tls_cert_fingerprint", "model_name", "request_nonce",
        "ohttp_key_config", "ohttp_attestation") if key in att}
    if att.get("compose_manager_attestation"):
        raw["compose_manager_attestation"] = {key: att["compose_manager_attestation"][key] for key in (
            "actions", "actions_hash", "nonce", "quote", "report_data", "vm_config", "event_log",
            "nonce_source") if key in att["compose_manager_attestation"]}
    info = att.get("info") or {}
    if isinstance(info, dict):
        kept = {key: info[key] for key in (
            "app_id", "compose_hash", "instance_id", "vm_config", "device_id", "app_cert",
            "key_provider_info", "mr_aggregated", "os_image_hash", "app_name") if key in info}
        tcb = info.get("tcb_info") or {}
        if isinstance(tcb, str):
            try:
                tcb = json.loads(tcb)
            except ValueError:
                tcb = {}
        if isinstance(tcb, dict):
            kept["tcb_info"] = {key: tcb[key] for key in (
                "event_log", "vm_config", "compose_hash",
                "os_image_hash") if key in tcb}
            compose = tcb.get("app_compose")
            if isinstance(compose, str):
                kept["tcb_info"].update(public_compose_preimage(compose))
        raw["info"] = kept
    return raw


_audit_match = audit_match


def _check_tdx(att: Dict) -> Dict:
    """Same verdict as upstream check_tdx_quote, but keeps the TCB status, advisories and
    raw quote that it only prints. `verified` mirrors dcap_qvl: the quote's signature
    and collateral verify, for UpToDate and OutOfDate alike; the TCB currency policy
    is applied separately via TCB_CURRENT_STATUSES (tcb_current)."""
    quote = att["intel_quote"]
    result = dstack_tdx.dcap_verify(quote)
    td10 = json.loads(result.to_json())["report"]["TD10"]
    return {
        "quote": {"body": {"reportdata": td10["report_data"], "mrconfig": td10["mr_config_id"]}},
        "verified": result.status in ("UpToDate", "OutOfDate"),
        "tcb_status": result.status,
        "advisory_ids": list(result.advisory_ids),
        "intel_quote": quote,
    }


def _tdx_evidence(intel: Dict) -> Dict:
    return {k: intel[k] for k in ("tcb_status", "advisory_ids", "intel_quote")}


def _tcb_info(att: Dict) -> Dict:
    tcb_info = (att.get("info") or {}).get("tcb_info") or {}
    return json.loads(tcb_info) if isinstance(tcb_info, str) else tcb_info


def _instance_id_bound(att: Dict, meas: Dict) -> bool:
    """teep da6cbcf: the id equals the payload of the one RTMR3 instance-id event
    of the replayed log, so it is quote-bound only when the replay passed."""
    iid = att["info"]["instance_id"].lower()
    return bool(meas["ok"] and _INSTANCE_ID_RE.fullmatch(iid) and
                dstack_tdx.runtime_events(_tcb_info(att)["event_log"], "instance-id") == [iid])


def _measurement_checks(att: Dict, intel: Dict) -> Dict:
    """Replay this attestation's event log against its quote registers.

    The compose-hash, app-id and os-image-hash that downstream checks consume
    come from the replayed log; the detached JSON info fields must merely agree.
    """
    info = att.get("info") or {}
    tcb_info = _tcb_info(att)
    event_log = tcb_info.get("event_log")
    try:
        measurements = dstack_tdx.attestation_measurements(intel["intel_quote"], event_log)
    except dstack_tdx.EventLogError as exc:
        return {"ok": False, "error": str(exc),
                "boot_registers": {"boot_config": False, "hardware_config": False, "reasons": [
                    f"quote/event-log binding failed ({exc}); image identity unauthenticated"]}}
    detached = {
        "app_id": str(info.get("app_id") or "").lower().removeprefix("0x"),
        "compose_hash": str(tcb_info.get("compose_hash") or "").lower().removeprefix("0x"),
        "os_image_hash": str(tcb_info.get("os_image_hash") or "").lower().removeprefix("0x"),
    }
    disagreements = {key: {"log": measurements[f"log_{key}"], "detached": value}
                     for key, value in detached.items()
                     if value and value != measurements[f"log_{key}"]}
    boot = dstack_boot_registers.check_boot_registers(
        measurements["log_os_image_hash"], measurements["registers"])
    ok = not disagreements
    return {**{k: v for k, v in measurements.items() if k != "mrconfigid"},
            "ok": ok, "detached_json_disagreements": disagreements,
            "boot_registers": boot}


class FetchError(RuntimeError):
    """The attestation endpoint answered with something other than HTTP 200."""


def _base(base_url: str) -> str:
    return base_url.rstrip("/").removesuffix("/v1")


def fetch_report(api_key: Optional[str], base_url: str, model: str, nonce: str) -> dict:
    resp = requests.get(
        f"{_base(base_url)}/v1/attestation/report",
        params={"model": model, "nonce": nonce,
                "signing_algo": "ecdsa", "include_tls_fingerprint": "true"},
        headers={"Authorization": f"Bearer {api_key}"} if api_key else {}, timeout=30,
    )
    if resp.status_code != 200:
        raise FetchError(f"HTTP {resp.status_code}: {resp.text[:200]}")
    return resp.json()


def _fail(model: str, started: float, err: str, report: Optional[dict] = None,
          nonce: str = "", base: str = "", **details) -> AttestationReport:
    if report is not None:
        details["raw_evidence"] = {
            "source": f"{base}/v1/attestation/report", "nonce": nonce,
            "requested_model": model,
            "gateway_attestation": _public_attestation_fields(report.get("gateway_attestation") or {}),
            "model_attestations": [_public_attestation_fields(m) for m in
                                   report.get("model_attestations") or []],
        }
    return AttestationReport(
        provider="near-ai", model=model, valid=False,
        verified_at=now_iso(), attestation_type="tdx+gpu",
        error=err, details=details,
        latency_s=round(time.time() - started, 2),
    )


def entry_identity(m: Dict) -> Tuple:
    """What two entries listed under one instance id must share (quotes themselves differ)."""
    q = dstack_tdx.parse_quote(m["intel_quote"])
    cm = m.get("compose_manager_attestation") or {}
    return (*(q[r] for r in ("mrtd", "rtmr0", "rtmr1", "rtmr2", "rtmr3")),
            str(_tcb_info(m).get("compose_hash") or (m.get("info") or {}).get("compose_hash")),
            m.get("signing_public_key"), str(m.get("signing_address")).lower(),
            m.get("tls_cert_fingerprint"), cm.get("actions_hash"))


def verify(api_key: str, base_url: str, model: str) -> AttestationReport:
    started = time.time()
    nonce = secrets.token_hex(32)
    try:
        report = fetch_report(api_key, base_url, model, nonce)
    except FetchError as exc:
        return _fail(model, started, str(exc))
    archive = near_deployments.load_archive()
    result = appraise_report(report, model, nonce, archive, base_url, started)
    seen = [d for c in result.details.get("model_composes", [])
            for d in c["deployments"].get("deployments", [])]
    if near_deployments.record(seen, archive, near_deployments.utcnow()):
        near_deployments.save_archive(archive)
    return result


def appraise_report(report: dict, model: str, nonce: str, archive: Dict[str, Dict],
                    base_url: str = DEFAULT_BASE_URL,
                    started: Optional[float] = None) -> AttestationReport:
    """Appraise a fetched gateway report. A policy rejection is a returned outcome."""
    started = started or time.time()
    base = _base(base_url)

    def fail(err: str, **details) -> AttestationReport:
        return _fail(model, started, err, report, nonce, base, **details)

    try:
        from model_verifier import check_report_data, check_gpu
    except ImportError:
        return fail("nearai-cloud-verifier not installed; set NEARAI_VERIFIER_PATH")

    gateway = report.get("gateway_attestation", {})
    models = report.get("model_attestations") or []
    if not gateway:
        return fail("no gateway_attestation")
    if not models:
        return fail("no model_attestations")
    if len(models) > _MAX_INSTANCES:
        return fail(f"{len(models)} model_attestations entries exceed the cap of {_MAX_INSTANCES}")
    ids = [(m.get("info") or {}).get("instance_id") for m in models]
    if not all(ids):
        return fail("model_attestations entries need instance ids", instance_ids=ids)
    instance_entries = {iid: ids.count(iid) for iid in dict.fromkeys(ids)}
    for iid, n in instance_entries.items():
        if n > 1 and len({entry_identity(m) for i, m in zip(ids, models) if i == iid}) != 1:
            return fail(f"instance {iid} listed with conflicting identities",
                        instance_ids=ids, instance_entries=instance_entries)
    keys = {tuple(str(m.get(k) or "").lower() for k in (
        "signing_public_key", "signing_address", "signing_algo")) for m in models}
    if len(keys) != 1 or not all(next(iter(keys))):
        return fail("model_attestations entries do not share one signing key",
                    signing_key_shared=False, instance_ids=ids)

    sc = ScoreCard()
    details: Dict[str, Any] = {"inner_models": len(models)}
    archive_revision = sha256_hex(json.dumps(archive, sort_keys=True, separators=(",", ":")))
    now = near_deployments.utcnow()
    chain = _chain_snapshot()
    details["policy_revision"] = archive_revision
    details["deployment_policy"] = {"archive": "data/near-deployments-seen.json",
                                    "min_age_s": DEPLOYMENT_MIN_AGE_S}
    details["chain_snapshot"] = {k: v for k, v in chain.items() if k != "block_tag"}
    details["model_contract"] = _contract_evidence(_MODELS_APP, chain["block_tag"])

    # Gateway TDX + report_data
    gw_intel = _check_tdx(gateway)
    gw_meas = _measurement_checks(gateway, gw_intel)
    gw_debug = dstack_tdx.quote_debug_disabled(gw_intel["intel_quote"])
    details["tdx"] = {"gateway": {**_tdx_evidence(gw_intel), "measurements": gw_meas,
                                  "debug_disabled": gw_debug}, "models": []}
    sc.tdx_verified = gw_intel["verified"]
    if not sc.tdx_verified:
        return fail("gateway TDX quote did not verify", gateway_intel=gw_intel,
                     verification_status="rejected",
                     verification_reason="gateway TDX quote appraisal rejected")

    # Explicit TCB currency policy (teep tee_tcb_current parity): only UpToDate
    # passes; any other verdict leaves the advisories on the row.
    details["tcb_policy"] = {
        "passing_status": sorted(dstack_tdx.TCB_CURRENT_STATUSES),
        "effect": "tcb_current=False for every other Intel PCS verdict; "
                  "tdx_verified still reflects quote signature appraisal",
    }

    buf2 = io.StringIO()
    with _STDOUT_LOCK, contextlib.redirect_stdout(buf2):
        gw_rd = check_report_data(gateway, nonce, gw_intel)
    sc.nonce_bound = bool(gw_rd.get("embeds_nonce"))
    sc.report_data_binds_key = bool(gw_rd.get("binds_address"))

    model_spk = models[0]["signing_public_key"]
    first_model_addr = models[0]["signing_address"]
    entries: list = []
    for i, (iid, m) in enumerate(zip(ids, models)):
        m_intel = _check_tdx(m)
        m_meas = _measurement_checks(m, m_intel)
        observed_model_name = m.get("model_name")
        r = {"instance_id": iid, "tdx_verified": m_intel["verified"], "tcb_status": m_intel["tcb_status"],
             "tcb_current": m_intel["tcb_status"] in dstack_tdx.TCB_CURRENT_STATUSES,
             "debug_disabled": dstack_tdx.quote_debug_disabled(m_intel["intel_quote"]),
             "event_log_replayed": m_meas["ok"], "instance_id_bound": _instance_id_bound(m, m_meas),
             "boot_config": m_meas["boot_registers"]["boot_config"],
             "model_name_matches": observed_model_name == model,
             "nonce_bound": False, "report_data_binds_key": False, "gpu_attested": False,
             "key_derives_to_address": False, "compose_hash_committed": False}
        entries.append(r)
        details["tdx"]["models"].append({**_tdx_evidence(m_intel), "measurements": m_meas,
                                         "debug_disabled": r["debug_disabled"],
                                         "instance_id": iid, "entry": i})
        if not m_intel["verified"]:
            continue
        with _STDOUT_LOCK, contextlib.redirect_stdout(io.StringIO()):
            m_rd = check_report_data(m, nonce, m_intel)
            g = check_gpu(m, nonce)
        r["nonce_bound"] = bool(m_rd.get("embeds_nonce"))
        r["report_data_binds_key"] = bool(m_rd.get("binds_address"))
        r["gpu_verdict"] = g.get("verdict")
        r["gpu_attested"] = g.get("verdict") in ("PASS", True) and bool(g.get("nonce_matches"))
        r["key_derives_to_address"] = (keccak_eth_address(m["signing_public_key"]).lower()
                                       == m["signing_address"].lower())

        app_compose = _tcb_info(m).get("app_compose")
        mr_config = m_intel["quote"]["body"]["mrconfig"]
        if app_compose and mr_config and m_meas["ok"]:
            # h is authorized only because the detached preimage hashes to the
            # log-authenticated compose-hash event and MRCONFIGID commits to it.
            h = sha256_hex(app_compose)
            app_id = m_meas["log_app_id"]
            log_compose = m_meas["log_compose_hash"]
            quote_compose_matches = (
                mr_config.lower().removeprefix("0x").startswith(("01" + h).lower())
                and h == log_compose)
            app_matches = app_id.lower() == _MODELS_APP.removeprefix("0x").lower()
            authorized = _allowed_on_chain(_MODELS_APP, h, chain["block_tag"])
            cm = m.get("compose_manager_attestation")
            deployments = (near_deployments.appraise(cm, m_intel["intel_quote"], nonce, archive,
                                                     DEPLOYMENT_MIN_AGE_S, now)
                           if cm else {"ok": False, "missing": "compose_manager_attestation"})
            r["deployments_ok"] = deployments["ok"]
            r["compose_hash_committed"] = (quote_compose_matches and app_matches and authorized and
                                           deployments["ok"] and observed_model_name == model)
            details.setdefault("model_composes", []).append({
                "instance_id": iid, "entry": i,
                "observed_model_name": observed_model_name, "requested_model_name": model,
                "app_id": app_id, "app_matches": app_matches, "deployments": deployments,
                "compose_hash": h, "log_compose_hash": log_compose,
                "quote_compose_matches": quote_compose_matches,
                "chain_authorized": authorized,
                "chain_block_number": chain["block_number"],
                "chain_block_hash": chain["block_hash"]})

    instances: Dict[str, Dict[str, Any]] = {}
    for iid in instance_entries:  # a layer holds for an instance only if it holds for every entry
        group = [r for r in entries if r["instance_id"] == iid]
        layers = {k for r in group for k, v in r.items() if isinstance(v, bool)}
        instances[iid] = {**group[0], **{k: all(r.get(k) is True for r in group) for k in layers}}

    def every(layer: str) -> bool:
        return all(r[layer] for r in entries)

    sc.tdx_verified = every("tdx_verified")
    sc.nonce_bound = sc.nonce_bound and every("nonce_bound")
    sc.report_data_binds_key = sc.report_data_binds_key and every("report_data_binds_key")
    sc.key_derives_to_address = every("key_derives_to_address")
    sc.gpu_attested = every("gpu_attested")
    sc.compose_hash_committed = every("compose_hash_committed")
    sc.tee_debug_disabled = gw_debug and every("debug_disabled")
    sc.event_log_replayed = gw_meas["ok"] and every("event_log_replayed") and every("instance_id_bound")
    sc.tee_boot_config = gw_meas["boot_registers"]["boot_config"] and every("boot_config")
    # RTMR0 is not derived for NEAR's VM shapes (no vm_config exposed): unproven, not checked.
    sc.tee_hardware_config = None
    sc.tcb_current = gw_intel["tcb_status"] in dstack_tdx.TCB_CURRENT_STATUSES and every("tcb_current")
    model_names_match = every("model_name_matches")
    details["tcb_statuses"] = {"gateway": gw_intel["tcb_status"],
                               "models": [r["tcb_status"] for r in entries]}
    details["model_names_match_request"] = model_names_match
    details["instances"] = instances
    details["entries"] = entries
    details["instance_entries"] = instance_entries
    details["instance_count"] = len(models)
    details["instance_ids"] = ids
    details["signing_key_shared"] = True
    details["instance_limit"] = _INSTANCE_LIMIT

    # These are gateway reference facts, not proof that the gateway verified the
    # downstream model's quote. Historical short ledger prefixes remain metadata
    # and cannot authorize a full digest.
    gw_app_compose = _tcb_info(gateway).get("app_compose") or ""
    gw_mr_config = (gw_intel.get("quote", {}).get("body", {}) or {}).get("mrconfig", "") or ""
    gw_compose_hash = sha256_hex(gw_app_compose) if gw_app_compose else ""
    gw_log_compose_hash = gw_meas.get("log_compose_hash") if gw_meas["ok"] else None
    gw_self_consistent = bool(
        gw_compose_hash
        and gw_mr_config
        and gw_mr_config.lower().startswith(("01" + gw_compose_hash).lower())
        and gw_log_compose_hash == gw_compose_hash
    )
    gw_cloud_api_digest = ""
    if gw_app_compose:
        dcf = json.loads(gw_app_compose).get("docker_compose_file", "")
        m = _CLOUD_API_IMAGE_RE.search(dcf)
        if m:
            gw_cloud_api_digest = m.group(1).lower()

    audit_set, audit_meta = _cloud_api_audit_set()
    gateway_app = json.loads(_CLOUD_API_AUDITS.read_text())["contract_address"]
    details["gateway_contract"] = _contract_evidence(gateway_app, chain["block_tag"])
    chain_authorized = bool(gw_compose_hash and _allowed_on_chain(
        gateway_app, gw_compose_hash, chain["block_tag"]))
    # Ledger keys are full 64-hex digests and matching is exact, so any match is
    # a full-digest match; a retired legacy prefix can never authorize a build.
    audit_key = _audit_match(gw_cloud_api_digest, audit_set)
    sc.gateway_reference_audited = bool(gw_self_consistent and chain_authorized and audit_key)

    details["gateway_compose_hash"] = gw_compose_hash
    details["cloud_api_image_digest"] = gw_cloud_api_digest
    details["gateway_self_consistent"] = gw_self_consistent
    details["chain_authorized"] = chain_authorized
    details["gateway_chain_query"] = {"contract": gateway_app, "compose_hash": gw_compose_hash,
                                       "authorized": chain_authorized,
                                       "block_number": chain["block_number"],
                                       "block_hash": chain["block_hash"],
                                       "chain_id": chain["chain_id"]}
    details["audit_key"] = audit_key
    details["gateway_review_status"] = "reviewed" if audit_key else "unreviewed"
    if audit_key:
        m = audit_meta[audit_key]
        details["audit"] = {
            "audited_at": m.get("audited_at"),
            "audited_by": m.get("audited_by"),
            "verdict": m.get("verdict"),
            "audit_doc": m.get("audit_doc"),
        }

    _assert_same_block(chain)
    details["chain_snapshot"]["block_hash_rechecked"] = True

    checked_ok = (
        sc.tdx_verified is True
        and sc.nonce_bound is True
        and sc.report_data_binds_key is True
        and sc.key_derives_to_address is True
        and sc.gpu_attested is True
        and sc.tee_debug_disabled is True
        and sc.event_log_replayed is True
        and sc.tcb_current is True
        and sc.tee_boot_config is True
        and model_names_match
        and sc.compose_hash_committed is True
        and gw_self_consistent
        and chain_authorized
    )
    details["request_path_verified"] = False
    details["verification_status"] = "not_checked" if checked_ok else "rejected"
    details["verification_reason"] = (
        "model/compose-manager actions and encrypted request are not quote-bound end to end"
        if checked_ok else "quote, model mapping, compose, key, GPU, TCB currency, "
        "debug-bit, event-log, boot-config or chain-policy check failed")
    details["raw_evidence"] = {
        "source": f"{base}/v1/attestation/report",
        "requested_model": model, "nonce": nonce,
        "gateway_attestation": _public_attestation_fields(gateway),
        "model_attestations": [_public_attestation_fields(m) for m in models],
        "tls_certificate": report.get("tls_certificate"),
        "ohttp_key_config": report.get("ohttp_key_config"),
        "ohttp_attestation": report.get("ohttp_attestation"),
        "deployment_archive": archive, "deployment_archive_sha256": archive_revision,
        "chain_snapshot": details["chain_snapshot"],
        "model_contract": details["model_contract"],
        "gateway_contract": details["gateway_contract"],
        "model_authorization_queries": details.get("model_composes") or [],
        "gateway_authorization_query": details["gateway_chain_query"],
    }
    preimages = [details["raw_evidence"]["gateway_attestation"]] + details["raw_evidence"]["model_attestations"]
    withheld = any(((entry.get("info") or {}).get("tcb_info") or {}).get(
        "app_compose_preimage_status") == "withheld_potential_secret" for entry in preimages)
    details["raw_evidence_completeness"] = "partial_sensitive_preimage_withheld" if withheld else "complete"

    return AttestationReport(
        provider="near-ai", model=model, valid=False,
        verified_at=now_iso(), attestation_type="tdx+gpu",
        signing_address=first_model_addr, signing_public_key=model_spk,
        scorecard=sc, details=details,
        latency_s=round(time.time() - started, 2),
    )
