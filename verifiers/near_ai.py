"""NEAR AI attestation verifier.

Relies on the vendored nearai-cloud-verifier modules (`model_verifier`,
`domain_verifier`). These live in a local clone at `_nearai-verifier/py`
(gitignored; CI clones it), which is the default search path; set
`NEARAI_VERIFIER_PATH` to override before importing `verify()`.
"""
from __future__ import annotations

import asyncio
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
    digest_set contains both full digests and truncated prefixes; match uses startswith."""
    return load_audit_ledger(_CLOUD_API_AUDITS, "image_digest")


_MODELS_APP = "0x2c0a0c96cb6dbd659bf1446e2f3fce58172ff91b"  # DstackApp shared by every NEAR AI model CVM
_EIP1967_IMPLEMENTATION_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
_HERMES_ANCHOR = ("https://raw.githubusercontent.com/amiller/hermes-agent/"
                  "feat/near-ai-attestation/hermes_cli/anchors/nearai_mainnet.json")


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


@lru_cache(maxsize=1)
def _anchored_model_composes() -> dict:
    """Keep model, app and compose together; never union across model policies."""
    r = requests.get(_HERMES_ANCHOR, timeout=20)
    r.raise_for_status()
    return r.json()


def _anchor_matches_model(anchor: dict, requested: str, observed: str,
                          app_id: str, compose_hash: str) -> bool:
    policy = anchor.get("models", {}).get(requested) or {}
    actual_app = app_id.lower().removeprefix("0x")
    expected_app = str(policy.get("app_id") or "").lower().removeprefix("0x")
    allowed = {h.lower().removeprefix("0x") for h in policy.get("compose_hashes", [])}
    return (observed == requested and bool(actual_app) and
            actual_app == expected_app == _MODELS_APP.removeprefix("0x") and
            compose_hash.lower().removeprefix("0x") in allowed)


def _public_attestation_fields(att: dict) -> dict:
    """Keep only protocol evidence consumed by our checks; no HTTP headers."""
    raw = {key: att[key] for key in (
        "intel_quote", "nvidia_payload", "signing_algo", "signing_public_key",
        "signing_address", "tls_cert_fingerprint", "model_name") if key in att}
    info = att.get("info") or {}
    if isinstance(info, dict):
        kept = {key: info[key] for key in ("app_id", "compose_hash")
                if key in info}
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


async def _check_tdx(att: Dict) -> Dict:
    """Same verdict as upstream check_tdx_quote, but keeps the TCB status, advisories and
    raw quote that it only prints. Both UpToDate and OutOfDate count as verified."""
    import dcap_qvl
    quote = att["intel_quote"]
    result = await dcap_qvl.get_collateral_and_verify(bytes.fromhex(quote))
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


def verify(api_key: str, base_url: str, model: str) -> AttestationReport:
    started = time.time()
    base = base_url.rstrip("/")
    if base.endswith("/v1"):
        base = base[:-3]
    nonce = secrets.token_hex(32)
    captured_report: dict | None = None

    def _fail(err: str, **details) -> AttestationReport:
        if captured_report is not None:
            details["raw_evidence"] = {
                "source": f"{base}/v1/attestation/report", "nonce": nonce,
                "requested_model": model,
                "gateway_attestation": _public_attestation_fields(
                    captured_report.get("gateway_attestation") or {}),
                "model_attestations": [_public_attestation_fields(m) for m in
                                       captured_report.get("model_attestations") or []],
            }
        return AttestationReport(
            provider="near-ai", model=model, valid=False,
            verified_at=now_iso(), attestation_type="tdx+gpu",
            error=err, details=details,
            latency_s=round(time.time() - started, 2),
        )

    try:
        from model_verifier import check_report_data, check_gpu
    except ImportError:
        return _fail("nearai-cloud-verifier not installed; set NEARAI_VERIFIER_PATH")

    resp = requests.get(
        f"{base}/v1/attestation/report",
        params={
            "model": model, "nonce": nonce,
            "signing_algo": "ecdsa", "include_tls_fingerprint": "true",
        },
        headers={"Authorization": f"Bearer {api_key}"}, timeout=30,
    )
    if resp.status_code != 200:
        return _fail(f"HTTP {resp.status_code}: {resp.text[:200]}")
    report = resp.json()
    captured_report = report

    gateway = report.get("gateway_attestation", {})
    models = report.get("model_attestations") or []
    if not gateway:
        return _fail("no gateway_attestation")
    if not models:
        return _fail("no model_attestations")

    sc = ScoreCard()
    details: Dict[str, Any] = {"inner_models": len(models)}
    anchor = _anchored_model_composes()
    anchor_policy = anchor.get("models", {}).get(model) or {}
    anchor_revision = sha256_hex(json.dumps(anchor, sort_keys=True, separators=(",", ":")))
    chain = _chain_snapshot()
    details["anchor_policy_revision_sha256"] = anchor_revision
    details["anchor_model"] = model
    details["chain_snapshot"] = {k: v for k, v in chain.items() if k != "block_tag"}
    details["model_contract"] = _contract_evidence(_MODELS_APP, chain["block_tag"])

    # Gateway TDX + report_data
    gw_intel = _sync(_check_tdx(gateway))
    details["tdx"] = {"gateway": _tdx_evidence(gw_intel), "models": []}
    sc.tdx_verified = gw_intel["verified"]
    if not sc.tdx_verified:
        return _fail("gateway TDX quote did not verify", gateway_intel=gw_intel,
                     verification_status="rejected",
                     verification_reason="gateway TDX quote appraisal rejected")

    buf2 = io.StringIO()
    with _STDOUT_LOCK, contextlib.redirect_stdout(buf2):
        gw_rd = check_report_data(gateway, nonce, gw_intel)
    sc.nonce_bound = bool(gw_rd.get("embeds_nonce"))
    sc.report_data_binds_key = bool(gw_rd.get("binds_address"))

    # Model-level TDX + GPU + key derivation
    model_spk = ""
    first_model_addr = ""
    model_ok = True
    gpu_ok = True
    key_ok = True
    compose_checks = []
    model_names_match = True

    for i, m in enumerate(models):
        m_intel = _sync(_check_tdx(m))
        details["tdx"]["models"].append(_tdx_evidence(m_intel))
        if not m_intel["verified"]:
            model_ok = False
            gpu_ok = False
            key_ok = False
            compose_checks.append(False)
            continue
        buf_m2 = io.StringIO()
        with _STDOUT_LOCK, contextlib.redirect_stdout(buf_m2):
            m_rd = check_report_data(m, nonce, m_intel)
        if not (m_rd.get("binds_address") and m_rd.get("embeds_nonce")):
            model_ok = False

        buf_m3 = io.StringIO()
        with _STDOUT_LOCK, contextlib.redirect_stdout(buf_m3):
            g = check_gpu(m, nonce)
        if g.get("verdict") not in ("PASS", True) or not g.get("nonce_matches"):
            gpu_ok = False
        if i == 0:
            details["gpu_verdict"] = g.get("verdict")

        spk = m.get("signing_public_key", "")
        addr = m.get("signing_address", "")
        key_ok = key_ok and bool(spk and addr)
        if spk and addr:
            try:
                derives = keccak_eth_address(spk).lower() == addr.lower()
            except Exception:
                derives = False
            key_ok = key_ok and derives
            if i == 0:
                model_spk = spk
                first_model_addr = addr

        # compose_hash
        info = m.get("info", {})
        observed_model_name = m.get("model_name")
        model_names_match = model_names_match and observed_model_name == model
        tcb_info = info.get("tcb_info") or {}
        if isinstance(tcb_info, str):
            try:
                tcb_info = json.loads(tcb_info)
            except Exception:
                tcb_info = {}
        app_compose = tcb_info.get("app_compose")
        mr_config = (m_intel.get("quote", {}).get("body", {}) or {}).get("mrconfig", "")
        if app_compose and mr_config:
            quote_compose_matches = mr_config.lower().removeprefix("0x").startswith(
                ("01" + sha256_hex(app_compose)).lower())
            h = sha256_hex(app_compose)
            app_id = str(info.get("app_id") or "").lower().removeprefix("0x")
            expected_app_id = str(anchor_policy.get("app_id") or "").lower().removeprefix("0x")
            anchored = _anchor_matches_model(anchor, model, observed_model_name, app_id, h)
            authorized = _allowed_on_chain(_MODELS_APP, h, chain["block_tag"])
            compose_checks.append(quote_compose_matches and anchored and authorized and
                                  observed_model_name == model)
            details.setdefault("model_composes", []).append({
                "observed_model_name": observed_model_name, "requested_model_name": model,
                "app_id": app_id, "expected_app_id": expected_app_id,
                "compose_hash": h, "quote_compose_matches": quote_compose_matches,
                "chain_authorized": authorized, "anchored": anchored,
                "anchor_policy_revision_sha256": anchor_revision,
                "chain_block_number": chain["block_number"],
                "chain_block_hash": chain["block_hash"]})
        else:
            compose_checks.append(False)

    sc.key_derives_to_address = key_ok
    sc.gpu_attested = gpu_ok
    sc.compose_hash_committed = bool(compose_checks and all(compose_checks))
    details["model_names_match_request"] = model_names_match

    # These are gateway reference facts, not proof that the gateway verified the
    # downstream model's quote. Historical short ledger prefixes remain metadata
    # and cannot authorize a full digest.
    gw_tcb = (gateway.get("info") or {}).get("tcb_info") or {}
    if isinstance(gw_tcb, str):
        gw_tcb = json.loads(gw_tcb)
    gw_app_compose = gw_tcb.get("app_compose") or ""
    gw_mr_config = (gw_intel.get("quote", {}).get("body", {}) or {}).get("mrconfig", "") or ""
    gw_compose_hash = sha256_hex(gw_app_compose) if gw_app_compose else ""
    gw_self_consistent = bool(
        gw_compose_hash
        and gw_mr_config
        and gw_mr_config.lower().startswith(("01" + gw_compose_hash).lower())
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
    full_audit_key = (gw_cloud_api_digest if len(gw_cloud_api_digest) == 64
                      and gw_cloud_api_digest in audit_set else None)
    audit_key = full_audit_key or _audit_match(gw_cloud_api_digest, audit_set)
    sc.gateway_reference_audited = bool(gw_self_consistent and chain_authorized and full_audit_key)

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
    details["full_digest_audit_key"] = full_audit_key
    details["audit_match_scope"] = (
        "full_digest" if full_audit_key else
        "legacy_prefix_hint" if audit_key else "none")
    details["gateway_review_status"] = "reviewed" if full_audit_key else "unreviewed"
    if full_audit_key:
        m = audit_meta[full_audit_key]
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
        and model_ok
        and model_names_match
        and sc.compose_hash_committed is True
        and gw_self_consistent
        and chain_authorized
    )
    details["request_path_verified"] = False
    details["verification_status"] = "not_checked" if checked_ok else "rejected"
    details["verification_reason"] = (
        "model/compose-manager actions and encrypted request are not quote-bound end to end"
        if checked_ok else "quote, model mapping, compose, key, GPU, or chain-policy check failed")
    details["raw_evidence"] = {
        "source": f"{base}/v1/attestation/report",
        "requested_model": model, "nonce": nonce,
        "gateway_attestation": _public_attestation_fields(gateway),
        "model_attestations": [_public_attestation_fields(m) for m in models],
        "tls_certificate": report.get("tls_certificate"),
        "anchor_url": _HERMES_ANCHOR, "anchor_policy": anchor,
        "anchor_sha256": anchor_revision,
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
