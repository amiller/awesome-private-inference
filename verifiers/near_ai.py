"""NEAR AI attestation verifier.

Relies on the vendored nearai-cloud-verifier modules (`model_verifier`,
`domain_verifier`). Make sure `NEARAI_VERIFIER_PATH` points at the repo's `py/`
directory before importing `verify()`.
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
    sha256_hex,
)

DEFAULT_BASE_URL = "https://cloud-api.near.ai"
_STDOUT_LOCK = threading.Lock()

_REPO_ROOT = Path(__file__).resolve().parents[1]
_ONCHAIN_STATUS = _REPO_ROOT / "data" / "onchain-status.json"
_CLOUD_API_AUDITS = _REPO_ROOT / "data" / "audits" / "near-ai_cloud-api.json"

_CLOUD_API_IMAGE_RE = re.compile(
    r"nearaidev/cloud-api@sha256:([0-9a-f]{64})"
)


@lru_cache(maxsize=1)
def _cloud_api_audit_set() -> Tuple[Set[str], Dict[str, Dict]]:
    """Read the analyst-pair audit ledger. Returns (digest_set, metadata_by_digest).
    digest_set contains both full digests and truncated prefixes; match uses startswith."""
    return load_audit_ledger(_CLOUD_API_AUDITS, "image_digest")


@lru_cache(maxsize=1)
def _cloud_api_chain_set() -> Set[str]:
    """Compose hashes authorized on Base for the cloud-api DstackApp contract."""
    audits = json.loads(_CLOUD_API_AUDITS.read_text())
    target_addr = audits["contract_address"].lower()
    status = json.loads(_ONCHAIN_STATUS.read_text())
    for c in status["contracts"]:
        if c["address"].lower() == target_addr:
            return {d["compose_hash"].lower() for d in c["distinct_compose_hashes"]}
    raise RuntimeError(
        f"data/onchain-status.json has no contract entry for {target_addr}; "
        "refresh probes/onchain_sweep.py or update CONTRACTS list"
    )


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


def verify(api_key: str, base_url: str, model: str) -> AttestationReport:
    started = time.time()
    base = base_url.rstrip("/")
    if base.endswith("/v1"):
        base = base[:-3]
    nonce = secrets.token_hex(32)

    def _fail(err: str, **details) -> AttestationReport:
        return AttestationReport(
            provider="near-ai", model=model, valid=False,
            verified_at=now_iso(), attestation_type="tdx+gpu",
            error=err, details=details,
            latency_s=round(time.time() - started, 2),
        )

    try:
        from model_verifier import check_tdx_quote, check_report_data, check_gpu
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

    gateway = report.get("gateway_attestation", {})
    models = report.get("model_attestations") or []
    if not gateway:
        return _fail("no gateway_attestation")
    if not models:
        return _fail("no model_attestations")

    sc = ScoreCard()
    details: Dict[str, Any] = {"inner_models": len(models)}

    # Gateway TDX + report_data
    buf = io.StringIO()
    with _STDOUT_LOCK, contextlib.redirect_stdout(buf):
        gw_intel = _sync(check_tdx_quote(gateway))
    sc.tdx_verified = bool(gw_intel and gw_intel.get("verified"))
    if not sc.tdx_verified:
        return _fail("gateway TDX quote did not verify", gateway_intel=gw_intel)

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
    compose_ok = None

    for i, m in enumerate(models):
        buf_m = io.StringIO()
        with _STDOUT_LOCK, contextlib.redirect_stdout(buf_m):
            m_intel = _sync(check_tdx_quote(m))
        if not (m_intel and m_intel.get("verified")):
            model_ok = False
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
        tcb_info = info.get("tcb_info") or {}
        if isinstance(tcb_info, str):
            try:
                tcb_info = json.loads(tcb_info)
            except Exception:
                tcb_info = {}
        app_compose = tcb_info.get("app_compose")
        mr_config = (m_intel.get("quote", {}).get("body", {}) or {}).get("mrconfig", "")
        if app_compose and mr_config:
            compose_ok = mr_config.lower().startswith(("01" + sha256_hex(app_compose)).lower())

    sc.key_derives_to_address = key_ok
    sc.gpu_attested = gpu_ok
    sc.compose_hash_committed = compose_ok

    # backend_attested = tri-state based on (1) gateway quote self-attests the
    # measured compose, (2) compose_hash is in the on-chain authorized set for
    # the cloud-api DstackApp on Base, (3) cloud-api image digest is in our
    # analyst-pair audit ledger. Outcomes:
    #   True              — chain-authorized AND audited
    #   "audit_pending"   — chain-authorized AND self-consistent, but the audit
    #                       ledger hasn't caught up to this image digest yet
    #                       (analyst backlog, not a provider fault)
    #   False             — quote doesn't self-attest, or compose not chain-authorized
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

    chain_set = _cloud_api_chain_set()
    audit_set, audit_meta = _cloud_api_audit_set()
    chain_authorized = gw_compose_hash in chain_set
    audit_key = _audit_match(gw_cloud_api_digest, audit_set)

    if not (gw_self_consistent and chain_authorized):
        sc.backend_attested = False
    elif audit_key is not None:
        sc.backend_attested = True
    else:
        sc.backend_attested = "audit_pending"

    details["gateway_compose_hash"] = gw_compose_hash
    details["cloud_api_image_digest"] = gw_cloud_api_digest
    details["gateway_self_consistent"] = gw_self_consistent
    details["chain_authorized"] = chain_authorized
    details["audit_key"] = audit_key
    if audit_key:
        m = audit_meta[audit_key]
        details["audit"] = {
            "audited_at": m.get("audited_at"),
            "audited_by": m.get("audited_by"),
            "verdict": m.get("verdict"),
            "audit_doc": m.get("audit_doc"),
        }

    valid = (
        sc.tdx_verified is True
        and sc.nonce_bound is True
        and sc.report_data_binds_key is True
        and sc.key_derives_to_address is True
        and sc.gpu_attested is True
        and model_ok
    )

    return AttestationReport(
        provider="near-ai", model=model, valid=valid,
        verified_at=now_iso(), attestation_type="tdx+gpu",
        signing_address=first_model_addr, signing_public_key=model_spk,
        scorecard=sc, details=details,
        latency_s=round(time.time() - started, 2),
    )
