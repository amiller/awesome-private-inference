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
from typing import Any, Dict, Optional
from urllib.parse import urlparse

import requests

_vendor = os.environ.get("NEARAI_VERIFIER_PATH")
if _vendor and _vendor not in sys.path:
    sys.path.insert(0, _vendor)

from .common import (
    AttestationReport,
    ScoreCard,
    keccak_eth_address,
    now_iso,
    sha256_hex,
)

DEFAULT_BASE_URL = "https://cloud-api.near.ai"
_STDOUT_LOCK = threading.Lock()

# cloud-api image digests audited to include inline backend verification
# (PR #552 merged 2026-04-27 + #558 2026-05-01). Pinning the image digest
# rather than the compose-JSON hash keeps the check stable across env-var /
# allowed_envs edits that don't change cloud-api behavior. Refresh when
# prod rotates: probe /v1/attestation/report, extract nearaidev/cloud-api
# image digest from gateway_attestation.info.tcb_info.app_compose.docker_compose_file,
# verify cloud-api source at that build still carries #552 + #558, add below.
_INLINE_VERIFY_CLOUD_API_DIGESTS = {
    # 2026-05-02 capture (compose 2e84b721…). Audited inline TDX+RTMR3+GPU NRAS
    # + SPKI fingerprint pinning in cloud-api commit 2cb48d2c54da via
    # devproof-audits-guide DEVPROOF-REPORT-revisit-2026-05-02.md §"What
    # inline verification actually checks".
    "22763fe4",  # prefix; only the audit doc's truncated form is on record
    # 2026-05-15 capture (compose 224ebb66…). Live-observed after a gateway
    # rotation that did not change inline-verify behavior (image digest only
    # rotates on actual code changes). NEAR has continuously shipped against
    # the post-#552 baseline; no revert of inline-verify visible in cloud-api
    # release notes or commit log between 2026-05-02 and 2026-05-15.
    "67dac8134ca6d048098e40a8faff0b44a5c34e96d4c00fba56a80c2d147a8e9c",
}

_CLOUD_API_IMAGE_RE = re.compile(
    r"nearaidev/cloud-api@sha256:([0-9a-f]{64})"
)


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

    # backend_attested = "gateway is running cloud-api code that inline-verifies
    # each backend's TDX/RTMR3/NRAS before serving" (cloud-api PR #552 + #558,
    # Apr/May 2026). The gateway's deployed code is itself attested via its TDX
    # quote; we confirm we're talking to that code by extracting the cloud-api
    # image digest from the measured compose and checking it's in our audited set.
    gw_tcb = (gateway.get("info") or {}).get("tcb_info") or {}
    if isinstance(gw_tcb, str):
        try:
            gw_tcb = json.loads(gw_tcb)
        except Exception:
            gw_tcb = {}
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
        try:
            dcf = json.loads(gw_app_compose).get("docker_compose_file", "")
            m = _CLOUD_API_IMAGE_RE.search(dcf)
            if m:
                gw_cloud_api_digest = m.group(1)
        except Exception:
            pass
    digest_audited = any(
        gw_cloud_api_digest.startswith(d) for d in _INLINE_VERIFY_CLOUD_API_DIGESTS
    )
    sc.backend_attested = gw_self_consistent and digest_audited
    details["gateway_compose_hash"] = gw_compose_hash
    details["cloud_api_image_digest"] = gw_cloud_api_digest

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
