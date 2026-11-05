"""End-to-end replay of the owner's real keyed Chutes capture (2026-11-05).

Chutes transport is mocked (the capture stands in for the keyed endpoints);
everything else is real: the actual quotes, certificates, gpu_evidence blobs,
the live NRAS response pinned in tests/fixtures/nras_attest_response.json and
NVIDIA's pinned production JWKS. Register matching runs against the real
published measurements.
"""
import base64
import json
from pathlib import Path

import pytest

from verifiers import chutes, nvidia_nras

FIXTURES = Path(__file__).resolve().parent / "fixtures"
CAPTURE = json.loads((FIXTURES / "chutes_capture_sample.json").read_text())
NRAS = json.loads((FIXTURES / "nras_attest_response.json").read_text())


class Response:
    status_code = 200

    def __init__(self, value):
        self.value = value

    def json(self):
        return self.value


def _run(monkeypatch, model, *, gpu_items=None, nras_response=None, jwks=None):
    entry = CAPTURE["models"][model]
    evidence = dict(entry["evidence"])
    if gpu_items is not None:
        evidence["gpu_evidence"] = gpu_items
    nonce = entry["nonce"]

    def get(url, *, headers, timeout):
        assert headers == {"Authorization": "Bearer test-token"}
        if url.endswith("/servers/tee/measurements"):
            return Response(CAPTURE["measurements"])
        if "/e2e/instances/" in url:
            return Response(entry["instances_response"])
        assert url.endswith(f"/evidence?nonce={nonce}"), url
        return Response(evidence)

    monkeypatch.setattr(chutes.requests, "get", get)
    monkeypatch.setattr(chutes.secrets, "token_hex", lambda n: nonce)
    monkeypatch.setattr(chutes.nvidia_nras, "fetch_jwks",
                        lambda: jwks or nvidia_nras.load_pinned_jwks())
    if nras_response is not None:
        monkeypatch.setattr(chutes.nvidia_nras, "attest_gpu_evidence",
                            lambda items, n, timeout=90: nras_response)
    monkeypatch.setattr(chutes.phala_tdx, "verify_tdx_quote", lambda v: {"quote": {"verified": True}})
    monkeypatch.setattr(chutes.phala_tdx, "is_verified", lambda v: True)
    monkeypatch.setattr(chutes.phala_tdx, "quote_body", lambda v: {"reportdata": "x"})
    monkeypatch.setattr(chutes, "_tcb_appraisal",
                        lambda q: {"tcb_status": "UpToDate", "advisory_ids": []})
    report = chutes.verify("test-token", "https://api.chutes.ai", model)
    fleet = report.details["fleet"][0]
    return report, fleet


def test_real_glm_instance_passes_crypto_core_with_real_nras_verdict(monkeypatch):
    report, fleet = _run(monkeypatch, "GLM-5.1-TEE")
    assert report.details["verification_status"] == "not_checked"
    assert fleet["outcome"] == "verified_core"
    assert fleet["gpu_attested"] is True
    assert fleet["matched_rows"] == [{
        "name": "8xh200 [10.2.1, numa-124c-1128g-nvsw-node1]", "version": "1.4.1",
        "fingerprint": "44b568b6d16d07520c7a29cd489fe0df89765986ea255a27498f7c7c6b62306e",
        "mrtd": fleet["mrtd"].upper(),  # the publication carries uppercase hex
        "expected_gpus": ["h200"], "gpu_count": 8}]
    assert report.scorecard.gpu_attested is True
    assert report.details["fleet_size_semantics"]


def test_real_gemma_instance_rejected_for_uncovered_gpu_count(monkeypatch):
    report, fleet = _run(monkeypatch, "gemma-4-31B-TEE")
    assert fleet["outcome"] == "rejected"
    assert fleet["gpu_attested"] is False
    assert "gpu_count_mismatch" in fleet["reason"]
    assert report.details["verification_status"] == "rejected"
    assert report.scorecard.gpu_attested is False


def test_tampered_gpu_item_nonce_rejects_real_instance(monkeypatch):
    """CPU↔GPU association negative: one blob re-nonce'd to another TD must
    reject even though the (real) NRAS verdict is a pass."""
    entry = CAPTURE["models"]["GLM-5.1-TEE"]
    items = [dict(item) for item in entry["evidence"]["gpu_evidence"]]
    blob = bytearray(base64.b64decode(items[3]["evidence"]))
    blob[4:36] = bytes.fromhex("ff" * 32)
    items[3]["evidence"] = base64.b64encode(bytes(blob)).decode()
    report, fleet = _run(monkeypatch, "GLM-5.1-TEE", gpu_items=items)
    assert fleet["gpu_attested"] is False
    assert fleet["reason"].startswith("gpu_appraisal_rejected")
    assert "gpu_evidence_nonce_not_bound_to_td_report_data" in fleet["reason"]


def test_dropped_gpu_item_rejects_real_instance(monkeypatch):
    entry = CAPTURE["models"]["GLM-5.1-TEE"]
    items = entry["evidence"]["gpu_evidence"][:-1]
    report, fleet = _run(monkeypatch, "GLM-5.1-TEE", gpu_items=items)
    assert fleet["gpu_attested"] is False
    assert "gpu_count_mismatch" in fleet["reason"]


def test_platform_verdict_false_in_nras_response_rejects(monkeypatch):
    """NRAS-attested failure: platform JWT verdict flipped to false without a
    valid signature cannot pass (re-signed by a test key outside the pinned
    JWKS, so the signature check rejects it first)."""
    entry = NRAS["responses"]["GLM-5.1-TEE"]
    response = json.loads(json.dumps(entry["response"]))
    platform = response[0][1]
    header_b64, payload_b64, sig_b64 = platform.split(".")
    payload = json.loads(nvidia_nras._b64url_decode(payload_b64))
    payload["x-nvidia-overall-att-result"] = False
    forged = (f"{header_b64}."
              f"{base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')}"
              f".{sig_b64}")
    response[0][1] = forged
    report, fleet = _run(monkeypatch, "GLM-5.1-TEE", nras_response=response)
    assert fleet["gpu_attested"] is False
    assert fleet["reason"].startswith("gpu_appraisal_rejected")
    assert "signature_invalid" in fleet["reason"]


def test_nras_transport_failure_leaves_gpu_layer_unverified_not_passed(monkeypatch):
    def unreachable(items, n, timeout=90):
        raise nvidia_nras.requests.ConnectionError("nras down")
    monkeypatch.setattr(chutes.nvidia_nras, "attest_gpu_evidence", unreachable)
    report, fleet = _run(monkeypatch, "GLM-5.1-TEE")
    assert fleet["gpu_attested"] is None
    assert "nras_unreachable" in fleet["gpu_reason"]
    # an unverified layer must not read as a pass anywhere
    assert report.scorecard.gpu_attested is None
    assert report.details["verification_status"] == "rejected"


def test_absent_gpu_evidence_is_unverified_not_passed(monkeypatch):
    report, fleet = _run(monkeypatch, "GLM-5.1-TEE", gpu_items=[])
    assert fleet["gpu_attested"] is None
    assert fleet["reason"].startswith("gpu_layer_unverified")
    assert fleet["reason"].count("no_gpu_evidence_in_response")
    assert report.details["verification_status"] == "rejected"
