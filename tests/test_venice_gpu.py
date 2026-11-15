"""Venice NRAS GPU appraisal: signature-verified JWTs, nonce-bound to our
request. Replays the live unauthenticated capture of Venice's
/tee/attestation (tests/fixtures/venice_attestation_sample.json, captured
2026-11-05 with a fresh 32-byte nonce) and the live NRAS response it
produced (tests/fixtures/nras_venice_response.json) against NVIDIA's
production JWKS captured the same day, with the clock pinned to the NRAS
capture time. Only Phala's TDX verifier is mocked (transport);
negative controls mutate one authenticated input at a time and must each
reject.
"""
import base64
import json
from pathlib import Path

import pytest
import requests

from tests.nras_capture import JWKS, pin_clock
from verifiers import nvidia_nras, venice

FIXTURES = Path(__file__).resolve().parent / "fixtures"
CAPTURE = json.loads((FIXTURES / "venice_attestation_sample.json").read_text())
NRAS = json.loads((FIXTURES / "nras_venice_response.json").read_text())
MODEL = "e2ee-qwen3-6-35b-a3b"


def _run(monkeypatch, *, att=None, nvidia_payload=None, nras_response=None,
         nras_error=None):
    att = att if att is not None else CAPTURE["response"]
    if nvidia_payload is not None:
        att = dict(att, nvidia_payload=nvidia_payload)
    nonce = CAPTURE["request_nonce"]

    class Response:
        status_code = 200
        text = ""

        def json(self):
            return att

    def get(url, *, params, headers, timeout):
        assert params == {"model": MODEL, "nonce": nonce}
        return Response()

    addr = att.get("signing_address", "")
    reportdata = addr.removeprefix("0x").ljust(64, "0") + nonce

    monkeypatch.setattr(venice.requests, "get", get)
    monkeypatch.setattr(venice.secrets, "token_hex", lambda n: nonce)
    monkeypatch.setattr(venice.phala_tdx, "verify_tdx_quote", lambda v: {"quote": {"verified": True}})
    monkeypatch.setattr(venice.phala_tdx, "is_verified", lambda v: True)
    monkeypatch.setattr(venice.phala_tdx, "quote_body", lambda v: {
        "reportdata": reportdata, "mrconfig": ""})
    monkeypatch.setattr(nvidia_nras, "fetch_jwks", lambda: JWKS)
    pin_clock(monkeypatch, NRAS["captured_utc"])
    if nras_error is not None:
        def unreachable(payload, timeout=90):
            raise nras_error
        monkeypatch.setattr(nvidia_nras, "attest_payload", unreachable)
    else:
        response = nras_response if nras_response is not None else NRAS["response"]
        monkeypatch.setattr(nvidia_nras, "attest_payload",
                            lambda payload, timeout=90: response)
    return venice.verify("key", venice.DEFAULT_BASE_URL, MODEL)


def test_real_capture_passes_signature_verified_gpu_appraisal(monkeypatch):
    report = _run(monkeypatch, nras_response=NRAS["response"])
    appraisal = report.details["gpu_appraisal"]
    assert appraisal["gpu_attested"] is True
    assert appraisal["verified_gpu_count"] == 8
    assert report.scorecard.gpu_attested is True
    assert report.scorecard.nonce_bound is True
    assert report.scorecard.report_data_binds_key is True
    assert report.details["gpu_count_pinned"] is False


def test_payload_nonce_for_another_session_rejects(monkeypatch):
    payload = CAPTURE["response"]["nvidia_payload"]
    if isinstance(payload, str):
        payload = json.loads(payload)
    payload = json.loads(json.dumps(payload))
    payload["nonce"] = "ff" * 32
    report = _run(monkeypatch, nvidia_payload=payload,
                  nras_response=NRAS["response"])
    assert report.scorecard.gpu_attested is False
    assert report.details["gpu_error"] == "nvidia_payload_nonce_is_not_the_request_nonce"


def test_tampered_platform_jwt_rejects(monkeypatch):
    response = json.loads(json.dumps(NRAS["response"]))
    platform = response[0][1]
    header_b64, payload_b64, sig_b64 = platform.split(".")
    payload = json.loads(nvidia_nras._b64url_decode(payload_b64))
    payload["eat_nonce"] = CAPTURE["request_nonce"]  # keep the nonce, forged bytes
    forged = (f"{header_b64}."
              f"{base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')}"
              f".{sig_b64}")
    response[0][1] = forged
    report = _run(monkeypatch, nras_response=response)
    assert report.scorecard.gpu_attested is False
    assert "signature_invalid" in report.details["gpu_appraisal"]["platform"]["reason"]


def test_dropped_per_gpu_token_rejects(monkeypatch):
    response = json.loads(json.dumps(NRAS["response"]))
    response[1].pop("GPU-3")
    report = _run(monkeypatch, nras_response=response)
    assert report.scorecard.gpu_attested is False
    assert "evidence_item_count_mismatch" in report.details["gpu_appraisal"]["reason"]


def test_platform_verdict_false_rejects(monkeypatch):
    """The same real tokens with the platform verdict flipped (re-signed by a
    test key, so the pinned-JWKS signature check rejects it)."""
    response = json.loads(json.dumps(NRAS["response"]))
    platform = response[0][1]
    header_b64, payload_b64, sig_b64 = platform.split(".")
    payload = json.loads(nvidia_nras._b64url_decode(payload_b64))
    payload["x-nvidia-overall-att-result"] = False
    forged = (f"{header_b64}."
              f"{base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')}"
              f".{sig_b64}")
    response[0][1] = forged
    report = _run(monkeypatch, nras_response=response)
    assert report.scorecard.gpu_attested is False
    assert "signature_invalid" in report.details["gpu_appraisal"]["platform"]["reason"]


def test_nras_unreachable_leaves_gpu_unverified_not_passed(monkeypatch):
    report = _run(monkeypatch, nras_error=requests.ConnectionError("nras down"))
    assert report.scorecard.gpu_attested is None
    assert "nras_unreachable" in report.details["gpu_error"]
    assert report.valid is False


def test_missing_nvidia_payload_leaves_gpu_layer_unchecked(monkeypatch):
    att = dict(CAPTURE["response"])
    att.pop("nvidia_payload")
    report = _run(monkeypatch, att=att)
    assert report.scorecard.gpu_attested is None
    assert "gpu_appraisal" not in report.details
    # `valid` keeps its pre-existing aggregate semantics, but the required
    # layer set for the venice shape stays uncovered (gpu_attested None).
    from verifiers.common import has_required_check_coverage
    assert has_required_check_coverage(report.scorecard.as_dict(), "venice") is False
