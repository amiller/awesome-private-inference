"""The sampled Chutes instance remains identifiable and replayable offline."""
import base64
import hashlib

from verifiers import chutes


def _run(monkeypatch, *, change_report_data=False, quote_valid=True, truncate_quote=False):
    nonce = "01" * 32
    pubkey = "public-key"
    cert_hash = bytes.fromhex("bb" * 32)
    key_hash = hashlib.sha256((nonce + pubkey).encode()).digest()
    body = bytearray(584)
    body[136:184] = bytes.fromhex("aa" * 48)
    body[520:584] = (bytes(32) if change_report_data else key_hash) + cert_hash
    quote = base64.b64encode(bytes(48) + body).decode()
    if truncate_quote:
        quote = base64.b64encode(b"short").decode()
    golden = [{"mrtd": "aa" * 48, "name": "sample", "version": "1"}]
    instance = {"instance_id": "instance-1", "e2e_pubkey": pubkey}
    evidence = {"quote": quote, "certificate": "public-certificate", "gpu_evidence": []}
    responses = [golden, {"instances": [instance]}, evidence]

    class Response:
        status_code = 200
        def __init__(self, value):
            self.value = value
        def json(self):
            return self.value

    seen = []
    def get(url, *, headers, timeout):
        seen.append(url)
        assert headers["Authorization"] == "Bearer test-token"
        return Response(responses.pop(0))

    monkeypatch.setattr(chutes.requests, "get", get)
    monkeypatch.setattr(chutes.secrets, "token_hex", lambda n: nonce)
    monkeypatch.setattr(chutes, "_cert_spki_sha256", lambda value: cert_hash.hex())
    monkeypatch.setattr(chutes, "load_audit_ledger", lambda *a: ({"aa" * 48}, {}))
    monkeypatch.setattr(chutes.phala_tdx, "verify_tdx_quote", lambda value: {"quote": {"verified": True}})
    monkeypatch.setattr(chutes.phala_tdx, "is_verified", lambda value: quote_valid)
    monkeypatch.setattr(chutes.phala_tdx, "quote_body", lambda value: {"reportdata": "mock"})
    report = chutes.verify("test-token", "https://api.chutes.ai", "Qwen3-32B-TEE")
    assert len(seen) == 3
    return report


def test_sampled_instance_and_quote_are_retained(monkeypatch):
    report = _run(monkeypatch)
    raw = report.details["raw_evidence"]
    assert report.signing_address == raw["instance_id"] == "instance-1"
    assert raw["quote_b64"]
    assert raw["golden_measurements"][0]["mrtd"] == "aa" * 48
    assert raw["golden_set_sha256"] == report.details["golden_set_sha256"]
    assert "test-token" not in str(raw)
    assert report.details["verification_status"] == "not_checked"


def test_rejected_chutes_binding_keeps_raw_evidence(monkeypatch):
    report = _run(monkeypatch, change_report_data=True)
    assert report.details["verification_status"] == "rejected"
    assert report.scorecard.report_data_binds_key is False
    assert report.details["raw_evidence"]["quote_b64"]


def test_rejected_quote_cannot_make_key_binding_pass(monkeypatch):
    report = _run(monkeypatch, quote_valid=False)
    assert report.scorecard.tdx_verified is False
    assert report.scorecard.report_data_binds_key is False
    assert report.scorecard.nonce_bound is False
    assert report.details["verification_status"] == "rejected"


def test_malformed_quote_is_rejected_with_raw_capture(monkeypatch):
    report = _run(monkeypatch, truncate_quote=True)
    assert report.details["verification_status"] == "rejected"
    assert report.details["raw_evidence"]["quote_b64"]
