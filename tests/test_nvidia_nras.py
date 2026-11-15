"""NRAS GPU-evidence appraisal: signature verification against NVIDIA's
published JWKS, nonce binding, CPU↔GPU association and GPU-count policy.

Real-evidence paths replay the owner's keyed Chutes capture
(tests/fixtures/chutes_capture_sample.json) and the live NRAS response it
produced (tests/fixtures/nras_attest_response.json, captured 2026-11-05)
against the production JWKS captured with it (tests/fixtures/nras_jwks.json),
with the clock pinned to the capture time. Signature negatives use locally generated EC P-384 keys whose x5c
chain pins to a test intermediate (the pinned SPKI set is swapped for the
test key's) so every rejection path is exercised without touching NVIDIA.
"""
import base64
import datetime
import json
import time
from pathlib import Path

import cryptography.hazmat.primitives.hashes as chashes
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import NameOID

from tests.nras_capture import JWKS, pin_clock
from verifiers import nvidia_nras

FIXTURES = Path(__file__).resolve().parent / "fixtures"
NONCE = "ab" * 32
GPU_COUNT = 8


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _make_chain():
    inter_key = ec.generate_private_key(ec.SECP384R1())
    leaf_key = ec.generate_private_key(ec.SECP384R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    inter = (x509.CertificateBuilder()
             .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test intermediate")]))
             .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test intermediate")]))
             .public_key(inter_key.public_key()).serial_number(x509.random_serial_number())
             .not_valid_before(now - datetime.timedelta(days=1))
             .not_valid_after(now + datetime.timedelta(days=1))
             .sign(inter_key, chashes.SHA384()))
    leaf = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test gpu leaf")]))
            .issuer_name(inter.subject)
            .public_key(leaf_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=1))
            .sign(inter_key, chashes.SHA384()))
    der = lambda cert: base64.b64encode(
        cert.public_bytes(serialization.Encoding.DER)).decode()
    import hashlib
    spki_sha = lambda cert: hashlib.sha256(cert.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()
    jwk = {
        "kty": "EC", "crv": "P-384", "kid": "test-kid",
        "x": _b64url(leaf_key.public_key().public_numbers().x.to_bytes(48, "big")),
        "y": _b64url(leaf_key.public_key().public_numbers().y.to_bytes(48, "big")),
        "x5c": [der(leaf), der(inter)],
    }
    return leaf_key, jwk, spki_sha(inter)


def _sign_token(leaf_key, payload: dict, kid="test-kid", alg="ES384") -> str:
    header = {"alg": alg, "kid": kid, "typ": "JWT"}
    header_b64 = _b64url(json.dumps(header).encode())
    payload_b64 = _b64url(json.dumps(payload).encode())
    signature = leaf_key.sign(f"{header_b64}.{payload_b64}".encode(),
                              ec.ECDSA(chashes.SHA384()))
    r, s = decode_dss_signature(signature)
    raw_sig = r.to_bytes(48, "big") + s.to_bytes(48, "big")
    return f"{header_b64}.{payload_b64}.{_b64url(raw_sig)}"


def _platform_payload(**overrides):
    payload = {
        "iss": "https://nras.attestation.nvidia.com",
        "sub": "NVIDIA-PLATFORM-ATTESTATION",
        "x-nvidia-ver": "2.0",
        "x-nvidia-overall-att-result": True,
        "eat_nonce": NONCE,
        "exp": int(time.time()) + 3600,
    }
    payload.update(overrides)
    return {k: v for k, v in payload.items() if v is not None}


def _gpu_payload(index, **overrides):
    payload = {
        "iss": "https://nras.attestation.nvidia.com",
        "eat_nonce": NONCE,
        "ueid": f"4905667398584198354845679187983555546298498662{index:02d}",
        "hwmodel": "GH100",
        "dbgstat": "disabled",
        "x-nvidia-gpu-driver-version": "595.71.05",
        "x-nvidia-gpu-attestation-report-nonce-match": True,
        "exp": int(time.time()) + 3600,
    }
    payload.update(overrides)
    return {k: v for k, v in payload.items() if v is not None}


def _evidence_item(nonce_hex=NONCE):
    blob = bytearray(64)
    blob[0:4] = b"\x11\xe0\x01\xff"
    blob[4:36] = bytes.fromhex(nonce_hex)
    return {"arch": "HOPPER", "certificate": "dGVzdA==",
            "evidence": base64.b64encode(bytes(blob)).decode()}


def _attest_response(leaf_key, gpus=GPU_COUNT, platform_overrides=None,
                     gpu_overrides=None):
    platform = _sign_token(
        leaf_key, _platform_payload(**(platform_overrides or {})))
    per_gpu = {f"GPU-{i}": _sign_token(leaf_key, _gpu_payload(i, **(gpu_overrides or {})))
               for i in range(gpus)}
    return [["JWT", platform], per_gpu]


@pytest.fixture()
def pinned_jwks(monkeypatch):
    leaf_key, jwk, inter_spki = _make_chain()
    monkeypatch.setattr(nvidia_nras, "PINNED_INTERMEDIATE_SPKI_SHA256", frozenset({inter_spki}))
    return leaf_key, {"keys": [jwk]}


# ---------------------------------------------------------------- pass path

def test_full_policy_pass(pinned_jwks):
    leaf_key, jwks = pinned_jwks
    items = [_evidence_item() for _ in range(GPU_COUNT)]
    result = nvidia_nras.appraise_gpu_attestation(
        items, NONCE, jwks, GPU_COUNT,
        attest_response=_attest_response(leaf_key))
    assert result["gpu_attested"] is True
    assert result["verified_gpu_count"] == GPU_COUNT
    assert result["platform"]["signature_verified"] and result["platform"]["nonce_bound"]


def test_real_captured_evidence_and_live_nras_response_pass(monkeypatch):
    """GLM-5.1-TEE instance c4dcc862: the owner's keyed capture, the live NRAS
    response it produced, and NVIDIA's pinned production JWKS — no mocks."""
    capture = json.loads((FIXTURES / "chutes_capture_sample.json").read_text())
    nras = json.loads((FIXTURES / "nras_attest_response.json").read_text())
    pin_clock(monkeypatch, nras["captured_utc"])
    entry = nras["responses"]["GLM-5.1-TEE"]
    quote = capture["models"]["GLM-5.1-TEE"]["evidence"]["quote"]
    report_data = base64.b64decode(quote)[48:][520:584]
    expected = report_data[:32].hex()
    assert entry["submitted_nonce"] == expected  # blob nonce == report_data[0:32]
    result = nvidia_nras.appraise_gpu_attestation(
        capture["models"]["GLM-5.1-TEE"]["evidence"]["gpu_evidence"],
        expected, JWKS, 8,
        attest_response=entry["response"])
    assert result["gpu_attested"] is True
    assert result["verified_gpu_count"] == 8


def test_real_gemma_evidence_records_count_mismatch(monkeypatch):
    """Real finding pinned as a regression test: every gemma-4-31B-TEE
    instance returns 1 GPU token while its matched published row
    (8xpro_6000) declares gpu_count 8 — the published GPU set is not
    covered, so this must reject, not pass."""
    capture = json.loads((FIXTURES / "chutes_capture_sample.json").read_text())
    nras = json.loads((FIXTURES / "nras_attest_response.json").read_text())
    pin_clock(monkeypatch, nras["captured_utc"])
    entry = nras["responses"]["gemma-4-31B-TEE"]
    quote = capture["models"]["gemma-4-31B-TEE"]["evidence"]["quote"]
    expected = base64.b64decode(quote)[48:][520:584][:32].hex()
    result = nvidia_nras.appraise_gpu_attestation(
        capture["models"]["gemma-4-31B-TEE"]["evidence"]["gpu_evidence"],
        expected, JWKS, 8,
        attest_response=entry["response"])
    assert result["gpu_attested"] is False
    assert "gpu_count_mismatch" in result["reason"]


# ------------------------------------------------- association (CPU↔GPU)

def test_evidence_item_bound_to_other_td_rejects(pinned_jwks):
    leaf_key, jwks = pinned_jwks
    items = [_evidence_item()] + [_evidence_item("ff" * 32)]
    result = nvidia_nras.appraise_gpu_attestation(
        items, NONCE, jwks, GPU_COUNT, attest_response=_attest_response(leaf_key))
    assert result["gpu_attested"] is False
    assert result["reason"].startswith("gpu_evidence_nonce_not_bound_to_td_report_data")
    assert "item[1]" in result["reason"]


def test_short_or_undecodable_evidence_blob_is_not_bound(pinned_jwks):
    leaf_key, jwks = pinned_jwks
    items = [_evidence_item(), {"arch": "HOPPER", "certificate": "x", "evidence": "AAAA"}]
    result = nvidia_nras.appraise_gpu_attestation(
        items, NONCE, jwks, GPU_COUNT, attest_response=_attest_response(leaf_key))
    assert result["gpu_attested"] is False
    assert result["reason"].startswith("gpu_evidence_nonce_not_bound_to_td_report_data")


# ------------------------------------------------------- signature negatives

def _tamper(token: str, mutate) -> str:
    header_b64, payload_b64, sig_b64 = token.split(".")
    payload = json.loads(nvidia_nras._b64url_decode(payload_b64))
    mutate(payload)
    forged = f"{header_b64}.{_b64url(json.dumps(payload).encode())}.{sig_b64}"
    return forged


def test_tampered_platform_payload_fails_signature(pinned_jwks):
    leaf_key, jwks = pinned_jwks
    response = _attest_response(leaf_key)
    response[0][1] = _tamper(response[0][1],
                             lambda p: p.update({"x-nvidia-overall-att-result": True,
                                                 "eat_nonce": "00" * 32}))
    items = [_evidence_item() for _ in range(GPU_COUNT)]
    result = nvidia_nras.appraise_gpu_attestation(
        items, NONCE, jwks, GPU_COUNT, attest_response=response)
    assert result["gpu_attested"] is False
    assert result["platform"]["reason"].startswith("signature_invalid")


def test_tampered_per_gpu_payload_fails_signature(pinned_jwks):
    leaf_key, jwks = pinned_jwks
    response = _attest_response(leaf_key)

    def flip(p):
        p["eat_nonce"] = "00" * 32
        p["x-nvidia-gpu-attestation-report-nonce-match"] = True
    response[1]["GPU-3"] = _tamper(response[1]["GPU-3"], flip)
    items = [_evidence_item() for _ in range(GPU_COUNT)]
    result = nvidia_nras.appraise_gpu_attestation(
        items, NONCE, jwks, GPU_COUNT, attest_response=response)
    assert result["gpu_attested"] is False
    assert result["gpus"]["GPU-3"]["reason"].startswith("signature_invalid")


def test_unknown_kid_rejected_against_pinned_production_jwks(pinned_jwks):
    leaf_key, _ = pinned_jwks
    token = _sign_token(leaf_key, _platform_payload())
    record = nvidia_nras.appraise_jwt(token, NONCE, JWKS, require_verdict=True)
    assert record["ok"] is False
    assert record["reason"] == "unknown_kid_not_in_published_jwks"


def test_production_jwks_fixture_pins_nvidia_intermediates(monkeypatch):
    pin_clock(monkeypatch, "2026-11-05T20:32:04+00:00")
    assert JWKS["keys"]
    for jwk in JWKS["keys"]:
        nvidia_nras._validated_key(jwk)  # raises unless the chain pins


def test_captured_leaf_outside_validity_window_rejects(monkeypatch):
    for iso in ("2026-11-05T18:00:00+00:00", "2026-11-06T08:00:00+00:00"):
        pin_clock(monkeypatch, iso)
        with pytest.raises(ValueError, match="validity window"):
            nvidia_nras._validated_key(JWKS["keys"][0])


def test_wrong_issuer_rejects(pinned_jwks):
    leaf_key, jwks = pinned_jwks
    token = _sign_token(leaf_key, _platform_payload(iss="https://evil.example"))
    record = nvidia_nras.appraise_jwt(token, NONCE, jwks, require_verdict=True)
    assert record["reason"] == "iss_mismatch: 'https://evil.example'"


def test_expired_or_missing_exp_rejects(pinned_jwks):
    leaf_key, jwks = pinned_jwks
    for exp in (int(time.time()) - 1, None, "9999999999"):
        token = _sign_token(leaf_key, _platform_payload(exp=exp))
        record = nvidia_nras.appraise_jwt(token, NONCE, jwks, require_verdict=True)
        assert record["reason"].startswith("expired_or_missing_exp"), exp


def test_alg_mismatch_rejects(pinned_jwks):
    leaf_key, jwks = pinned_jwks
    token = _sign_token(leaf_key, _platform_payload(), alg="ES256")
    record = nvidia_nras.appraise_jwt(token, NONCE, jwks, require_verdict=True)
    assert record["reason"].startswith("alg_key_mismatch")


def test_bare_jwk_without_x5c_rejects(pinned_jwks):
    leaf_key, jwks = pinned_jwks
    bare = {k: v for k, v in jwks["keys"][0].items() if k != "x5c"}
    record = nvidia_nras.appraise_jwt(
        _sign_token(leaf_key, _platform_payload()), NONCE, {"keys": [bare]},
        require_verdict=True)
    assert record["reason"].startswith("jwk_chain_rejected")


def test_unpinned_intermediate_rejects(pinned_jwks):
    leaf_key, jwks = pinned_jwks
    other_key, other_jwk, _ = _make_chain()
    record = nvidia_nras.appraise_jwt(
        _sign_token(leaf_key, _platform_payload()), NONCE, {"keys": [other_jwk]},
        require_verdict=True)
    assert record["reason"].startswith("jwk_chain_rejected")


def test_jwk_coordinates_not_matching_leaf_reject(pinned_jwks):
    leaf_key, jwks = pinned_jwks
    stranger = ec.generate_private_key(ec.SECP384R1())
    forged = dict(jwks["keys"][0])
    forged["x"] = _b64url(stranger.public_key().public_numbers().x.to_bytes(48, "big"))
    forged["y"] = _b64url(stranger.public_key().public_numbers().y.to_bytes(48, "big"))
    record = nvidia_nras.appraise_jwt(
        _sign_token(leaf_key, _platform_payload()), NONCE, {"keys": [forged]},
        require_verdict=True)
    assert record["reason"].startswith("jwk_chain_rejected")


# --------------------------------------------------- verdict/nonce negatives

def test_platform_verdict_failure_rejects(pinned_jwks):
    leaf_key, jwks = pinned_jwks
    for bad in (False, "FAIL", "false", None):
        response = _attest_response(
            leaf_key, platform_overrides={"x-nvidia-overall-att-result": bad})
        result = nvidia_nras.appraise_gpu_attestation(
            [_evidence_item() for _ in range(GPU_COUNT)], NONCE, jwks, GPU_COUNT,
            attest_response=response)
        assert result["gpu_attested"] is False, bad
        assert result["platform"]["reason"].startswith("verdict_not_pass"), bad


def test_platform_wrong_or_missing_nonce_rejects(pinned_jwks):
    leaf_key, jwks = pinned_jwks
    for bad in ("00" * 32, None):
        response = _attest_response(leaf_key, platform_overrides={"eat_nonce": bad})
        result = nvidia_nras.appraise_gpu_attestation(
            [_evidence_item() for _ in range(GPU_COUNT)], NONCE, jwks, GPU_COUNT,
            attest_response=response)
        assert result["platform"]["reason"].startswith("eat_nonce_mismatch"), bad


def test_per_gpu_wrong_nonce_rejects(pinned_jwks):
    leaf_key, jwks = pinned_jwks
    response = _attest_response(leaf_key)
    response[1]["GPU-5"] = _sign_token(leaf_key, _gpu_payload(5, eat_nonce="00" * 32))
    result = nvidia_nras.appraise_gpu_attestation(
        [_evidence_item() for _ in range(GPU_COUNT)], NONCE, jwks, GPU_COUNT,
        attest_response=response)
    assert result["gpus"]["GPU-5"]["reason"].startswith("eat_nonce_mismatch")


def test_gpu_attestation_report_nonce_match_false_rejects(pinned_jwks):
    leaf_key, jwks = pinned_jwks
    response = _attest_response(
        leaf_key, gpu_overrides={"x-nvidia-gpu-attestation-report-nonce-match": False})
    result = nvidia_nras.appraise_gpu_attestation(
        [_evidence_item() for _ in range(GPU_COUNT)], NONCE, jwks, GPU_COUNT,
        attest_response=response)
    assert result["gpu_attested"] is False
    assert all(r["reason"] == "gpu_attestation_report_nonce_match_not_true"
               for r in result["gpus"].values())


# ------------------------------------------------------------- count policy

def test_per_gpu_count_mismatch_rejects(pinned_jwks):
    leaf_key, jwks = pinned_jwks
    for gpus, expected_gpu_count in ((GPU_COUNT, GPU_COUNT + 1), (GPU_COUNT - 1, GPU_COUNT)):
        items = [_evidence_item() for _ in range(gpus)]
        result = nvidia_nras.appraise_gpu_attestation(
            items, NONCE, jwks, expected_gpu_count,
            attest_response=_attest_response(leaf_key, gpus=gpus))
        assert result["gpu_attested"] is False, gpus
        assert "gpu_count_mismatch" in result["reason"], gpus


def test_evidence_item_count_mismatch_rejects(pinned_jwks):
    """Fewer verified per-GPU tokens than submitted evidence items — one GPU
    never came back attested — must reject."""
    leaf_key, jwks = pinned_jwks
    items = [_evidence_item() for _ in range(GPU_COUNT)]
    result = nvidia_nras.appraise_gpu_attestation(
        items, NONCE, jwks, GPU_COUNT - 1,
        attest_response=_attest_response(leaf_key, gpus=GPU_COUNT - 1))
    assert result["gpu_attested"] is False
    assert "evidence_item_count_mismatch" in result["reason"]


def test_allow_unknown_count_records_observed_count(pinned_jwks):
    """Venice semantics: no published gpu_count exists, so the observed count
    is recorded and the pass rests on signature + nonce + self-consistency."""
    leaf_key, jwks = pinned_jwks
    items = [_evidence_item() for _ in range(GPU_COUNT)]
    result = nvidia_nras.appraise_gpu_attestation(
        items, NONCE, jwks, None,
        attest_response=_attest_response(leaf_key), allow_unknown_count=True)
    assert result["gpu_attested"] is True
    assert result["verified_gpu_count"] == GPU_COUNT


def test_duplicate_ueid_does_not_pad_the_count(pinned_jwks):
    leaf_key, jwks = pinned_jwks
    response = _attest_response(leaf_key)
    victim = response[1]["GPU-1"]
    response[1]["GPU-1"] = response[1]["GPU-0"]
    result = nvidia_nras.appraise_gpu_attestation(
        [_evidence_item() for _ in range(GPU_COUNT)], NONCE, jwks, GPU_COUNT,
        attest_response=response)
    assert result["gpu_attested"] is False
    assert result["reason"] == "per_gpu_tokens_not_distinct_by_ueid"


def test_no_gpu_count_never_passes(pinned_jwks):
    leaf_key, jwks = pinned_jwks
    result = nvidia_nras.appraise_gpu_attestation(
        [_evidence_item() for _ in range(GPU_COUNT)], NONCE, jwks, None,
        attest_response=_attest_response(leaf_key))
    assert result["gpu_attested"] is False
    assert result["reason"] == "no_matched_configuration_row_gpu_count"


def test_response_without_platform_or_gpu_tokens_rejects(pinned_jwks):
    leaf_key, jwks = pinned_jwks
    platform = _sign_token(leaf_key, _platform_payload())
    for response in ([["JWT", platform]], [[]], ["junk"]):
        result = nvidia_nras.appraise_gpu_attestation(
            [_evidence_item()], NONCE, jwks, 1, attest_response=response)
        assert result["gpu_attested"] is False
        assert result["reason"] == "nras_response_missing_platform_or_gpu_tokens"


def test_absent_gpu_evidence_is_not_a_pass(pinned_jwks):
    _, jwks = pinned_jwks
    for empty in (None, []):
        result = nvidia_nras.appraise_gpu_attestation(empty, NONCE, jwks, 8)
        assert result["gpu_attested"] is None
        assert result["reason"] == "no_gpu_evidence_in_response"
