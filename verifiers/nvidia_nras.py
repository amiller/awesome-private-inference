"""NVIDIA NRAS GPU attestation appraisal.

Chutes evidence responses carry per-GPU attestation *evidence blobs*
(``{arch, certificate, evidence}``), not JWTs. The blobs are submitted to
NVIDIA's public NRAS ``v3/attest/gpu`` endpoint as
``{"nonce": <hex>, "arch": <arch>, "evidence_list": [...]}``; NRAS answers
``[["JWT", platform_jwt], {"GPU-i": per_gpu_jwt, ...}]``. A verdict read out
of an unverified JWT is not evidence, so every returned token must verify
against NVIDIA's published JWKS before its claims count.

CPU↔GPU association (established from the 2026-11-05 keyed capture, confirmed
by NRAS itself): the evidence blob embeds a 32-byte nonce at bytes [4:36]
which is exactly the TDX quote's ``report_data[0:32]`` — i.e.
SHA256(url_nonce || e2e_pubkey), hardware-bound by the TD. Submitting any
other nonce makes NRAS reject with NONCE_NOT_MATCHING. So the chain is:
our fresh url nonce → TD report_data[0:32] → GPU evidence blob nonce →
NRAS eat_nonce echoed in every platform/per-GPU JWT.

Policy (recorded; sources cited per rule):

  association Every gpu_evidence item's embedded nonce must equal the TD
              quote's report_data[0:32]. An item minted for any other TD
              does not count.
  signature   Each returned JWT header `kid` must select a key from the JWKS
              published at DEFAULT_JWKS_URL. That key must carry an x5c chain
              whose leaf signature verifies under the intermediate above it,
              and the intermediate's SPKI digest must be one of the pinned
              NVIDIA intermediates below (captured 2026-11-05 from the same
              endpoint). The JWS signature must verify under the leaf key
              with the header alg matching the key type. No x5c, unknown
              intermediate, alg/key mismatch or bad signature rejects the
              token.
  platform    The platform JWT must carry `x-nvidia-overall-att-result`
              boolean true or the string "PASS" (NRAS v3 returns boolean
              true/false; NEAR's production verifier accepts "PASS" — both
              accepted, both cited) and `eat_nonce` equal to the expected
              nonce.
  per-GPU     Each per-GPU JWT must verify, carry the same `eat_nonce`, and
              `x-nvidia-gpu-attestation-report-nonce-match` true (the GPU
              report's own nonce match, distinct from eat_nonce).
  count       The per-GPU tokens (distinct `ueid`) must number exactly the
              matched configuration row's `gpu_count`.

Claims reference: docs.nvidia.com/attestation GPU Claims Guide (v3.0 claims
table; EAT nonce claim). JWKS endpoint and certificate subjects are
NVIDIA-published; the pinned fixtures with capture time and URL are
tests/fixtures/nras_jwks.json and tests/fixtures/nras_attest_response.json.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import requests

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

ATTEST_URL = "https://nras.attestation.nvidia.com/v3/attest/gpu"
DEFAULT_JWKS_URL = "https://nras.attestation.nvidia.com/.well-known/jwks.json"
PINNED_JWKS_FIXTURE = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "nras_jwks.json"

# SPKI-SHA256 of the NVIDIA Attestation Service GPU intermediates ("…GPU
# Intermediate 004"/"005", issuer "NVIDIA Attestation Service CA 001"),
# captured 2026-11-05 from DEFAULT_JWKS_URL. Update only as a deliberate,
# recorded trust-root decision.
PINNED_INTERMEDIATE_SPKI_SHA256 = frozenset({
    "fd32837f954e2c45db073105166dfe6985ae0480bb113fba63b091a75affe896",
    "ba14d00377699189b6762c22c744a9dbdc62aa9396097ada7150426c6ff39afc",
})

_PASS_VERDICTS = (True, "PASS")

_ALG_FOR_KEY = {("EC", "P-256"): "ES256", ("EC", "P-384"): "ES384", ("RSA", None): "RS256"}


def fetch_jwks(url: str = DEFAULT_JWKS_URL, timeout: int = 20) -> Dict[str, Any]:
    """Fetch NVIDIA's published JWKS. Errors propagate; no cached fallback."""
    resp = requests.get(url, timeout=timeout, headers={"Accept": "application/json"})
    resp.raise_for_status()
    body = resp.json()
    if not isinstance(body.get("keys"), list) or not body["keys"]:
        raise ValueError(f"JWKS at {url} carries no keys")
    return body


def load_pinned_jwks(path: Path = PINNED_JWKS_FIXTURE) -> Dict[str, Any]:
    """The fixture-captured JWKS (tests and offline replay)."""
    fixture = json.loads(Path(path).read_text())
    return fixture["jwks"]


def _b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * ((4 - len(value) % 4) % 4))


def _spki_sha256(public_key) -> str:
    return hashlib.sha256(public_key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()


def _verify_cert_signature(child: x509.Certificate, issuer_key) -> None:
    if isinstance(issuer_key, ec.EllipticCurvePublicKey):
        issuer_key.verify(child.signature, child.tbs_certificate_bytes,
                          ec.ECDSA(child.signature_hash_algorithm))
    elif isinstance(issuer_key, rsa.RSAPublicKey):
        issuer_key.verify(child.signature, child.tbs_certificate_bytes,
                          padding.PKCS1v15(), child.signature_hash_algorithm)
    else:
        raise ValueError(f"unsupported issuer key type {type(issuer_key).__name__}")


def _validated_key(jwk: Dict[str, Any]) -> Tuple[Any, str]:
    """Return (public_key, alg) for a JWKS entry pinned to NVIDIA's PKI.

    The leaf certificate's signature is verified under the intermediate in the
    same x5c chain, and the intermediate's SPKI digest must be pinned. The
    JWK's raw coordinates are accepted only when they match the leaf cert's
    public key, so a bare key without an NVIDIA-issued chain never verifies.
    """
    chain_b64 = jwk.get("x5c")
    if not isinstance(chain_b64, list) or len(chain_b64) < 2:
        raise ValueError("jwk carries no x5c chain")
    certs = [x509.load_der_x509_certificate(base64.b64decode(c)) for c in chain_b64]
    leaf, intermediate = certs[0], certs[1]
    _verify_cert_signature(leaf, intermediate.public_key())
    if _spki_sha256(intermediate.public_key()) not in PINNED_INTERMEDIATE_SPKI_SHA256:
        raise ValueError("x5c intermediate is not a pinned NVIDIA intermediate")
    alg = _ALG_FOR_KEY.get((jwk.get("kty"), jwk.get("crv")))
    if alg is None:
        raise ValueError(f"unsupported jwk type {jwk.get('kty')}/{jwk.get('crv')}")
    if jwk.get("kty") == "EC":
        key = ec.EllipticCurvePublicNumbers(
            int.from_bytes(_b64url_decode(jwk["x"]), "big"),
            int.from_bytes(_b64url_decode(jwk["y"]), "big"),
            ec.SECP256R1() if jwk["crv"] == "P-256" else ec.SECP384R1(),
        ).public_key()
    else:
        key = rsa.RSAPublicNumbers(
            int.from_bytes(_b64url_decode(jwk["e"]), "big"),
            int.from_bytes(_b64url_decode(jwk["n"]), "big"),
        ).public_key()
    if _spki_sha256(key) != _spki_sha256(leaf.public_key()):
        raise ValueError("jwk coordinates do not match the x5c leaf certificate")
    return key, alg


def _verify_jws(key, alg: str, header_b64: str, payload_b64: str, signature: bytes) -> None:
    signing_input = f"{header_b64}.{payload_b64}".encode()
    if alg == "ES384":
        if len(signature) != 96:
            raise ValueError("ES384 signature is not 96 bytes")
        sig = encode_dss_signature(int.from_bytes(signature[:48], "big"),
                                   int.from_bytes(signature[48:], "big"))
        key.verify(sig, signing_input, ec.ECDSA(hashes.SHA384()))
    elif alg == "ES256":
        if len(signature) != 64:
            raise ValueError("ES256 signature is not 64 bytes")
        sig = encode_dss_signature(int.from_bytes(signature[:32], "big"),
                                   int.from_bytes(signature[32:], "big"))
        key.verify(sig, signing_input, ec.ECDSA(hashes.SHA256()))
    elif alg == "RS256":
        key.verify(signature, signing_input, padding.PKCS1v15(), hashes.SHA256())
    else:
        raise ValueError(f"unsupported alg {alg!r}")


def evidence_nonce(item: Any) -> Optional[str]:
    """The 32-byte nonce a GPU evidence blob embeds at bytes [4:36], as hex.

    Returns None when the item is not a dict with a decodable `evidence`
    blob of at least 36 bytes; the caller records the reason.
    """
    try:
        blob = base64.b64decode(item["evidence"])
    except (KeyError, TypeError, ValueError, binascii.Error):
        return None
    if len(blob) < 36:
        return None
    return blob[4:36].hex()


def attest_gpu_evidence(items: List[Dict[str, Any]], nonce: str,
                        timeout: int = 90) -> Any:
    """Submit GPU evidence blobs to NVIDIA's public NRAS attestation endpoint.

    The response is [[\"JWT\", platform_jwt], {\"GPU-i\": jwt, ...}]. Transport
    and HTTP errors propagate; no fallback.
    """
    arch = items[0].get("arch")
    evidence_list = [{k: item[k] for k in ("arch", "certificate", "evidence")}
                     for item in items]
    return attest_payload({"nonce": nonce, "arch": arch,
                           "evidence_list": evidence_list}, timeout=timeout)


def attest_payload(payload: Dict[str, Any], timeout: int = 90) -> Any:
    """Submit a provider-assembled NRAS request payload unchanged."""
    resp = requests.post(ATTEST_URL, json=payload, timeout=timeout)
    resp.raise_for_status()
    return resp.json()


def appraise_jwt(token: str, nonce: str, jwks: Dict[str, Any],
                 *, require_verdict: bool,
                 require_gpu_nonce_match: bool = False) -> Dict[str, Any]:
    """Appraise one NRAS JWT under the recorded signature/nonce policy.

    Returns a per-token record; `ok` is True only when signature and (for
    platform tokens) verdict, and (for per-GPU tokens) the GPU report nonce
    match all pass. Errors and mismatches are returned as reasons, never as a
    pass.
    """
    record: Dict[str, Any] = {"ok": False}
    if not isinstance(token, str) or token.count(".") != 2:
        record["reason"] = "not_a_jwt"
        return record
    header_b64, payload_b64, sig_b64 = token.split(".")
    record["jwt_sha256"] = hashlib.sha256(token.encode()).hexdigest()
    try:
        header = json.loads(_b64url_decode(header_b64))
        payload = json.loads(_b64url_decode(payload_b64))
        signature = _b64url_decode(sig_b64)
    except (ValueError, json.JSONDecodeError) as exc:
        record["reason"] = f"malformed_jwt: {type(exc).__name__}"
        return record
    kid, alg = header.get("kid"), header.get("alg")
    record["kid"] = kid
    key_entry = next((k for k in jwks.get("keys", []) if k.get("kid") == kid), None)
    if key_entry is None:
        record["reason"] = "unknown_kid_not_in_published_jwks"
        return record
    try:
        key, expected_alg = _validated_key(key_entry)
    except (ValueError, InvalidSignature) as exc:
        record["reason"] = f"jwk_chain_rejected: {exc}"
        return record
    if alg != expected_alg:
        record["reason"] = f"alg_key_mismatch: header {alg!r} vs key {expected_alg!r}"
        return record
    try:
        _verify_jws(key, alg, header_b64, payload_b64, signature)
    except (InvalidSignature, ValueError) as exc:
        record["reason"] = f"signature_invalid: {type(exc).__name__}"
        return record
    record["signature_verified"] = True
    record["iss"] = payload.get("iss")
    for field in ("ueid", "hwmodel", "x-nvidia-gpu-driver-version", "dbgstat"):
        if field in payload:
            record[field] = payload[field]
    if require_verdict:
        verdict = payload.get("x-nvidia-overall-att-result")
        record["verdict"] = verdict if isinstance(verdict, (bool, str)) else repr(verdict)
        if verdict not in _PASS_VERDICTS:
            record["reason"] = f"verdict_not_pass: {verdict!r}"
            return record
    eat_nonce = payload.get("eat_nonce")
    if not isinstance(eat_nonce, str) or eat_nonce != nonce:
        record["reason"] = f"eat_nonce_mismatch: {eat_nonce!r}"
        return record
    record["nonce_bound"] = True
    if require_gpu_nonce_match:
        if payload.get("x-nvidia-gpu-attestation-report-nonce-match") is not True:
            record["reason"] = "gpu_attestation_report_nonce_match_not_true"
            return record
    record["ok"] = True
    return record


def _parse_attest_response(body: Any) -> Tuple[Optional[str], Dict[str, str]]:
    """Split the NRAS response into (platform_jwt, {gpu_label: jwt})."""
    platform = None
    per_gpu: Dict[str, str] = {}
    if isinstance(body, list):
        for entry in body:
            if isinstance(entry, list) and len(entry) == 2 and entry[0] == "JWT":
                platform = entry[1]
            elif isinstance(entry, dict):
                per_gpu.update({str(k): v for k, v in entry.items()
                                if isinstance(v, str)})
    return platform, per_gpu


def appraise_gpu_attestation(items: Any, expected_nonce: str, jwks: Dict[str, Any],
                             gpu_count: Optional[int],
                             attest_response: Optional[Any] = None,
                             timeout: int = 90,
                             allow_unknown_count: bool = False) -> Dict[str, Any]:
    """Appraise a provider's gpu_evidence under the recorded policy.

    `gpu_attested` is True only when every item's embedded nonce equals the
    TD-bound expected_nonce, the NRAS platform JWT verifies with verdict
    pass and the same eat_nonce, every per-GPU JWT verifies with the same
    eat_nonce and its GPU report nonce match true, and the distinct per-GPU
    tokens number exactly the submitted evidence items and `gpu_count`.
    With allow_unknown_count (providers with no published GPU-count
    configuration, e.g. Venice) a missing `gpu_count` records the observed
    count instead of failing; the items/tokens consistency still applies.
    Absent evidence yields None with a reason — never a pass. Transport
    errors propagate to the caller (the layer is unverified, not passed).
    """
    if items is None or items == []:
        return {"gpu_attested": None, "reason": "no_gpu_evidence_in_response"}
    if not isinstance(items, list):
        return {"gpu_attested": None,
                "reason": f"gpu_evidence_not_a_list: {type(items).__name__}"}
    bad_items = [i for i, item in enumerate(items)
                 if evidence_nonce(item) != expected_nonce]
    if bad_items:
        return {"gpu_attested": False, "tokens": [],
                "reason": ("gpu_evidence_nonce_not_bound_to_td_report_data: "
                           + ",".join(f"item[{i}]" for i in bad_items))}
    if attest_response is None:
        attest_response = attest_gpu_evidence(items, expected_nonce, timeout=timeout)
    platform_jwt, per_gpu = _parse_attest_response(attest_response)
    result: Dict[str, Any] = {"gpu_attested": False,
                              "platform": None, "gpus": None}
    if platform_jwt is None or not per_gpu:
        result["reason"] = "nras_response_missing_platform_or_gpu_tokens"
        return result
    platform = appraise_jwt(platform_jwt, expected_nonce, jwks, require_verdict=True)
    result["platform"] = platform
    gpu_records = {label: appraise_jwt(token, expected_nonce, jwks,
                                       require_verdict=False,
                                       require_gpu_nonce_match=True)
                   for label, token in per_gpu.items()}
    result["gpus"] = gpu_records
    bad = [f"{name}: {record.get('reason')}"
           for name, record in [("platform", platform), *gpu_records.items()]
           if not record["ok"]]
    if bad:
        result["reason"] = "; ".join(bad)
        return result
    ueids = [r["ueid"] for r in gpu_records.values() if "ueid" in r]
    if len(set(ueids)) != len(per_gpu):
        result["reason"] = "per_gpu_tokens_not_distinct_by_ueid"
        return result
    if len(per_gpu) != len(items):
        result["reason"] = (f"evidence_item_count_mismatch: {len(per_gpu)} verified "
                            f"per-GPU tokens vs {len(items)} evidence items")
        return result
    if gpu_count is None:
        if not allow_unknown_count:
            result["reason"] = "no_matched_configuration_row_gpu_count"
            return result
    elif len(per_gpu) != gpu_count:
        result["reason"] = (f"gpu_count_mismatch: {len(per_gpu)} verified per-GPU "
                            f"tokens vs gpu_count {gpu_count}")
        return result
    result["gpu_attested"] = True
    result["verified_gpu_count"] = len(per_gpu)
    return result


def decode_payload(token: str) -> Dict[str, Any]:
    """Decoded (unverified) payload — for retaining claim details in evidence."""
    return json.loads(_b64url_decode(token.split(".")[1]))
