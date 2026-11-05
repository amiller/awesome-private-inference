"""AMD vendor-chain negative controls for the Tinfoil verifier.

Every check that can pass is proven to reject tampered input, each mutation
applied independently to real retained evidence:

  - tinfoil_atc_bundle.json      router.inf6.tinfoil.sh, report v3 + VCEK
  - tinfoil_router0_v5_bundle.json  router-0.tinfoil.sh, report v5 + VCEK
  - amd_kds_{genoa,milan}_cert_chain.pem  AMD KDS ARK/ASK chains (wrong-product
    control); both proven genuine by verifying ARK self-signature and
    ARK->ASK internally before use as negative-control anchors.

No mocks except the live-TLS transport stub where the full pipeline is run.
"""
from __future__ import annotations

import base64
import gzip
import json
from dataclasses import replace
from pathlib import Path
from unittest import mock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from verifiers import tinfoil, tinfoil_amd, tinfoil_sev

FIXTURES = Path(__file__).parent / "fixtures"
V3 = json.loads((FIXTURES / "tinfoil_atc_bundle.json").read_text())
V5 = json.loads((FIXTURES / "tinfoil_router0_v5_bundle.json").read_text())


def _bundle(raw):
    return tinfoil._Bundle.from_json(raw)


def _offline_tls(bundle):
    expected = bundle.sev_report().report_data[:32].hex()
    return mock.patch.object(tinfoil, "_live_tls_spki_sha256", lambda host, **kw: expected)


def _load_chain(name):
    return x509.load_pem_x509_certificates((FIXTURES / name).read_bytes())


def _milan_anchors():
    ask, ark = _load_chain("amd_kds_milan_cert_chain.pem")
    return {"ark": ark, "ask": ask}


# ---------------------------------------------------------------- positives


@pytest.mark.parametrize("raw", [V3, V5], ids=["router.inf6-v3", "router-0-v5"])
def test_hardware_chain_and_report_signature_verify(raw):
    bundle = _bundle(raw)
    report = bundle.sev_report()
    vcek_der = base64.b64decode(bundle.vcek_b64)
    check = tinfoil_amd.verify_vcek_chain(vcek_der, report)
    assert check.product_name == "Genoa"
    assert check.hwid_hex == report.chip_id.hex()
    tinfoil_amd.verify_report_signature(report, vcek_der)


def test_v5_bundle_full_pipeline_hardware_verified():
    bundle = _bundle(V5)
    with _offline_tls(bundle):
        report = tinfoil.verify_bundle(
            bundle, model="router", repo="tinfoilsh/confidential-model-router"
        )
    assert report.scorecard.hardware_signature_verified is True
    assert report.scorecard.measurement_matches_release is True
    assert report.details["hardware_signature_verification"]["status"] == "verified"
    assert report.details["sev"]["version"] == 5
    sev = report.details["sev"]
    hw = report.details["hardware_signature_verification"]
    # #18: reported_tcb/current_tcb retained in row details, and the retained
    # value agrees with the VCEK-bound SPLs (not a detached self-claim)
    assert sev["reported_tcb_parts"] == hw["spl"]
    assert len(sev["current_tcb"]) == 16
    assert not report.valid  # encrypted request binding still not performed


def test_milan_chain_fixture_is_genuine():
    """The wrong-product control anchors are a real AMD publication: the chain
    verifies internally (ARK self-signature, ARK->ASK) before we use it to
    attack the Genoa path."""
    ask, ark = _load_chain("amd_kds_milan_cert_chain.pem")
    tinfoil_amd._verify_signed_by(ark, ark, "ARK-Milan")
    tinfoil_amd._verify_signed_by(ask, ark, "ASK-Milan")


# ------------------------------------------- report tampering (each field)


def _tampered_bundle(raw, offset, mask=0xFF):
    inner = bytearray(gzip.decompress(
        base64.b64decode(raw["enclaveAttestationReport"]["body"])))
    inner[offset] ^= mask
    doc = dict(raw["enclaveAttestationReport"])
    doc["body"] = base64.b64encode(gzip.compress(bytes(inner), mtime=0)).decode()
    return tinfoil._Bundle.from_json({**raw, "enclaveAttestationReport": doc})


@pytest.mark.parametrize(
    "offset",
    [0x08, 0x50, 0x90, 0x180, 0x1A0],
    ids=["policy", "report_data", "measurement", "reported_tcb", "chip_id"],
)
def test_flipped_report_byte_in_signed_area_rejected(offset):
    for raw in (V3, V5):
        bundle = _tampered_bundle(raw, offset)
        vcek_der = base64.b64decode(bundle.vcek_b64)
        with pytest.raises(ValueError, match="signature"):
            tinfoil_amd.verify_report_signature(bundle.sev_report(), vcek_der)
        with _offline_tls(bundle):
            report = tinfoil.verify_bundle(bundle, model="router")
        assert not report.valid
        assert "AMD chain/report verification failed" in report.error
        assert report.details["hardware_signature_verification"].startswith("rejected")


@pytest.mark.parametrize("offset", [0x2A0, 0x2E8, 0x317])
def test_flipped_signature_byte_rejected(offset):
    for raw in (V3, V5):
        bundle = _tampered_bundle(raw, offset)
        vcek_der = base64.b64decode(bundle.vcek_b64)
        with pytest.raises(ValueError, match="signature"):
            tinfoil_amd.verify_report_signature(bundle.sev_report(), vcek_der)


def _tampered_report_body(raw, mutate):
    inner = bytearray(gzip.decompress(
        base64.b64decode(raw["enclaveAttestationReport"]["body"])))
    mutate(inner)
    doc = dict(raw["enclaveAttestationReport"])
    doc["body"] = base64.b64encode(gzip.compress(bytes(inner), mtime=0)).decode()
    return tinfoil._Bundle.from_json({**raw, "enclaveAttestationReport": doc})


def test_debug_bit_set_rejected_before_any_trust():
    def set_debug(body):
        policy = int.from_bytes(body[0x08:0x10], "little") | (1 << 19)
        body[0x08:0x10] = policy.to_bytes(8, "little")

    bundle = _tampered_report_body(V3, set_debug)
    assert bundle.sev_report().debug is True
    with _offline_tls(bundle):
        report = tinfoil.verify_bundle(bundle, model="router")
    assert not report.valid
    assert "DEBUG" in report.error
    assert report.scorecard.hardware_signature_verified is None


def test_debug_bit_parse_level():
    """Policy DEBUG bit parsed straight from a tampered byte stream."""
    raw = bytearray(gzip.decompress(
        base64.b64decode(V3["enclaveAttestationReport"]["body"])))
    assert tinfoil_sev.parse(bytes(raw)).debug is False
    raw[0x0A] |= 1 << 3  # bit 19 = byte 2, bit 3 of the LE policy
    assert tinfoil_sev.parse(bytes(raw)).debug is True


# ------------------------------------------------- wrong / tampered anchors


def test_milan_anchors_reject_genoa_vcek():
    """The real Milan chain (wrong product) must not authenticate a Genoa VCEK."""
    bundle = _bundle(V3)
    vcek_der = base64.b64decode(bundle.vcek_b64)
    with pytest.raises(ValueError):
        tinfoil_amd.verify_vcek_chain(vcek_der, bundle.sev_report(), anchors=_milan_anchors())


def test_wrong_ark_key_rejects_at_signature_layer():
    """An attacker-supplied ARK with the genuine ARK-Genoa identity but a fresh
    key passes its own self-signature and the name/validity checks; the
    ARK->ASK RSA-PSS signature must still fail."""
    genuine = tinfoil_amd.load_genoa_anchors()
    ark_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    fake_ark = (
        x509.CertificateBuilder()
        .subject_name(genuine["ark"].subject)
        .issuer_name(genuine["ark"].subject)
        .public_key(ark_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(genuine["ark"].not_valid_before_utc)
        .not_valid_after(genuine["ark"].not_valid_after_utc)
        .sign(
            ark_key,
            hashes.SHA256(),
            rsa_padding=padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH
            ),
        )
    )
    anchors = {"ark": fake_ark, "ask": genuine["ask"]}
    bundle = _bundle(V3)
    vcek_der = base64.b64decode(bundle.vcek_b64)
    tinfoil_amd._verify_signed_by(fake_ark, fake_ark, "fake ARK")  # self-consistent
    with pytest.raises(ValueError, match="ASK: signature"):
        tinfoil_amd.verify_vcek_chain(
            vcek_der, bundle.sev_report(), anchors=anchors
        )


def test_corrupted_ark_file_fails_closed(tmp_path, monkeypatch):
    from cryptography.hazmat.primitives.serialization import Encoding

    anchors = tinfoil_amd.load_genoa_anchors()
    provenance = (tinfoil_amd._CERTS_DIR / "amd_genoa_provenance.json").read_text()
    monkeypatch.setattr(tinfoil_amd, "_CERTS_DIR", tmp_path)
    for key, name in (("ark", "amd_genoa_ark.pem"), ("ask", "amd_genoa_ask.pem")):
        (tmp_path / name).write_bytes(anchors[key].public_bytes(Encoding.PEM))
    (tmp_path / "amd_genoa_provenance.json").write_text(provenance)
    tampered = bytearray(anchors["ark"].public_bytes(Encoding.PEM))
    tampered[-10] ^= 0x01
    (tmp_path / "amd_genoa_ark.pem").write_bytes(bytes(tampered))
    with pytest.raises(ValueError):  # PEM loader or fingerprint pin: either way closed
        tinfoil_amd.load_genoa_anchors()


def test_swapped_valid_anchor_rejected_by_pin(tmp_path, monkeypatch):
    """A different genuine AMD certificate in place of the pinned ARK parses
    fine; the DER fingerprint pin must reject it."""
    from cryptography.hazmat.primitives.serialization import Encoding

    anchors = tinfoil_amd.load_genoa_anchors()
    provenance = (tinfoil_amd._CERTS_DIR / "amd_genoa_provenance.json").read_text()
    monkeypatch.setattr(tinfoil_amd, "_CERTS_DIR", tmp_path)
    (tmp_path / "amd_genoa_ark.pem").write_bytes(
        anchors["ask"].public_bytes(Encoding.PEM))  # valid cert, wrong role
    (tmp_path / "amd_genoa_ask.pem").write_bytes(
        anchors["ask"].public_bytes(Encoding.PEM))
    (tmp_path / "amd_genoa_provenance.json").write_text(provenance)
    with pytest.raises(ValueError, match="fingerprint"):
        tinfoil_amd.load_genoa_anchors()


def test_substituted_ark_rejected(tmp_path, monkeypatch):
    """Milan's real ARK swapped in for the pinned Genoa ARK, with the provenance
    fingerprint re-pinned to match: the identity check must still reject."""
    from cryptography.hazmat.primitives.serialization import Encoding

    _, milan_ark = _load_chain("amd_kds_milan_cert_chain.pem")
    genoa = tinfoil_amd.load_genoa_anchors()
    monkeypatch.setattr(tinfoil_amd, "_CERTS_DIR", tmp_path)
    for name, cert in (("amd_genoa_ark.pem", milan_ark), ("amd_genoa_ask.pem", genoa["ask"])):
        (tmp_path / name).write_bytes(cert.public_bytes(Encoding.PEM))
    prov = {
        "ark_der_sha256": tinfoil_amd._der_fp(milan_ark),
        "ask_der_sha256": tinfoil_amd._der_fp(genoa["ask"]),
        "captured_from": "tampered", "captured_utc": "tampered", "cross_checked_against": "tampered",
    }
    (tmp_path / "amd_genoa_provenance.json").write_text(json.dumps(prov))
    tampered_anchors = tinfoil_amd.load_genoa_anchors()  # re-pinned pin passes
    bundle = _bundle(V3)
    with pytest.raises(ValueError, match="ARK-Genoa"):
        tinfoil_amd.verify_vcek_chain(
            base64.b64decode(bundle.vcek_b64), bundle.sev_report(),
            anchors=tampered_anchors,
        )


# ------------------------------------------------------ VCEK binding attacks


def test_vcek_for_another_chip_rejected():
    """router-0's genuine, ASK-signed VCEK against router.inf6's report: chain
    verifies until the hwID==chip_id binding."""
    bundle = _bundle(V3)
    report = bundle.sev_report()
    other_vcek = base64.b64decode(V5["vcek"])
    with pytest.raises(ValueError, match="another chip"):
        tinfoil_amd.verify_vcek_chain(other_vcek, report)
    # Same attack through the full pipeline
    with _offline_tls(bundle):
        result = tinfoil.verify_bundle(
            replace(bundle, vcek_b64=V5["vcek"]), model="router"
        )
    assert not result.valid
    assert "another chip" in result.error
    assert result.scorecard.hardware_signature_verified is None


def test_mismatched_tcb_rejected_by_spl_binding():
    """Report whose reported_tcb differs from the VCEK's SPLs (chip_id kept):
    rejected by the bl/tee/snp/ucode binding."""
    bundle = _bundle(V3)
    report = bundle.sev_report()
    vcek_der = base64.b64decode(bundle.vcek_b64)
    good = tinfoil_sev.tcb_parts(report.reported_tcb)
    assert tinfoil_amd.verify_vcek_chain(vcek_der, report).spl == good
    for part, shift in (("bl", 0), ("tee", 8), ("snp", 48), ("ucode", 56)):
        tampered = replace(report, reported_tcb=report.reported_tcb ^ (1 << shift))
        with pytest.raises(ValueError, match="SPL"):
            tinfoil_amd.verify_vcek_chain(vcek_der, tampered)
    # A byte-flip in the report's reported_tcb is also caught by the report
    # signature itself (0x180 is inside the signed area)
    flipped = _tampered_bundle(V3, 0x180)
    with pytest.raises(ValueError, match="signature"):
        tinfoil_amd.verify_report_signature(
            flipped.sev_report(), base64.b64decode(flipped.vcek_b64)
        )


def _oid_der(dotted: str) -> bytes:
    parts = [int(p) for p in dotted.split(".")]
    body = bytearray([parts[0] * 40 + parts[1]])
    for p in parts[2:]:
        stack = []
        while p:
            stack.append(p & 0x7F)
            p >>= 7
        for i, b in enumerate(reversed(stack)):
            body.append(b | (0x80 if i < len(stack) - 1 else 0))
    return bytes([0x06, len(body)]) + bytes(body)


def test_tampered_vcek_spl_extension_rejected():
    """A VCEK whose SPL extension bytes were edited is no longer ASK-signed:
    the ASK->VCEK RSA-PSS signature must fail (fields are authenticated)."""
    vcek = bytearray(base64.b64decode(V3["vcek"]))
    oid = _oid_der(tinfoil_amd.OID_BL_SPL)
    pos = vcek.find(oid)
    assert pos != -1, "bl SPL extension not found in VCEK DER"
    int_pos = vcek.index(0x02, pos + len(oid))
    vcek[int_pos + 2] ^= 0x01
    bundle = _bundle(V3)
    with pytest.raises(ValueError, match="VCEK: signature"):
        tinfoil_amd.verify_vcek_chain(bytes(vcek), bundle.sev_report())


# ---------------------------------------------- detached-key binding attacks


def test_report_data_not_bound_to_key_in_use_rejected():
    """router.inf6's report replayed with router-0's genuine enclaveCert: the
    report_data -> (TLS SPKI, HPKE SAN, hatt) bindings must reject it."""
    bundle = _bundle(V3)
    swapped = replace(bundle, enclave_cert_pem=V5["enclaveCert"])
    with _offline_tls(bundle):
        result = tinfoil.verify_bundle(swapped, model="router")
    assert not result.valid
    assert "report_data" in result.error
    assert result.scorecard.hardware_signature_verified is True  # chain ok; binding failed


def test_wrong_vcek_product_rejected():
    """The V5 (Genoa) VCEK is fine; a Milan product name inside the VCEK would
    be rejected by the product binding — exercised via the v3 report parsed
    against its own product field."""
    bundle = _bundle(V3)
    report = bundle.sev_report()
    vcek_der = base64.b64decode(bundle.vcek_b64)
    as_milan = replace(report, product_name="Milan")
    with pytest.raises(ValueError, match="product"):
        tinfoil_amd.verify_vcek_chain(vcek_der, as_milan)
