"""AMD SEV-SNP vendor chain and report-signature verification (ARK -> ASK -> VCEK).

Trust anchors: verifiers/certs/amd_genoa_{ark,ask}.pem, pinned by DER SHA-256
fingerprints in verifiers/certs/amd_genoa_provenance.json (captured from AMD KDS
2026-11-05, byte-identical to the chain embedded in Tinfoil's published
PyPI client ``tinfoil==0.15.0``). Loading fails closed if the stored bytes do
not hash to the pinned fingerprints.

Every function raises on failure; there are no fallbacks.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict

from cryptography.exceptions import InvalidSignature
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.asymmetric import utils as asym_utils
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from . import tinfoil_sev

_CERTS_DIR = Path(__file__).resolve().parent / "certs"

# VCEK extension OIDs (AMD arc 1.3.6.1.4.1.3704).
OID_STRUCT_VERSION = "1.3.6.1.4.1.3704.1.1"
OID_PRODUCT_NAME = "1.3.6.1.4.1.3704.1.2"
OID_BL_SPL = "1.3.6.1.4.1.3704.1.3.1"
OID_TEE_SPL = "1.3.6.1.4.1.3704.1.3.2"
OID_SNP_SPL = "1.3.6.1.4.1.3704.1.3.3"
OID_UCODE_SPL = "1.3.6.1.4.1.3704.1.3.8"
OID_HWID = "1.3.6.1.4.1.3704.1.4"
OID_CSP_ID = "1.3.6.1.4.1.3704.1.5"


class ChainError(ValueError):
    pass


def _der_fp(cert: x509.Certificate) -> str:
    return hashlib.sha256(cert.public_bytes(Encoding.DER)).hexdigest()


def _load_pinned(name: str, expected_fp: str) -> x509.Certificate:
    path = _CERTS_DIR / name
    cert = x509.load_pem_x509_certificate(path.read_bytes())
    fp = _der_fp(cert)
    if fp != expected_fp:
        raise ChainError(f"{name} fingerprint {fp} != pinned {expected_fp}")
    return cert


def load_genoa_anchors() -> Dict[str, x509.Certificate]:
    prov = json.loads((_CERTS_DIR / "amd_genoa_provenance.json").read_text())
    return {
        "ark": _load_pinned("amd_genoa_ark.pem", prov["ark_der_sha256"]),
        "ask": _load_pinned("amd_genoa_ask.pem", prov["ask_der_sha256"]),
        "provenance": prov,
    }


def _verify_signed_by(cert: x509.Certificate, issuer: x509.Certificate, label: str) -> None:
    if cert.signature_algorithm_oid != x509.SignatureAlgorithmOID.RSASSA_PSS:
        raise ChainError(f"{label}: not RSASSA-PSS signed ({cert.signature_algorithm_oid._name})")
    params = cert.signature_algorithm_parameters
    if not isinstance(params, padding.PSS):
        raise ChainError(f"{label}: unexpected signature parameters {params!r}")
    try:
        issuer.public_key().verify(
            cert.signature, cert.tbs_certificate_bytes, params, cert.signature_hash_algorithm
        )
    except InvalidSignature as exc:
        raise ChainError(f"{label}: signature does not verify under issuer key") from exc


def _find_ext(cert: x509.Certificate, oid: str) -> bytes | None:
    for ext in cert.extensions:
        if ext.oid.dotted_string == oid:
            return ext.value.value
    return None


def _ext_value(cert: x509.Certificate, oid: str) -> bytes:
    raw = _find_ext(cert, oid)
    if raw is None:
        raise ChainError(f"VCEK missing extension {oid}")
    return raw


def _der_int(raw: bytes, oid: str) -> int:
    if len(raw) < 3 or raw[0] != 0x02:
        raise ChainError(f"VCEK extension {oid} is not a DER INTEGER")
    length = raw[1]
    if length + 2 != len(raw):
        raise ChainError(f"VCEK extension {oid} has unexpected DER length")
    return int.from_bytes(raw[2:2 + length], "big")


def _der_ia5string(raw: bytes, oid: str) -> str:
    if len(raw) < 2 or raw[0] != 0x16 or raw[1] + 2 != len(raw):
        raise ChainError(f"VCEK extension {oid} is not a DER IA5String")
    return raw[2:2 + raw[1]].decode("ascii")


def _check_amd_name(name: x509.Name, cn: str) -> None:
    got = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    if len(got) != 1 or got[0].value != cn:
        raise ChainError(f"expected subject CN={cn}, got {[a.value for a in got]}")
    for oid, want in (
        (NameOID.ORGANIZATION_NAME, "Advanced Micro Devices"),
        (NameOID.COUNTRY_NAME, "US"),
        (NameOID.STATE_OR_PROVINCE_NAME, "CA"),
        (NameOID.LOCALITY_NAME, "Santa Clara"),
        (NameOID.ORGANIZATIONAL_UNIT_NAME, "Engineering"),
    ):
        attrs = name.get_attributes_for_oid(oid)
        if len(attrs) != 1 or attrs[0].value != want:
            raise ChainError(f"unexpected {oid._name}: {[a.value for a in attrs]}")


def _check_validity(cert: x509.Certificate, label: str) -> None:
    now = datetime.now(timezone.utc)
    if now < cert.not_valid_before_utc or now > cert.not_valid_after_utc:
        raise ChainError(
            f"{label}: outside validity window "
            f"{cert.not_valid_before_utc.isoformat()}..{cert.not_valid_after_utc.isoformat()}"
        )


@dataclass
class VcekCheck:
    ark_der_sha256: str
    ask_der_sha256: str
    vcek_der_sha256: str
    product_name: str
    hwid_hex: str
    spl: Dict[str, int]
    trust_anchor_provenance: Dict[str, str]

    def as_dict(self) -> Dict[str, object]:
        return {
            "ark_der_sha256": self.ark_der_sha256,
            "ask_der_sha256": self.ask_der_sha256,
            "vcek_der_sha256": self.vcek_der_sha256,
            "product_name": self.product_name,
            "hwid_hex": self.hwid_hex,
            "spl": self.spl,
            "trust_anchor_provenance": self.trust_anchor_provenance,
        }


def verify_vcek_chain(
    vcek_der: bytes, report: tinfoil_sev.SnpReport, *, anchors=None
) -> VcekCheck:
    """Verify ARK self-signature, ARK->ASK, ASK->VCEK, and bind the VCEK to the
    report (product, hwID==chip_id, SPLs==reported_tcb). Raises ChainError.
    ``anchors`` overrides the pinned Genoa trust anchors (negative controls)."""
    if anchors is None:
        anchors = load_genoa_anchors()
    ark: x509.Certificate = anchors["ark"]
    ask: x509.Certificate = anchors["ask"]

    _check_amd_name(ark.subject, "ARK-Genoa")
    if ark.issuer != ark.subject:
        raise ChainError("ARK is not self-issued")
    _verify_signed_by(ark, ark, "ARK")
    _check_validity(ark, "ARK")

    _check_amd_name(ask.subject, "SEV-Genoa")
    if ask.issuer != ark.subject:
        raise ChainError(f"ASK issuer {ask.issuer.rfc4514_string()} != ARK subject")
    _verify_signed_by(ask, ark, "ASK")
    _check_validity(ask, "ASK")

    vcek = x509.load_der_x509_certificate(vcek_der)
    if vcek.version != x509.Version.v3:
        raise ChainError(f"VCEK is not X.509 v3 ({vcek.version})")
    _check_amd_name(vcek.subject, "SEV-VCEK")
    if vcek.issuer != ask.subject:
        raise ChainError(f"VCEK issuer {vcek.issuer.rfc4514_string()} != ASK subject")
    _verify_signed_by(vcek, ask, "VCEK")
    _check_validity(vcek, "VCEK")

    pub = vcek.public_key()
    if not isinstance(pub, ec.EllipticCurvePublicKey) or pub.curve.name != "secp384r1":
        raise ChainError("VCEK public key is not ECDSA P-384")

    product = _der_ia5string(_ext_value(vcek, OID_PRODUCT_NAME), OID_PRODUCT_NAME)
    if product != report.product_name or product != "Genoa":
        raise ChainError(f"VCEK product {product!r} != report product {report.product_name!r}")

    if _find_ext(vcek, OID_CSP_ID) is not None:
        raise ChainError("VCEK unexpectedly carries a CSP_ID extension")

    hwid = _ext_value(vcek, OID_HWID)
    if len(hwid) != 64:
        raise ChainError(f"VCEK hwID extension is {len(hwid)} bytes, expected 64")
    if hwid != report.chip_id:
        raise ChainError(
            f"VCEK hwID {hwid.hex()} != report chip_id {report.chip_id.hex()} (VCEK for another chip)"
        )

    spl = {
        "bl": _der_int(_ext_value(vcek, OID_BL_SPL), OID_BL_SPL),
        "tee": _der_int(_ext_value(vcek, OID_TEE_SPL), OID_TEE_SPL),
        "snp": _der_int(_ext_value(vcek, OID_SNP_SPL), OID_SNP_SPL),
        "ucode": _der_int(_ext_value(vcek, OID_UCODE_SPL), OID_UCODE_SPL),
    }
    expected = tinfoil_sev.tcb_parts(report.reported_tcb)
    if spl != expected:
        raise ChainError(f"VCEK SPLs {spl} != report reported_tcb {expected}")

    return VcekCheck(
        ark_der_sha256=_der_fp(ark),
        ask_der_sha256=_der_fp(ask),
        vcek_der_sha256=_der_fp(vcek),
        product_name=product,
        hwid_hex=hwid.hex(),
        spl=spl,
        trust_anchor_provenance={
            "captured_from": anchors["provenance"]["captured_from"],
            "captured_utc": anchors["provenance"]["captured_utc"],
            "cross_checked_against": anchors["provenance"]["cross_checked_against"],
        },
    )


def verify_report_signature(report: tinfoil_sev.SnpReport, vcek_der: bytes) -> None:
    """Verify the ECDSA P-384/SHA-384 report signature over the exact signed
    bytes [0x000, 0x2A0) under the VCEK key. Raises on mismatch."""
    if report.signature_algo != 1:
        raise ChainError(f"unsupported report signature algorithm {report.signature_algo}")
    vcek = x509.load_der_x509_certificate(vcek_der)
    r, s = report.signature_rs()
    if r == 0 or s == 0:
        raise ChainError("report signature has a zero R/S component")
    try:
        vcek.public_key().verify(
            asym_utils.encode_dss_signature(r, s),
            report.signed_data,
            ec.ECDSA(hashes.SHA384()),
        )
    except InvalidSignature as exc:
        raise ChainError(
            "report ECDSA signature does not verify under the VCEK key"
        ) from exc
