"""MDA -> Secure Enclave key binding for Darkbloom provider feed entries.

Ported from devproof-audits-guide case-studies/darkbloom-d-inference/verify/binding-check.py,
adding the chain check to the pinned Apple Enterprise Attestation Root that the original omits.
The binding holds when the MDA leaf's OID 1.2.840.113635.100.8.11.1 carries sha256 of the
provider's base64 se_public_key string. Validity is recorded against capture time, not enforced.
"""
from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import Encoding

CERTS = Path(__file__).parent / "certs"
OID_SE_KEY_HASH = "1.2.840.113635.100.8.11.1"


def load_root() -> x509.Certificate:
    prov = json.loads((CERTS / "apple_enterprise_attestation_root_provenance.json").read_text())
    cert = x509.load_pem_x509_certificate((CERTS / "apple_enterprise_attestation_root.pem").read_bytes())
    fp = hashlib.sha256(cert.public_bytes(Encoding.DER)).hexdigest()
    if fp != prov["der_sha256"]:
        raise ValueError(f"Apple root fingerprint {fp} != pinned {prov['der_sha256']}")
    return cert


def binding(provider: dict, root: x509.Certificate, at: datetime) -> dict:
    chain = provider.get("mda_cert_chain_b64") or []
    if not chain:
        return {"result": "not_checked", "reason": "no_chain_published"}
    try:
        certs = [x509.load_der_x509_certificate(base64.b64decode(c)) for c in chain]
        for child, parent in zip(certs, certs[1:] + [root]):
            child.verify_directly_issued_by(parent)
    except (ValueError, TypeError, InvalidSignature) as exc:
        return {"result": "chain_invalid", "error": f"{type(exc).__name__}: {exc}"}
    leaf = certs[0]
    out = {"leaf_serial": format(leaf.serial_number, "x"), "leaf_not_after": leaf.not_valid_after_utc.isoformat(),
           "valid_at_capture": all(c.not_valid_before_utc <= at <= c.not_valid_after_utc for c in certs)}
    ext = next((e for e in leaf.extensions if e.oid.dotted_string == OID_SE_KEY_HASH), None)
    if ext is None:
        return {"result": "no_oid", **out}
    raw = ext.value.value
    if len(raw) >= 2 and raw[0] == 0x04 and raw[1] == len(raw) - 2:
        raw = raw[2:]
    expected = hashlib.sha256(provider["se_public_key"].encode("ascii")).digest()
    return {"result": "holds" if raw == expected else "fails", **out}
