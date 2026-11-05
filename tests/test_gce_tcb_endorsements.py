"""Verification tests for Google's signed GCE TCB TDX launch endorsements (issue #33).

Positive cases run against retained real evidence captured 2026-11-05 under
tests/fixtures/gce-tcb/. Negative controls mutate one authenticated input at a
time; where a mutation must stay internally consistent to isolate a single check,
a synthetic endorsement is built and signed by a test-generated RSA-PSS CA.
"""
import datetime
import importlib.util
import json
import pathlib

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import Encoding

FIXTURES = pathlib.Path(__file__).parent / "fixtures" / "gce-tcb"
spec = importlib.util.spec_from_file_location(
    "gce_tcb_endorsements", pathlib.Path(__file__).parent.parent / "watch" / "gce_tcb_endorsements.py")
gce = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gce)

NOW = datetime.datetime(2026, 11, 5, 14, 0, tzinfo=datetime.timezone.utc)
ROOT_DER = (FIXTURES / "GCE-cc-tcb-root_1.der").read_bytes()
ROOT = x509.load_der_x509_certificate(ROOT_DER)
LISTING = json.loads((FIXTURES / "listing-2026-11-05.json").read_text())
FD_NAMES = {i["name"] for i in LISTING["items"]}


def verify_fixture(filename):
    raw = (FIXTURES / "endorsements" / filename).read_bytes()
    parsed = gce.parse_launch_endorsement(raw)
    return parsed, gce.verify_endorsement(
        parsed, "ovmf_x64_csm/tdx/" + filename, ROOT, ROOT_DER, FD_NAMES, NOW)


# --- protobuf wire encoder for synthetic endorsements ---

def field_bytes(number, payload):
    return _varint(number << 3 | 2) + _varint(len(payload)) + payload


def field_varint(number, value):
    return _varint(number << 3 | 0) + _varint(value)


def _varint(value):
    out = b""
    while True:
        byte = value & 0x7F
        value >>= 7
        out += bytes([byte | (0x80 if value else 0)])
        if not value:
            return out


def timestamp_message(seconds):
    return field_varint(1, seconds)


def measurement(ram_gib, early_accept, mrtd):
    out = b""
    if ram_gib is not None:
        out += field_varint(1, ram_gib)
    if early_accept:
        out += field_varint(2, 1)
    out += field_bytes(3, mrtd)
    return out


def golden_message(timestamp, cl_spec, commit, cert_der, digest, ca_bundle, tdx):
    out = field_bytes(1, timestamp_message(int(timestamp.timestamp())))
    if cl_spec:
        out += field_varint(2, cl_spec)
    if commit:
        out += field_bytes(3, commit)
    out += field_bytes(4, cert_der)
    out += field_bytes(5, digest)
    out += field_bytes(6, ca_bundle)
    out += field_bytes(8, tdx)
    return out


def tdx_message(svn, measurements):
    out = field_varint(1, svn)
    for m in measurements:
        out += field_bytes(2, m)
    return out


def launch_endorsement(golden, signature):
    return field_bytes(1, golden) + field_bytes(2, signature)


def pem_bundle(cert):
    return cert.public_bytes(Encoding.PEM)


# --- synthetic RSA-PSS CA ---

def make_ca(name, ca_key=None, issuer_cert=None, issuer_key=None, not_before=None,
            not_after=None):
    key = ca_key or rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, name)])
    signer_cert = issuer_cert or None
    signer_key = issuer_key or key
    builder = (x509.CertificateBuilder()
               .subject_name(subject)
               .issuer_name(signer_cert.subject if signer_cert else subject)
               .public_key(key.public_key())
               .serial_number(x509.random_serial_number())
               .not_valid_before(not_before or datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc))
               .not_valid_after(not_after or datetime.datetime(2040, 1, 1, tzinfo=datetime.timezone.utc)))
    pss = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)
    cert = builder.sign(signer_key, hashes.SHA256(), rsa_padding=pss)
    return cert, key


def sign_with(key, data):
    return key.sign(data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
                    hashes.SHA256())


@pytest.fixture(scope="module")
def mini_ca():
    root_cert, root_key = make_ca("mini-test-root")
    leaf_cert, leaf_key = make_ca("mini-test-leaf", issuer_cert=root_cert, issuer_key=root_key)
    return root_cert, root_key, leaf_cert, leaf_key


def synthetic(raw_endorsement_bytes=None, *, golden=None, signature=b"",
              object_mrtd=None, digest=None, cert_der=None, ca_bundle=None,
              timestamp=datetime.datetime(2025, 1, 1, tzinfo=datetime.timezone.utc),
              cl_spec=123, tdx_bytes=None, root=None, root_der=b"wrong-root"):
    """Assemble inputs for verify_endorsement from synthetic parts."""
    root = root
    root_der = root_der
    mrtd = object_mrtd or (b"\x11" * 48)
    digest = digest if digest is not None else bytes.fromhex(
        next(iter(sorted(n for n in FD_NAMES if n.endswith(".fd")))).split("/")[-1][:-3])
    tdx = tdx_bytes if tdx_bytes is not None else tdx_message(2, [measurement(None, False, mrtd)])
    golden_payload = golden if golden is not None else golden_message(
        timestamp, cl_spec, b"\xaa" * 8, cert_der, digest, ca_bundle, tdx)
    raw = raw_endorsement_bytes if raw_endorsement_bytes is not None else \
        launch_endorsement(golden_payload, signature)
    parsed = gce.parse_launch_endorsement(raw)
    return parsed, gce.verify_endorsement(
        parsed, f"ovmf_x64_csm/tdx/{(object_mrtd or mrtd).hex()}.binarypb",
        root, root_der, FD_NAMES, NOW)


# --- positive cases on retained real evidence ---

REAL_FIXTURES = sorted(p.name for p in (FIXTURES / "endorsements").glob("*.binarypb"))


@pytest.mark.parametrize("filename", REAL_FIXTURES)
def test_real_endorsement_verifies(filename):
    parsed, record = verify_fixture(filename)
    assert record["result"] == "verified", record["checks"]
    assert record["mrtd_name"] == filename[: -len(".binarypb")]
    assert record["svn"] == 2
    assert any(m["mrtd"] == record["mrtd_name"] for m in record["measurements"])
    assert f"ovmf_x64_csm/{record['firmware_sha384']}.fd" in FD_NAMES
    assert "GCE-uefi-signer" in record["signer"]["subject"]
    assert record["signer"]["issuer"] == ROOT.issuer.rfc4514_string()
    assert record["measurements"], "TDX endorsement without measurements"


def test_vendored_root_matches_independent_fingerprint():
    meta = json.loads((FIXTURES / "GCE-cc-tcb-root_1.meta.json").read_text())
    assert ROOT.fingerprint(hashes.SHA256()).hex() == meta["file_sha256"]
    assert ":".join(ROOT.fingerprint(hashes.SHA256()).hex()[i:i + 2]
                     for i in range(0, 64, 2)).upper() == meta["cert_sha256_fingerprint_openssl"]
    assert ROOT.not_valid_before_utc.replace(tzinfo=None).isoformat() + "Z" == meta["not_before"]
    assert ROOT.not_valid_after_utc.replace(tzinfo=None).isoformat() + "Z" == meta["not_after"]


def test_listing_fixture_covers_all_endorsement_digests():
    """Every retained endorsement's digest names a .fd object in the retained listing."""
    for filename in REAL_FIXTURES:
        _, record = verify_fixture(filename)
        assert record["firmware_sha384"], filename


# --- negative controls: each passing check fails on independently tampered input ---

def test_tampered_payload_fails_signature():
    parsed, record = verify_fixture(REAL_FIXTURES[-1])
    # Flip one byte inside the embedded signer certificate: structure stays
    # parseable, so the failure is attributable to the signature check alone.
    golden_raw = bytearray(parsed["golden_raw"])
    cert_at = golden_raw.find(parsed["cert_der"])
    assert cert_at >= 0
    golden_raw[cert_at + 100] ^= 1
    raw = launch_endorsement(bytes(golden_raw), parsed["signature"])
    tampered = gce.parse_launch_endorsement(raw)
    record2 = gce.verify_endorsement(
        tampered, "ovmf_x64_csm/tdx/" + record["mrtd_name"] + ".binarypb",
        ROOT, ROOT_DER, FD_NAMES, NOW)
    assert record2["checks"]["signature"].startswith("fail")


def test_tampered_signature_fails():
    parsed, record = verify_fixture(REAL_FIXTURES[-1])
    bad_sig = parsed["signature"][:-1] + bytes([parsed["signature"][-1] ^ 1])
    raw = launch_endorsement(parsed["golden_raw"], bad_sig)
    tampered = gce.parse_launch_endorsement(raw)
    record2 = gce.verify_endorsement(
        tampered, "ovmf_x64_csm/tdx/" + record["mrtd_name"] + ".binarypb",
        ROOT, ROOT_DER, FD_NAMES, NOW)
    assert record2["checks"]["signature"].startswith("fail")


def test_wrong_root_fails_chain():
    parsed, record = verify_fixture(REAL_FIXTURES[-1])
    other_root, _ = make_ca("wrong-root")
    record2 = gce.verify_endorsement(
        parsed, "ovmf_x64_csm/tdx/" + record["mrtd_name"] + ".binarypb",
        other_root, other_root.public_bytes(Encoding.DER), FD_NAMES, NOW)
    assert record2["checks"]["chain_to_root"].startswith("fail")
    assert record2["checks"]["root_bundle_match"].startswith("fail")
    # The signature itself is intact: only the trust decision changed.
    assert record2["checks"]["signature"] == "ok"


def test_rogue_signer_fails_chain(mini_ca):
    root_cert, root_key, _, _ = mini_ca
    rogue_cert, rogue_key = make_ca("rogue-leaf")
    mrtd = b"\x22" * 48
    digest = bytes.fromhex(sorted(n for n in FD_NAMES)[0].split("/")[-1][:-3])
    golden = golden_message(datetime.datetime(2025, 1, 1, tzinfo=datetime.timezone.utc),
                            1, b"\x01", rogue_cert.public_bytes(Encoding.DER),
                            digest, pem_bundle(rogue_cert),
                            tdx_message(2, [measurement(None, False, mrtd)]))
    raw = launch_endorsement(golden, sign_with(rogue_key, golden))
    parsed = gce.parse_launch_endorsement(raw)
    record = gce.verify_endorsement(parsed, f"ovmf_x64_csm/tdx/{mrtd.hex()}.binarypb",
                                    ROOT, ROOT_DER, FD_NAMES, NOW)
    assert record["checks"]["signature"] == "ok"
    assert record["checks"]["chain_to_root"].startswith("fail")
    assert record["result"] == "failed"


def test_root_bundle_mismatch_isolated(mini_ca):
    """Chain and signature pass against the mini CA, but empty ca_bundle fails the pin."""
    root_cert, root_key, leaf_cert, leaf_key = mini_ca
    mrtd = b"\x33" * 48
    digest = bytes.fromhex(sorted(n for n in FD_NAMES)[0].split("/")[-1][:-3])
    golden = golden_message(datetime.datetime(2025, 1, 1, tzinfo=datetime.timezone.utc),
                            1, b"\x01", leaf_cert.public_bytes(Encoding.DER),
                            digest, b"",
                            tdx_message(2, [measurement(None, False, mrtd)]))
    raw = launch_endorsement(golden, sign_with(leaf_key, golden))
    parsed = gce.parse_launch_endorsement(raw)
    record = gce.verify_endorsement(parsed, f"ovmf_x64_csm/tdx/{mrtd.hex()}.binarypb",
                                    root_cert, root_cert.public_bytes(Encoding.DER),
                                    FD_NAMES, NOW)
    assert record["checks"]["signature"] == "ok"
    assert record["checks"]["chain_to_root"] == "ok"
    assert record["checks"]["root_bundle_match"].startswith("fail")


def test_object_name_mrtd_mismatch_fails():
    parsed, _ = verify_fixture(REAL_FIXTURES[-1])
    wrong_name = "ovmf_x64_csm/tdx/" + "ab" * 96 + ".binarypb"
    record = gce.verify_endorsement(parsed, wrong_name, ROOT, ROOT_DER, FD_NAMES, NOW)
    assert record["checks"]["name_mrtd"].startswith("fail")
    assert record["result"] == "failed"


def test_missing_firmware_object_fails():
    parsed, _ = verify_fixture(REAL_FIXTURES[-1])
    mrtd = parsed["measurements"][0]["mrtd"]
    record = gce.verify_endorsement(parsed, f"ovmf_x64_csm/tdx/{mrtd}.binarypb",
                                    ROOT, ROOT_DER, set(), NOW)
    assert record["checks"]["firmware_object"].startswith("fail")
    assert record["checks"]["signature"] == "ok"


def test_cert_not_yet_valid_at_endorsement_fails(mini_ca):
    root_cert, root_key, leaf_cert, leaf_key = mini_ca
    late_leaf_cert, late_leaf_key = make_ca(
        "late-leaf", issuer_cert=root_cert, issuer_key=root_key,
        not_before=datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc))
    mrtd = b"\x44" * 48
    digest = bytes.fromhex(sorted(n for n in FD_NAMES)[0].split("/")[-1][:-3])
    golden = golden_message(datetime.datetime(2025, 6, 1, tzinfo=datetime.timezone.utc),
                            1, b"\x01", late_leaf_cert.public_bytes(Encoding.DER),
                            digest, pem_bundle(root_cert),
                            tdx_message(2, [measurement(None, False, mrtd)]))
    raw = launch_endorsement(golden, sign_with(late_leaf_key, golden))
    parsed = gce.parse_launch_endorsement(raw)
    record = gce.verify_endorsement(parsed, f"ovmf_x64_csm/tdx/{mrtd.hex()}.binarypb",
                                    root_cert, root_cert.public_bytes(Encoding.DER),
                                    FD_NAMES, NOW)
    assert record["checks"]["cert_valid_at_endorsement"].startswith("fail")
    assert record["checks"]["signature"] == "ok"
    assert record["checks"]["chain_to_root"] == "ok"


def test_missing_provenance_fails(mini_ca):
    root_cert, root_key, leaf_cert, leaf_key = mini_ca
    mrtd = b"\x55" * 48
    digest = bytes.fromhex(sorted(n for n in FD_NAMES)[0].split("/")[-1][:-3])
    golden = golden_message(datetime.datetime(2024, 9, 1, tzinfo=datetime.timezone.utc),
                            0, b"", leaf_cert.public_bytes(Encoding.DER),
                            digest, pem_bundle(root_cert),
                            tdx_message(2, [measurement(None, False, mrtd)]))
    raw = launch_endorsement(golden, sign_with(leaf_key, golden))
    parsed = gce.parse_launch_endorsement(raw)
    record = gce.verify_endorsement(parsed, f"ovmf_x64_csm/tdx/{mrtd.hex()}.binarypb",
                                    root_cert, root_cert.public_bytes(Encoding.DER),
                                    FD_NAMES, NOW)
    assert record["checks"]["provenance"].startswith("fail")


@pytest.mark.parametrize("mangle", [
    b"", b"\x08", b"\x12\x05\xab", b"not-a-protobuf",
    bytes([0x12, 0x05, 0x01, 0x02, 0x03]),  # payload present, signature missing
])
def test_malformed_protobuf_rejected(mangle):
    with pytest.raises(ValueError):
        gce.parse_launch_endorsement(mangle)


def test_unknown_wire_type_rejected():
    with pytest.raises(ValueError):
        gce.parse_launch_endorsement(bytes([0x0F]))


def test_duplicate_singular_field_rejected():
    inner = field_bytes(1, timestamp_message(100)) + field_bytes(1, timestamp_message(200))
    with pytest.raises(ValueError):
        gce.parse_launch_endorsement(launch_endorsement(inner, b""))


# --- history behaviour ---

def _sample_history():
    mrtd_a, mrtd_b = "a" * 192, "b" * 192
    fw_a, fw_b = "f" * 96, "e" * 96
    return {
        "endorsements": {
            mrtd_a: {"firmware_sha384": fw_a, "result": "verified", "removed": False,
                     "bucket_created": "2026-01-01T00:00:00Z"},
            mrtd_b: {"firmware_sha384": fw_b, "result": "verified", "removed": False,
                     "bucket_created": "2026-02-01T00:00:00Z"},
        },
        "firmware": {
            fw_a: {"bucket_created": "2026-01-01T00:00:00Z"},
            fw_b: {"bucket_created": "2026-02-01T00:00:00Z"},
        },
        "intel_rims": {},
    }


def test_update_history_records_withdrawal_and_rim_change():
    history = _sample_history()
    mrtd_a, mrtd_b = "a" * 192, "b" * 192
    fw_a, fw_b = "f" * 96, "e" * 96
    current = {
        f"ovmf_x64_csm/tdx/{mrtd_b}.binarypb": {"timeCreated": "2026-02-01T00:00:00Z"},
        f"ovmf_x64_csm/{fw_b}.fd": {"timeCreated": "2026-02-01T00:00:00Z"},
        "intel_rims/intel-tdx-rim-prod.textproto":
            {"md5Hash": "newmd5", "generation": "9", "updated": "2026-11-05T16:00:00Z"},
    }
    history.setdefault("intel_rims", {})["intel_rims/intel-tdx-rim-prod.textproto"] = \
        {"md5": "oldmd5", "generation": "8"}
    records = {f"ovmf_x64_csm/tdx/{mrtd_b}.binarypb": {
        "result": "verified", "checks": {}, "firmware_sha384": fw_b,
        "golden_timestamp": "2026-01-31T00:00:00Z", "cl_spec": 1, "commit_hex": None,
        "svn": 2, "sev_snp_present": False, "measurements": [], "signer": {}}}
    gce.update_history(history, current, records, NOW, NOW.isoformat())
    assert history["endorsements"][mrtd_a]["removed"] is True
    assert history["firmware"][fw_a]["removed"] is True
    assert history["endorsements"][mrtd_b]["removed"] is False
    rim = history["intel_rims"]["intel_rims/intel-tdx-rim-prod.textproto"]
    assert rim["md5"] == "newmd5"
    assert rim["changes"] == [{"at": NOW.isoformat(), "from_md5": "oldmd5",
                               "to_md5": "newmd5", "to_updated": "2026-11-05T16:00:00Z",
                               "to_generation": "9"}]


def test_update_history_appends_failure_log():
    history = _sample_history()
    mrtd_b = "b" * 192
    fw_b = "e" * 96
    current = {f"ovmf_x64_csm/tdx/{mrtd_b}.binarypb": {"timeCreated": "2026-02-01T00:00:00Z"}}
    records = {f"ovmf_x64_csm/tdx/{mrtd_b}.binarypb": {
        "result": "failed", "checks": {"signature": "fail: boom"}, "firmware_sha384": fw_b,
        "golden_timestamp": None, "cl_spec": None, "commit_hex": None, "svn": None,
        "sev_snp_present": None, "measurements": []}}
    gce.update_history(history, current, records, NOW, NOW.isoformat())
    assert history["endorsements"][mrtd_b]["failures"] == [
        {"at": NOW.isoformat(), "reasons": ["fail: boom"]}]


def test_lookup_flags_unendorsed_and_age():
    history = _sample_history()
    unendorsed = gce.lookup(history, "c" * 192)
    assert unendorsed["endorsed"] is False
    older = gce.lookup(history, "a" * 192)
    assert older["endorsed"] is True
    assert older["newer_firmware_releases"] == 1


def test_history_digest_cross_check_record_is_consistent():
    """The live one-binary cross-check recorded in the committed history must hold."""
    history_path = pathlib.Path(__file__).parent.parent / "data" / "gce-tcb-endorsements.json"
    if not history_path.exists():
        pytest.skip("history file not yet written")
    history = json.loads(history_path.read_text())
    check = history.get("digest_cross_check")
    assert check, "digest cross-check record missing"
    assert check["match"] is True
    assert check["content_sha384"] == check["endorsed_sha384"]
    assert check["object"] == f"ovmf_x64_csm/{check['endorsed_sha384']}.fd"


# --- provider-row cross-reference (S7) against real retained evidence ---

CHUTES_LEDGER = pathlib.Path(__file__).parent.parent / "data" / "audits" / "chutes_tee.json"


def test_retained_provider_mrtds_cross_referenced_against_real_endorsements():
    """Both retained Chutes TDX MRTDs (analyst-pair signoff) are NOT GCE-endorsed:
    Chutes runs a custom non-dstack TDX stack, so its base-TD MRTD cannot appear in
    Google's GCE firmware endorsement set. This is the fail direction of the check,
    run against the committed live history."""
    history = json.loads((pathlib.Path(__file__).parent.parent /
                          "data" / "gce-tcb-endorsements.json").read_text())
    ledger = json.loads(CHUTES_LEDGER.read_text())
    refs = gce.cross_reference_audits({"endorsements": history["endorsements"],
                                       "firmware": history["firmware"]},
                                      CHUTES_LEDGER.parent, NOW.isoformat())
    rows = refs["chutes_tee.json"]
    assert len(rows) == len(ledger["audits"]) == 2
    for row in rows:
        assert row["endorsed"] is False
        assert "result" not in row and "firmware_sha384" not in row
        assert row["note"] == "not among observed GCE TDX launch endorsements"
        assert row["verdict"] == "golden-set-member-serving-code-unmeasured"
    # No retained Chutes value leaked into the GCE endorsement set.
    for audit in ledger["audits"]:
        assert audit["mrtd"] not in history["endorsements"]


def test_cross_reference_recognises_a_genuinely_endorsed_mrtd(tmp_path):
    """Pass direction, real evidence: a real GCE-endorsed MRTD placed in a synthetic
    ledger must resolve to its verified endorsement, not fail everything."""
    history = json.loads((pathlib.Path(__file__).parent.parent /
                          "data" / "gce-tcb-endorsements.json").read_text())
    endorsed_mrtd, entry = sorted(history["endorsements"].items())[0]
    assert entry["result"] == "verified"
    ledger = {"identity_field": "mrtd", "source_repo": "test-ledger",
              "audits": [{"mrtd": endorsed_mrtd.upper(), "signoff": "analyst-pair",
                          "verdict": "test", "last_seen": "2026-11-05"}]}
    (tmp_path / "test_ledger.json").write_text(json.dumps(ledger))
    refs = gce.cross_reference_audits({"endorsements": history["endorsements"],
                                       "firmware": history["firmware"]},
                                      tmp_path, NOW.isoformat())
    row = refs["test_ledger.json"][0]
    assert row["endorsed"] is True
    assert row["result"] == "verified"
    assert row["firmware_sha384"] == entry["firmware_sha384"]
    assert row["ledger"] == "test-ledger"
    assert row["checked_at"] == NOW.isoformat()
