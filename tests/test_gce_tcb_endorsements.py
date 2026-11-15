"""Verification of Google's signed GCE TCB TDX launch endorsements (issue #33).

Positive cases run on real endorsements retained 2026-11-05 under tests/fixtures/gce-tcb/.
Negative controls change one input; where a check must be isolated, a synthetic endorsement
is signed by a test-generated RSA-PSS CA.
"""
import base64, datetime, hashlib, importlib.util, json, pathlib, sys

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import Encoding

REPO = pathlib.Path(__file__).parent.parent
FIXTURES = REPO / "tests/fixtures/gce-tcb"
spec = importlib.util.spec_from_file_location("firmware_endorsements", REPO / "watch/firmware_endorsements.py")
fe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fe)

NOW = datetime.datetime(2026, 11, 5, 14, 0, tzinfo=datetime.timezone.utc)
ROOT_DER = fe.ROOT.read_bytes()
ROOT = x509.load_der_x509_certificate(ROOT_DER)
LISTING = {i["name"]: i for i in json.loads((FIXTURES / "listing-2026-11-05.json").read_text())["items"]}
FD_NAMES = {n for n in LISTING if n.endswith(".fd")}
FD_DIGEST = bytes.fromhex(sorted(FD_NAMES)[0].split("/")[-1][:-3])
REAL = sorted(p.name for p in (FIXTURES / "endorsements").glob("*.binarypb"))
PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)


def verify_fixture(filename, root=ROOT, root_der=ROOT_DER, fd_names=FD_NAMES):
    parsed = fe.parse_launch_endorsement((FIXTURES / "endorsements" / filename).read_bytes())
    return parsed, fe.verify_endorsement(parsed, fe.TDX_PREFIX + filename, root, root_der, fd_names, NOW)


def _varint(value):
    out = b""
    while True:
        byte, value = value & 0x7F, value >> 7
        out += bytes([byte | (0x80 if value else 0)])
        if not value:
            return out


def field_bytes(number, payload):
    return _varint(number << 3 | 2) + _varint(len(payload)) + payload


def field_varint(number, value):
    return _varint(number << 3) + _varint(value)


def golden_message(timestamp, cl_spec, commit, cert_der, digest, ca_bundle, mrtd):
    tdx = field_varint(1, 2) + field_bytes(2, field_bytes(3, mrtd))
    out = field_bytes(1, field_varint(1, int(timestamp.timestamp())))
    if cl_spec:
        out += field_varint(2, cl_spec)
    if commit:
        out += field_bytes(3, commit)
    return out + field_bytes(4, cert_der) + field_bytes(5, digest) + field_bytes(6, ca_bundle) + field_bytes(8, tdx)


def launch_endorsement(golden, signature):
    return field_bytes(1, golden) + field_bytes(2, signature)


def make_ca(name, issuer_cert=None, issuer_key=None, not_before=datetime.datetime(2024, 1, 1), issuer_name=None):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, name)])
    cert = (x509.CertificateBuilder().subject_name(subject)
            .issuer_name(issuer_name or (issuer_cert.subject if issuer_cert else subject))
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(not_before).not_valid_after(datetime.datetime(2040, 1, 1))
            .sign(issuer_key or key, hashes.SHA256(), rsa_padding=PSS))
    return cert, key


def synthetic(leaf_cert, leaf_key, root_cert, ca_bundle, mrtd, timestamp=datetime.datetime(2025, 1, 1),
              cl_spec=1, commit=b"\x01"):
    golden = golden_message(timestamp.replace(tzinfo=datetime.timezone.utc), cl_spec, commit,
                            leaf_cert.public_bytes(Encoding.DER), FD_DIGEST, ca_bundle, mrtd)
    parsed = fe.parse_launch_endorsement(launch_endorsement(golden, leaf_key.sign(golden, PSS, hashes.SHA256())))
    return fe.verify_endorsement(parsed, f"{fe.TDX_PREFIX}{mrtd.hex()}.binarypb", root_cert,
                                 root_cert.public_bytes(Encoding.DER), FD_NAMES, NOW)


@pytest.fixture(scope="module")
def mini_ca():
    root_cert, root_key = make_ca("mini-test-root")
    leaf_cert, leaf_key = make_ca("mini-test-leaf", root_cert, root_key)
    return root_cert, root_key, leaf_cert, leaf_key


def test_vendored_root_is_googles():
    assert hashlib.sha256(ROOT_DER).hexdigest() == "e876bc6978bf4f3da445f98a0a82363c8c0bae5a1fc033c6df65846a6cb0f18c"
    assert "CN=GCE-cc-tcb-root" in ROOT.subject.rfc4514_string() and ROOT.subject == ROOT.issuer


@pytest.mark.parametrize("filename", REAL)
def test_real_endorsement_verifies(filename):
    _, record = verify_fixture(filename)
    assert record["result"] == "verified", record["checks"]
    assert record["svn"] == 2
    assert f"ovmf_x64_csm/{record['firmware_sha384']}.fd" in FD_NAMES
    assert "GCE-uefi-signer" in record["signer"]["subject"]
    assert record["signer"]["issuer"] == ROOT.subject.rfc4514_string()


def test_tampered_payload_fails_signature():
    parsed, _ = verify_fixture(REAL[-1])
    golden = bytearray(parsed["golden_raw"])
    golden[golden.find(parsed["digest"])] ^= 1
    tampered = fe.parse_launch_endorsement(launch_endorsement(bytes(golden), parsed["signature"]))
    record = fe.verify_endorsement(tampered, fe.TDX_PREFIX + REAL[-1], ROOT, ROOT_DER, FD_NAMES, NOW)
    assert record["checks"]["signature"].startswith("fail")


def test_tampered_signature_fails():
    parsed, _ = verify_fixture(REAL[-1])
    bad = fe.parse_launch_endorsement(launch_endorsement(parsed["golden_raw"], parsed["signature"][:-1] + b"\x00"))
    record = fe.verify_endorsement(bad, fe.TDX_PREFIX + REAL[-1], ROOT, ROOT_DER, FD_NAMES, NOW)
    assert record["checks"]["signature"].startswith("fail")


def test_wrong_root_fails_chain():
    other, _ = make_ca("wrong-root")
    _, record = verify_fixture(REAL[-1], other, other.public_bytes(Encoding.DER))
    assert record["checks"]["chain_to_root"].startswith("fail")
    assert record["checks"]["root_bundle_match"].startswith("fail")
    assert record["checks"]["signature"] == "ok"


def test_leaf_naming_root_but_signed_by_other_key_fails_chain(mini_ca):
    """Issuer name equals the root subject; only the root signature check can reject it."""
    root_cert, _, _, _ = mini_ca
    impostor_cert, impostor_key = make_ca("mini-test-root")
    leaf_cert, leaf_key = make_ca("forged-leaf", impostor_cert, impostor_key)
    assert leaf_cert.issuer == root_cert.subject
    record = synthetic(leaf_cert, leaf_key, root_cert, root_cert.public_bytes(Encoding.PEM), b"\x22" * 48)
    assert record["checks"]["signature"] == "ok"
    assert record["checks"]["chain_to_root"] == "fail: root does not verify leaf certificate"
    assert record["result"] == "failed"


def test_mini_ca_chain_passes(mini_ca):
    root_cert, _, leaf_cert, leaf_key = mini_ca
    record = synthetic(leaf_cert, leaf_key, root_cert, root_cert.public_bytes(Encoding.PEM), b"\x23" * 48)
    assert record["result"] == "verified", record["checks"]


def test_root_bundle_mismatch_isolated(mini_ca):
    root_cert, _, leaf_cert, leaf_key = mini_ca
    record = synthetic(leaf_cert, leaf_key, root_cert, leaf_cert.public_bytes(Encoding.PEM), b"\x33" * 48)
    assert record["checks"]["chain_to_root"] == "ok"
    assert record["checks"]["root_bundle_match"].startswith("fail")


def test_empty_ca_bundle_raises(mini_ca):
    root_cert, _, leaf_cert, leaf_key = mini_ca
    with pytest.raises(ValueError):
        synthetic(leaf_cert, leaf_key, root_cert, b"", b"\x34" * 48)


def test_object_name_mrtd_mismatch_fails():
    parsed, _ = verify_fixture(REAL[-1])
    record = fe.verify_endorsement(parsed, fe.TDX_PREFIX + "ab" * 48 + ".binarypb", ROOT, ROOT_DER, FD_NAMES, NOW)
    assert record["checks"]["name_mrtd"].startswith("fail")


def test_missing_firmware_object_fails():
    _, record = verify_fixture(REAL[-1], fd_names=set())
    assert record["checks"]["firmware_object"].startswith("fail")
    assert record["checks"]["signature"] == "ok"


def test_cert_not_yet_valid_at_endorsement_fails(mini_ca):
    root_cert, root_key, _, _ = mini_ca
    late_cert, late_key = make_ca("late-leaf", root_cert, root_key, not_before=datetime.datetime(2026, 1, 1))
    record = synthetic(late_cert, late_key, root_cert, root_cert.public_bytes(Encoding.PEM), b"\x44" * 48,
                       timestamp=datetime.datetime(2025, 6, 1))
    assert record["checks"]["cert_valid_at_endorsement"].startswith("fail")
    assert record["checks"]["chain_to_root"] == "ok"


def test_missing_provenance_fails(mini_ca):
    root_cert, _, leaf_cert, leaf_key = mini_ca
    record = synthetic(leaf_cert, leaf_key, root_cert, root_cert.public_bytes(Encoding.PEM), b"\x55" * 48,
                       timestamp=datetime.datetime(2024, 9, 1), cl_spec=0, commit=b"")
    assert record["checks"]["provenance"].startswith("fail")


@pytest.mark.parametrize("raw", [b"", b"\x08", b"\x12\x05\xab", b"not-a-protobuf", bytes([0x12, 0x05, 1, 2, 3]),
                                 bytes([0x0F])])
def test_malformed_protobuf_rejected(raw):
    with pytest.raises(ValueError):
        fe.parse_launch_endorsement(raw)


def test_duplicate_singular_field_rejected():
    inner = field_bytes(1, field_varint(1, 100)) + field_bytes(1, field_varint(1, 200))
    with pytest.raises(ValueError):
        fe.parse_launch_endorsement(launch_endorsement(inner, b""))


def rim_listing(content, generation="9"):
    return {"intel_rims/rim.textproto": {"md5Hash": base64.b64encode(hashlib.md5(content).digest()).decode(),
                                         "generation": generation, "updated": "2026-11-05T21:00:00Z",
                                         "timeCreated": "2026-03-06T00:00:00Z", "size": str(len(content))}}


def test_update_history_records_withdrawal_and_retains_rim_versions(tmp_path, monkeypatch):
    a, b, fw_a, fw_b = "a" * 96, "b" * 96, "f" * 96, "e" * 96
    meta = {"timeCreated": "2026-02-01T00:00:00Z"}
    contents = {"v1": b"rim-v1", "v2": b"rim-v2"}
    history, store = {}, tmp_path / "gce-tcb-intel-rims"
    for day, current, version in ((1, [a, b], "v1"), (2, [b], "v1"), (3, [b], "v2")):
        monkeypatch.setattr(fe, "fetch_object", lambda name, c=contents[version]: c)
        listing = {**{f"{fe.TDX_PREFIX}{m}.binarypb": meta for m in current},
                   **{f"ovmf_x64_csm/{fw}.fd": meta for fw in ([fw_a, fw_b] if a in current else [fw_b])},
                   **rim_listing(contents[version])}
        records = {f"{fe.TDX_PREFIX}{m}.binarypb": {"result": "verified", "firmware_sha384": fw_b} for m in current}
        fe.update_history(history, listing, records, store, f"day{day}")
        if day == 2:
            assert history["endorsements"][a]["removed_at"] == "day2"
            assert history["firmware"][fw_a]["removed_at"] == "day2"
    assert "removed_at" not in history["endorsements"][b]
    assert history["endorsements"][b] == {"first_seen": "day1", "bucket_created": meta["timeCreated"],
                                          "result": "verified", "firmware_sha384": fw_b}
    versions = history["intel_rims"]["intel_rims/rim.textproto"]["retained_versions"]
    assert [v["at"] for v in versions] == ["day1", "day3"]
    assert versions[1]["from_md5"] == rim_listing(b"rim-v1")["intel_rims/rim.textproto"]["md5Hash"]
    assert (tmp_path / versions[1]["path"]).read_bytes() == b"rim-v2"
    before = json.dumps(history, sort_keys=True)
    fe.update_history(history, listing, records, store, "day4")
    assert json.dumps(history, sort_keys=True) == before, "an unchanged bucket must not change the history"


def test_rim_download_md5_mismatch_raises(tmp_path, monkeypatch):
    monkeypatch.setattr(fe, "fetch_object", lambda name: b"served-bytes")
    with pytest.raises(ValueError, match="listing md5"):
        fe.update_history({}, rim_listing(b"listed-bytes"), {}, tmp_path, "now")


def test_committed_history_is_consistent():
    history = json.loads((REPO / "data/gce-tcb-endorsements.json").read_text())
    assert history["endorsements"] and all(e["result"] == "verified" for e in history["endorsements"].values())
    for name, entry in history["intel_rims"].items():
        latest = entry["retained_versions"][-1]
        content = (REPO / "data" / latest["path"]).read_bytes()
        assert base64.b64encode(hashlib.md5(content).digest()).decode() == entry["md5"], name


def test_main_writes_diff_verification_and_history(tmp_path, monkeypatch):
    objects = {fe.TDX_PREFIX + f: (FIXTURES / "endorsements" / f).read_bytes() for f in REAL}
    objects["intel_rims/rim.textproto"] = b"rim"
    listing = {**{n: dict(m, size="1") for n, m in LISTING.items()}, **rim_listing(b"rim")}
    monkeypatch.setattr(fe, "listing", lambda: listing)
    monkeypatch.setattr(fe, "fetch_object", objects.__getitem__)
    bad = bytearray(objects[fe.TDX_PREFIX + REAL[0]])
    bad[-1] ^= 1
    objects[fe.TDX_PREFIX + REAL[0]] = bytes(bad)
    out, history = tmp_path / "report.txt", tmp_path / "data/gce-tcb-endorsements.json"
    history.parent.mkdir()
    monkeypatch.setattr(sys, "argv", ["x", "--snapshots", str(tmp_path / "snaps"), "--history", str(history),
                                      "--output", str(out)])
    fe.main()
    report = out.read_text()
    assert "FIRST SNAPSHOT" in report
    assert f"{len(REAL) - 1}/{len(REAL)} TDX endorsements verified" in report
    assert f"VERIFY FAILED {fe.TDX_PREFIX}{REAL[0]}: signature fail" in report
    h = json.loads(history.read_text())
    assert set(h["endorsements"]) == {f.removesuffix(".binarypb") for f in REAL}
    assert (history.parent / h["intel_rims"]["intel_rims/rim.textproto"]["retained_versions"][0]["path"]).read_bytes() == b"rim"
