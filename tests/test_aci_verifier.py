"""The ACI shape's own arithmetic, checked against fixed vectors rather than the network."""
import hashlib
import io
import json
import tarfile
from unittest.mock import Mock

from verifiers import aci
from verifiers.common import REQUIRED_LAYERS_BY_SHAPE


def test_statement_binding_matches_spec_template():
    # spec/aci.md §3.2: exact bytes, this field order, no whitespace.
    digest = "sha256:" + "ab" * 32
    nonce = "cd" * 32
    statement = '{"keyset_digest":"%s","nonce":"%s","purpose":"aci.report_data.v1"}' % (digest, nonce)
    assert hashlib.sha256(statement.encode()).hexdigest() == hashlib.sha256(
        json.dumps({"keyset_digest": digest, "nonce": nonce,
                    "purpose": aci.PURPOSE}, separators=(",", ":")).encode()).hexdigest()


def test_rtmr3_replay_folds_only_imr3_events():
    log = [{"imr": 0, "digest": "aa" * 48}, {"imr": 3, "digest": "bb" * 48},
           {"imr": 3, "digest": "cc" * 48}]
    expected = bytes(48)
    for digest in ("bb" * 48, "cc" * 48):
        expected = hashlib.sha384(expected + bytes.fromhex(digest)).digest()
    assert aci._replayed_rtmr3(log) == expected.hex()


def test_tee_only_domains_comes_from_the_measured_compose():
    compose = """
services:
  launcher:
    image: example@sha256:abc
configs:
  gateway-config:
    content: |
      {
        "bind": "0.0.0.0:8086",
        "middleware": { "tee_only_domains": ["tee.example.com"] }
      }
"""
    assert aci._tee_only_domains(compose) == ["tee.example.com"]


def test_attested_serving_is_required_by_the_shape():
    # The layer that differs between hostnames on one shared attestation must be
    # required, or the open host would score identically to the TEE-only ones.
    assert "attested_serving_enforced" in REQUIRED_LAYERS_BY_SHAPE["aci-gateway"]


def _event(name, payload):
    kind = 134217729
    digest = hashlib.sha384(kind.to_bytes(4, "little") + b":" + name.encode() +
                            b":" + payload).hexdigest()
    return {"imr": 3, "event_type": kind, "event": name,
            "event_payload": payload.hex(), "digest": digest}


def _verify_fixture(monkeypatch, *, quote_reportdata=None, mutate=None, archive_too_large=False):
    host = "tee.example.test"
    compose = json.dumps({"docker_compose_file": """
configs:
  gateway-config:
    content: '{"middleware":{"tee_only_domains":["tee.example.test"]}}'
"""})
    os_hash = "aa" * 32
    events = [_event("compose-hash", bytes.fromhex(aci.sha256_hex(compose))),
              _event("boot-mr-done", b""),
              _event("os-image-hash", bytes.fromhex(os_hash))]
    keyset = {"keys": []}  # deployed draft keyset shape is immaterial to JCS binding
    keyset_digest = "sha256:" + aci.sha256_hex(aci._jcs(keyset))
    nonce = "00" * 32
    statement = {"keyset_digest": keyset_digest, "nonce": nonce, "purpose": aci.PURPOSE}
    expected = aci.sha256_hex(aci._jcs(statement))
    envelope = {"workload_keyset_digest": keyset_digest, "attestation": {
        "workload_keyset": keyset, "report_data": expected,
        "evidence": {"quote": "mock", "event_log": json.dumps(events),
                     "app_compose": compose,
                     "vm_config": json.dumps({"os_image_hash": os_hash, "image": "prod"})}}}
    quote = {"reportdata": quote_reportdata or expected + "00" * 32,
             "rtmr3": aci._replayed_rtmr3(events)}
    if mutate:
        mutate(envelope, quote)
    monkeypatch.setattr(aci.os, "urandom", lambda n: bytes(n))
    monkeypatch.setattr(aci.requests, "get", Mock(side_effect=[
        Mock(json=lambda: envelope), Mock(json=lambda: {"data": ["model"]})]))
    monkeypatch.setattr(aci, "verify_tdx_quote", lambda value: {"quote": {"verified": True}})
    monkeypatch.setattr(aci, "quote_body", lambda value: quote)
    monkeypatch.setattr(aci, "is_verified", lambda value: True)
    if archive_too_large:
        monkeypatch.setattr(aci, "_os_image_is_production", lambda value: (_ for _ in ()).throw(
            aci.ArchiveTooLarge("cap")))
    else:
        monkeypatch.setattr(aci, "_os_image_is_production", lambda value: True)
    monkeypatch.setattr(aci, "_sessions_carry_evidence", lambda value: (True, "1/1"))
    return aci.verify("", "", host)


def test_aci_accepts_consistent_quoted_bindings(monkeypatch):
    report = _verify_fixture(monkeypatch)
    assert not report.valid  # base OS boot registers are not checked yet
    assert report.details["event_payloads_bound"] is True
    assert report.details["verification_status"] == "not_checked"
    assert report.scorecard.os_image_archive_declares_production is True
    assert report.scorecard.prod_os_image is None
    assert report.scorecard.backend_attested is None
    assert report.scorecard.catalog_serves is None
    assert report.scorecard.sessions_publish_evidence_digests is True


def test_aci_rejects_detached_report_data_counterexample(monkeypatch):
    report = _verify_fixture(monkeypatch, quote_reportdata="00" * 64)
    assert not report.valid
    assert report.scorecard.nonce_bound is False
    assert report.scorecard.report_data_binds_key is False
    assert report.details["verification_status"] == "rejected"
    raw = report.details["raw_evidence"]
    assert raw["quote"] == "mock"
    assert raw["nonce"] == "00" * 32
    assert raw["event_log"] and raw["app_compose"]


def test_aci_rejects_changed_event_payload_with_same_quoted_digest(monkeypatch):
    def mutate(envelope, quote):
        events = json.loads(envelope["attestation"]["evidence"]["event_log"])
        events[0]["event_payload"] = "bb" * 32
        envelope["attestation"]["evidence"]["event_log"] = json.dumps(events)
    report = _verify_fixture(monkeypatch, mutate=mutate)
    assert not report.valid
    assert report.details["event_payloads_bound"] is False


def test_aci_rejects_detached_os_image_hash(monkeypatch):
    def mutate(envelope, quote):
        envelope["attestation"]["evidence"]["vm_config"] = json.dumps(
            {"os_image_hash": "bb" * 32, "image": "prod"})
    report = _verify_fixture(monkeypatch, mutate=mutate)
    assert not report.valid
    assert report.scorecard.os_image_archive_declares_production is False
    assert report.details["verification_status"] == "rejected"


def test_aci_rejects_detached_keyset_digest(monkeypatch):
    def mutate(envelope, quote):
        envelope["attestation"]["workload_keyset"]["keys"].append("unquoted-key")
    report = _verify_fixture(monkeypatch, mutate=mutate)
    assert not report.valid
    assert report.scorecard.report_data_binds_key is False


def test_aci_rejects_duplicate_compose_claim(monkeypatch):
    def mutate(envelope, quote):
        events = json.loads(envelope["attestation"]["evidence"]["event_log"])
        events.append(events[0].copy())
        envelope["attestation"]["evidence"]["event_log"] = json.dumps(events)
        quote["rtmr3"] = aci._replayed_rtmr3(events)
    report = _verify_fixture(monkeypatch, mutate=mutate)
    assert not report.valid
    assert report.scorecard.compose_hash_committed is False


def test_aci_rejects_compose_claim_appended_after_boot(monkeypatch):
    def mutate(envelope, quote):
        events = json.loads(envelope["attestation"]["evidence"]["event_log"])
        events.insert(1, events.pop(0))
        envelope["attestation"]["evidence"]["event_log"] = json.dumps(events)
        quote["rtmr3"] = aci._replayed_rtmr3(events)
    report = _verify_fixture(monkeypatch, mutate=mutate)
    assert report.scorecard.compose_hash_committed is False
    assert report.scorecard.attested_serving_enforced is False
    assert report.details["verification_status"] == "rejected"


def test_aci_archive_size_cap_is_not_a_quote_rejection(monkeypatch):
    report = _verify_fixture(monkeypatch, archive_too_large=True)
    assert report.details["verification_status"] == "not_checked"
    assert report.details["os_archive_metadata_status"] == "size_cap_exceeded"
    assert report.scorecard.os_image_archive_declares_production is None


def test_aci_archive_rejects_oversized_download_before_read(monkeypatch):
    class LargeResponse:
        headers = {"Content-Length": str(aci.MAX_OS_ARCHIVE_BYTES + 1)}
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def read(self, *args): raise AssertionError("oversized archive must not be read")
    monkeypatch.setattr(aci.urllib.request, "urlopen", lambda *a, **k: LargeResponse())
    aci._os_image_is_production.cache_clear()
    import pytest
    with pytest.raises(aci.ArchiveTooLarge):
        aci._os_image_is_production("aa" * 32)


def test_aci_archive_rejects_excessive_expansion(monkeypatch):
    payload = io.BytesIO()
    with tarfile.open(fileobj=payload, mode="w:gz") as archive:
        data = b"x" * 2048
        member = tarfile.TarInfo("large.bin")
        member.size = len(data)
        archive.addfile(member, io.BytesIO(data))

    class CompressedResponse:
        headers = {}
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def read(self, *args): return payload.getvalue()

    monkeypatch.setattr(aci, "MAX_OS_EXPANDED_BYTES", 1024)
    monkeypatch.setattr(aci.urllib.request, "urlopen", lambda *a, **k: CompressedResponse())
    aci._os_image_is_production.cache_clear()
    import pytest
    with pytest.raises(aci.ArchiveTooLarge):
        aci._os_image_is_production("ab" * 32)


def test_aci_manifest_digest_must_name_metadata_file():
    metadata = b'{"is_dev":false}'
    digest = hashlib.sha256(metadata).hexdigest()
    assert aci._manifest_binds_metadata(f"{digest}  metadata.json\n".encode(), metadata)
    assert not aci._manifest_binds_metadata(f"{digest}  unrelated.bin\n".encode(), metadata)
