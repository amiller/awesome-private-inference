"""Boot-register policy and retained-evidence replay for the ACI shape.

Retained real evidence: data/observations/evidence/sha256/01680c7c…json
(tee.redpill.ai workload on bd369a8c, 32 vCPU), 2d27859e…json (the same
gateway on 8db40cb2, 16 vCPU, ovmf pre202505) and the OS image
metadata members captured 2026-11-05 from
https://download.dstack.org/os-images/mr_bd369a8c….tar.gz
(tests/fixtures/os-image-bd369a8c-metadata.tar.gz). Only transport
(the gateway, Phala's verifier and Intel collateral) is mocked; every
digest, signature, register and archive member is the real thing.
"""
import hashlib
import json
import pathlib

from types import SimpleNamespace

import pytest

from verifiers import aci, dstack_boot_registers

EVIDENCE = pathlib.Path("data/observations/evidence/sha256/"
                        "01680c7c66c808ee8217f411d3654109c0097a10dbdede218ae3f8b2d3db2400.json")
CURRENT = pathlib.Path("data/observations/evidence/sha256/"
                       "2d27859e220edfc6fb9f45d4e3db62beacc3fb1abf20c12bed363b66b4c4564e.json")
OS_IMAGE_FIXTURE = pathlib.Path(__file__).parent / "fixtures" / "os-image-bd369a8c-metadata.tar.gz"
OFFSETS = {"mrtd": 184, "rtmr0": 376, "rtmr1": 424, "rtmr2": 472}


def _retained_evidence(path=EVIDENCE):
    return json.loads(path.read_text())


def _replay(monkeypatch, *, evidence=None, host=None, tcb_status="UpToDate", archive_prod=None):
    """Run aci.verify() over retained evidence, mocking only transport."""
    evidence = evidence or _retained_evidence()
    body = evidence["appraisal"]["body"]
    envelope = {
        "api_version": evidence["api_version"],
        "workload_id": evidence["workload_id"],
        "workload_keyset_digest": evidence["workload_keyset_digest"],
        "attestation": {
            "workload_keyset": evidence["workload_keyset"],
            "keyset_endorsement": evidence.get("keyset_endorsement"),
            "report_data": evidence["report_data"],
            "source_provenance": evidence.get("source_provenance"),
            "evidence": {
                "quote": evidence["quote"],
                "event_log": json.dumps(evidence["event_log"]),
                "app_compose": evidence["app_compose"],
                "vm_config": evidence["vm_config"],
            },
        },
    }
    from unittest.mock import Mock
    monkeypatch.setattr(aci.os, "urandom", lambda n: bytes.fromhex(evidence["nonce"])[:n])
    monkeypatch.setattr(aci.requests, "get", Mock(side_effect=[
        Mock(json=lambda: envelope), Mock(json=lambda: {"data": ["m"]})]))
    monkeypatch.setattr(aci, "verify_tdx_quote",
                        lambda value: {"quote": {"verified": True, "body": body}})
    monkeypatch.setattr(aci, "quote_body", lambda value: body)
    monkeypatch.setattr(aci, "is_verified", lambda value: True)
    if isinstance(tcb_status, Exception):
        def _tcb(_quote):
            raise tcb_status
    else:
        def _tcb(_quote):
            return SimpleNamespace(status=tcb_status, advisory_ids=["INTEL-SA-01192"]
                                   if tcb_status == "OutOfDate" else [])
    monkeypatch.setattr(aci.dstack_tdx, "dcap_verify", _tcb)
    monkeypatch.setattr(aci, "_sessions_carry_evidence", lambda base: (True, "1/1"))

    class ArchiveResponse:
        headers = {"Content-Length": str(OS_IMAGE_FIXTURE.stat().st_size)}

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self, *args):
            return OS_IMAGE_FIXTURE.read_bytes()

    monkeypatch.setattr(aci.urllib.request, "urlopen", lambda *a, **k: ArchiveResponse())
    monkeypatch.setattr(aci, "_os_image_is_production", (lambda h: archive_prod)
                        if archive_prod is not None else aci._os_image_is_production.__wrapped__)
    return aci.verify("", "", host or "tee.redpill.ai")


def _entry(os_prefix):
    return next(e for e in json.loads(dstack_boot_registers.POLICY_PATH.read_text())["entries"]
                if e["os_image_hash"].startswith(os_prefix))


def test_policy_pins_the_independently_derived_registers():
    derived = json.loads((pathlib.Path("research/dstack-mr-derivation-2026-11-05") /
                          "derived-registers.json").read_text())
    entry = _entry("bd369a8c")
    assert (derived["mrtd"], derived["rtmr0"]) in {(s["mrtd"], s["rtmr0"]) for s in entry["vm_shapes"]}
    assert (derived["rtmr1"], derived["rtmr2"]) == (entry["rtmr1"], entry["rtmr2"])


def test_retained_accepted_example_replays_green(monkeypatch):
    report = _replay(monkeypatch)
    assert report.valid is True
    assert report.details["verification_status"] == "verified"
    assert report.scorecard.tee_boot_config is True
    assert report.scorecard.tee_hardware_config is True
    assert report.scorecard.prod_os_image is True
    assert report.scorecard.os_image_archive_declares_production is True
    assert report.details["tcb_status"] == "UpToDate"
    assert "tcb_status" not in report.details["raw_evidence"]["appraisal"]


def test_current_16_vcpu_gateway_passes_boot_registers(monkeypatch):
    report = _replay(monkeypatch, evidence=_retained_evidence(CURRENT), archive_prod=True)
    assert json.loads(_retained_evidence(CURRENT)["vm_config"])["cpu_count"] == 16
    assert report.scorecard.tee_boot_config is True
    assert report.scorecard.tee_hardware_config is True
    assert report.details["verification_status"] == "verified"


@pytest.mark.parametrize("register", list(OFFSETS))
def test_each_tampered_register_is_rejected(monkeypatch, register):
    evidence = _retained_evidence()
    raw = bytearray(bytes.fromhex(evidence["quote"]))
    raw[OFFSETS[register]] ^= 0x01
    report = _replay(monkeypatch, evidence={**evidence, "quote": raw.hex()})
    assert report.valid is False
    assert report.scorecard.prod_os_image is False
    assert report.details["verification_status"] == "rejected"
    sc = report.scorecard
    assert (sc.tee_boot_config, sc.tee_hardware_config) == {
        "mrtd": (False, False), "rtmr0": (True, False),
        "rtmr1": (False, True), "rtmr2": (False, True)}[register]


def test_genuine_quote_for_unapproved_boot_image_is_rejected(monkeypatch):
    monkeypatch.setattr(dstack_boot_registers, "_policy", lambda: {"revision": "t", "entries": {}})
    report = _replay(monkeypatch)
    assert report.scorecard.tee_boot_config is False
    assert report.scorecard.tee_hardware_config is None
    assert report.scorecard.prod_os_image is False
    assert report.details["verification_status"] == "rejected"
    assert "no pinned derivation" in report.details["verification_reason"]


def test_eventlog_quote_binding_mutation_is_rejected(monkeypatch):
    # Append a well-formed extra IMR3 event: every preimage still hashes to its
    # digest, but the log now replays to a different RTMR3 than the quoted one.
    evidence = _retained_evidence()
    log = json.loads(json.dumps(evidence["event_log"]))
    payload = b"tamper"
    kind = 134217729
    digest = hashlib.sha384(kind.to_bytes(4, "little") + b":extra:" + payload).hexdigest()
    log.append({"imr": 3, "event_type": kind, "event": "extra",
                "event_payload": payload.hex(), "digest": digest})
    report = _replay(monkeypatch, evidence={**evidence, "event_log": log})
    assert report.details["event_payloads_bound"] is True
    assert report.scorecard.compose_hash_committed is False
    assert report.scorecard.tee_boot_config is False
    assert report.details["verification_status"] == "rejected"


def test_hostname_outside_measured_tee_only_domains(monkeypatch):
    report = _replay(monkeypatch, host="api.redpill.ai")
    assert "api.redpill.ai" not in report.details["tee_only_domains"]
    assert report.scorecard.attested_serving_enforced is False
    assert report.details["verification_status"] == "rejected"
    assert report.valid is False


def test_tcb_status_is_retained_verbatim(monkeypatch):
    report = _replay(monkeypatch, tcb_status="OutOfDate")
    assert report.details["tcb_status"] == "OutOfDate"
    assert report.details["advisory_ids"] == ["INTEL-SA-01192"]
    assert report.scorecard.tdx_verified is True


def test_tcb_failure_propagates_instead_of_null(monkeypatch):
    with pytest.raises(RuntimeError, match="collateral"):
        _replay(monkeypatch, tcb_status=RuntimeError("collateral fetch failed"))
