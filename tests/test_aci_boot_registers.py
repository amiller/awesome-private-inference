"""Boot-register policy and retained-evidence replay for the ACI shape.

Retained real evidence: data/observations/evidence/sha256/01680c7c…json
(tee.redpill.ai workload captured by the daily probe) and the OS image
metadata members captured 2026-11-05 from
https://download.dstack.org/os-images/mr_bd369a8c….tar.gz
(tests/fixtures/os-image-bd369a8c-metadata.tar.gz). Only transport
(the gateway, Phala's verifier and Intel collateral) is mocked; every
digest, signature, register and archive member is the real thing.
"""
import hashlib
import io
import json
import pathlib

import pytest

from verifiers import aci

EVIDENCE = pathlib.Path("data/observations/evidence/sha256/"
                        "01680c7c66c808ee8217f411d3654109c0097a10dbdede218ae3f8b2d3db2400.json")
OS_IMAGE_FIXTURE = pathlib.Path(__file__).parent / "fixtures" / "os-image-bd369a8c-metadata.tar.gz"
RECORDED_TCB = {"tcb_status": "UpToDate", "advisory_ids": [],
                "source": "dcap-qvl local verification (recorded live 2026-11-05)"}


def _retained_evidence():
    return json.loads(EVIDENCE.read_text())


def _replay(monkeypatch, *, evidence=None, quote_body=None, policy_entries=None,
            host=None, catalog=None, tcb=None):
    """Run aci.verify() over the retained evidence, mocking only transport."""
    evidence = evidence or _retained_evidence()
    body = dict(quote_body if quote_body is not None
                else evidence["appraisal"]["body"])
    host = host or "tee.redpill.ai"
    policy = aci.load_boot_register_policy()
    if policy_entries is not None:
        policy = {**policy, "entries": policy_entries}
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
        Mock(json=lambda: envelope),
        Mock(json=lambda: catalog if catalog is not None else {"data": ["m"]})]))
    monkeypatch.setattr(aci, "verify_tdx_quote",
                        lambda value: {"quote": {"verified": True, "body": body}})
    monkeypatch.setattr(aci, "quote_body", lambda value: body)
    monkeypatch.setattr(aci, "is_verified", lambda value: True)
    def _tcb(_quote):
        if isinstance(tcb, Exception):
            raise tcb
        return dict(tcb if tcb is not None else RECORDED_TCB)
    monkeypatch.setattr(aci, "_tcb_status_for_quote", _tcb)
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
    aci._os_image_is_production.cache_clear()
    monkeypatch.setattr(aci, "load_boot_register_policy", lambda path=aci.BOOT_REGISTER_POLICY: policy)
    return aci.verify("", "", host)


def test_policy_pins_the_independently_derived_registers():
    # The pinned set must stay identical to the recorded dstack-mr derivation
    # (research/dstack-mr-derivation-2026-11-05/derived-registers.json), which
    # was computed from the published image before any comparison.
    derived = json.loads((pathlib.Path("research/dstack-mr-derivation-2026-11-05") /
                          "derived-registers.json").read_text())
    policy = aci.load_boot_register_policy()
    assert len(policy["entries"]) == 1
    entry = policy["entries"][0]
    assert entry["os_image_hash"] == "bd369a8c2f9edb2b52dad48ac8e0b32dde5f1337c423a506b48d07403a7d8033"
    for register, value in derived.items():
        assert entry[register] == value


def test_retained_accepted_example_replays_green(monkeypatch):
    report = _replay(monkeypatch)
    assert report.valid is True
    assert report.details["verification_status"] == "verified"
    assert report.scorecard.boot_registers_match_pinned is True
    assert report.scorecard.prod_os_image is True
    assert report.scorecard.os_image_archive_declares_production is True
    assert report.scorecard.nonce_bound is True
    assert report.scorecard.report_data_binds_key is True
    assert report.details["tcb_status"] == "UpToDate"
    assert report.details["advisory_ids"] == []
    assert report.details["boot_registers"]["os_image_hash"].startswith("bd369a8c")


@pytest.mark.parametrize("register", ["mrtd", "rtmr0", "rtmr1", "rtmr2"])
def test_each_tampered_register_is_rejected_independently(monkeypatch, register):
    evidence = _retained_evidence()
    body = dict(evidence["appraisal"]["body"])
    original = body[register].removeprefix("0x")
    body[register] = "0x" + ("0" if original[0] != "0" else "1") + original[1:]
    report = _replay(monkeypatch, quote_body=body)
    assert report.valid is False
    assert report.scorecard.boot_registers_match_pinned is False
    assert report.scorecard.prod_os_image is False
    assert report.details["verification_status"] == "rejected"
    assert register in report.details["boot_registers"]["mismatched_registers"]
    assert report.details["boot_registers"]["expected"][register] == original


def test_tampered_expected_policy_is_rejected(monkeypatch):
    policy = aci.load_boot_register_policy()
    entry = json.loads(json.dumps(policy["entries"][0]))
    entry["rtmr2"] = "0" * 94 + "ff"
    report = _replay(monkeypatch, policy_entries=[entry])
    assert report.scorecard.boot_registers_match_pinned is False
    assert report.details["verification_status"] == "rejected"
    assert "rtmr2" in report.details["boot_registers"]["mismatched_registers"]


def test_genuine_quote_for_unapproved_boot_image_is_rejected(monkeypatch):
    # Same genuine retained quote, but the policy pins nothing for its image:
    # an unapproved boot image must be rejected with a reason, never N/A.
    report = _replay(monkeypatch, policy_entries=[])
    assert report.scorecard.boot_registers_match_pinned is False
    assert report.scorecard.prod_os_image is False
    assert report.details["verification_status"] == "rejected"
    assert report.details["boot_registers"]["status"] == \
        "no pinned boot-register expectations for this os image"


def test_unpinned_vm_shape_is_rejected_not_na(monkeypatch):
    evidence = _retained_evidence()
    vm_config = json.loads(evidence["vm_config"])
    vm_config["cpu_count"] = 33
    evidence = {**evidence, "vm_config": json.dumps(vm_config)}
    report = _replay(monkeypatch, evidence=evidence)
    assert report.scorecard.boot_registers_match_pinned is False
    assert report.details["verification_status"] == "rejected"
    assert report.details["boot_registers"]["status"] == "vm shape is not in the pinned policy"
    assert report.details["boot_registers"]["shape_mismatch"]["cpu_count"] == (33, 32)


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
    assert report.details["verification_status"] == "rejected"


def test_hostname_outside_measured_tee_only_domains(monkeypatch):
    report = _replay(monkeypatch, host="api.redpill.ai")
    assert "api.redpill.ai" not in report.details["tee_only_domains"]
    assert report.scorecard.attested_serving_enforced is False
    assert report.details["verification_status"] == "rejected"
    assert report.valid is False


def test_tcb_status_is_retained_verbatim(monkeypatch):
    report = _replay(monkeypatch, tcb={"tcb_status": "OutOfDate",
                                      "advisory_ids": ["INTEL-SA-01192"],
                                      "source": "dcap-qvl local verification"})
    assert report.details["tcb_status"] == "OutOfDate"
    assert report.details["advisory_ids"] == ["INTEL-SA-01192"]
    assert report.scorecard.tdx_verified is True  # status retained, not folded into a boolean


def test_tcb_failure_propagates_instead_of_null(monkeypatch):
    def boom(quote):
        raise RuntimeError("collateral fetch failed")
    with pytest.raises(RuntimeError):
        _replay(monkeypatch, tcb=RuntimeError("collateral fetch failed"))


def test_vm_config_with_unmodeled_measurement_fields_is_rejected(monkeypatch):
    evidence = _retained_evidence()
    vm_config = json.loads(evidence["vm_config"])
    vm_config["swtpm"] = True
    report = _replay(monkeypatch, evidence={**evidence, "vm_config": json.dumps(vm_config)})
    assert report.scorecard.boot_registers_match_pinned is False
    assert report.details["boot_registers"]["status"] == \
        "vm config carries measurement inputs the pinned shape does not model"
    assert report.details["boot_registers"]["unmodeled_fields"] == {"swtpm": True}


def test_malformed_policy_is_rejected_by_the_loader(tmp_path):
    import json as jsonlib
    policy = aci.load_boot_register_policy()
    entry = policy["entries"][0]
    for mutation in ({"mrtd": "short"}, {"rtmr0": "z" * 96}, {"os_image_hash": "abc"},
                     {"vm_shape": {"cpu_count": 32, "unmodeled": 1}}):
        broken = jsonlib.loads(jsonlib.dumps(entry)); broken.update(mutation)
        path = tmp_path / "broken.json"
        path.write_text(jsonlib.dumps({**policy, "entries": [broken]}))
        with pytest.raises(ValueError):
            aci.load_boot_register_policy(str(path))
