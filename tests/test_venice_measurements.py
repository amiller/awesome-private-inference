"""Venice verifier controls against the 2026-11-05 live capture.

tests/fixtures/venice_tee_attestation_e2ee-glm-5-1.json is a verbatim
unauthenticated capture from https://api.venice.ai/api/v1/tee/attestation
(2026-11-05T20:30:09Z). Transport (Phala verifier, dcap collateral) is mocked;
the quote, event log, vm_config and app_compose are the real captured bytes.
"""
import json
from pathlib import Path

from types import SimpleNamespace

import pytest

from verifiers import dstack_tdx, venice

FIXTURE = (Path(__file__).resolve().parents[1] / "tests" / "fixtures"
           / "venice_tee_attestation_e2ee-glm-5-1.json")


def _capture():
    return json.loads(FIXTURE.read_text())["response"]


def _patch(monkeypatch, att, dcap_status="UpToDate"):
    parsed = dstack_tdx.parse_quote(att["intel_quote"] or att["attestation"]["evidence"]["quote"])

    class Resp:
        status_code = 200

        def json(self):
            return att

    monkeypatch.setattr(venice.requests, "get", lambda *a, **k: Resp())
    monkeypatch.setattr(venice.secrets, "token_hex", lambda n: att["nonce"])
    monkeypatch.setattr(venice.phala_tdx, "verify_tdx_quote",
                        lambda q: {"quote": {"verified": True, "body": {
                            "reportdata": parsed["report_data"],
                            "mrconfig": parsed["mrconfigid"],
                            "rtmr3": parsed["rtmr3"]},
                            "tcb_status": None}})

    monkeypatch.setattr(venice.dstack_tdx, "dcap_verify",
                        lambda q: SimpleNamespace(status=dcap_status, advisory_ids=[]))


def _verify(monkeypatch, att, **kw):
    _patch(monkeypatch, att, **kw)
    return venice.verify("key", venice.DEFAULT_BASE_URL, "e2ee-glm-5-1")


def test_live_capture_passes_measurement_layers(monkeypatch):
    report = _verify(monkeypatch, _capture())
    sc = report.scorecard
    assert sc.tdx_verified is True
    assert sc.event_log_replayed is True
    assert sc.tee_debug_disabled is True
    assert sc.tee_boot_config is True
    assert sc.tee_hardware_config is True
    assert sc.compose_hash_committed is True
    assert sc.tcb_current is True
    assert report.details["phala_tcb_status"] is None  # Phala returns no verdict
    assert report.details["dcap_appraisal"]["tcb_status"] == "UpToDate"
    assert report.details["api_version"] == "aci/1"
    assert report.details["vm_config"]["os_image_hash"].startswith("bd369a8c")


def test_outofdate_dcap_verdict_fails_tcb_current(monkeypatch):
    report = _verify(monkeypatch, _capture(), dcap_status="OutOfDate")
    assert report.scorecard.tcb_current is False
    assert report.scorecard.tdx_verified is True  # Phala appraisal unaffected


def test_dcap_failure_propagates(monkeypatch):
    _patch(monkeypatch, _capture())

    def unreachable(q):
        raise RuntimeError("PCS unreachable")
    monkeypatch.setattr(venice.dstack_tdx, "dcap_verify", unreachable)
    with pytest.raises(RuntimeError, match="PCS unreachable"):
        venice.verify("key", venice.DEFAULT_BASE_URL, "e2ee-glm-5-1")


def test_debug_bit_flip_fails_debug_layer(monkeypatch):
    att = json.loads(json.dumps(_capture()))
    raw = bytearray(bytes.fromhex(att["attestation"]["evidence"]["quote"]))
    raw[168] |= 0x01
    att["attestation"]["evidence"]["quote"] = raw.hex()
    att["intel_quote"] = raw.hex()
    report = _verify(monkeypatch, att)
    assert report.scorecard.tee_debug_disabled is False
    assert report.scorecard.event_log_replayed is True  # registers untouched


def test_quote_duplicate_disagreement_is_rejected(monkeypatch):
    att = json.loads(json.dumps(_capture()))
    raw = bytearray(bytes.fromhex(att["attestation"]["evidence"]["quote"]))
    raw[168] |= 0x01
    att["intel_quote"] = raw.hex()  # evidence.quote keeps the real bytes
    report = _verify(monkeypatch, att)
    assert report.error == "top-level quote disagrees with attestation.evidence.quote"
    assert report.scorecard.tee_debug_disabled is None


def test_event_log_tamper_fails_replay_compose_and_boot(monkeypatch):
    att = json.loads(json.dumps(_capture()))
    log = json.loads(att["attestation"]["evidence"]["event_log"])
    for entry in log:
        if entry.get("event") == "compose-hash":
            entry["event_payload"] = "ff" + entry["event_payload"][2:]
    att["attestation"]["evidence"]["event_log"] = json.dumps(log)
    report = _verify(monkeypatch, att)
    assert report.scorecard.event_log_replayed is False
    assert report.scorecard.compose_hash_committed is not True
    assert report.scorecard.tee_boot_config is False
    assert report.scorecard.tee_hardware_config is False
    assert report.scorecard.tee_debug_disabled is True  # read from the quote alone


def test_debug_bit_survives_replay_failure(monkeypatch):
    att = json.loads(json.dumps(_capture()))
    raw = bytearray(bytes.fromhex(att["attestation"]["evidence"]["quote"]))
    raw[168] |= 0x01
    raw[520] ^= 0x08  # RTMR3: replay now fails too
    att["attestation"]["evidence"]["quote"] = att["intel_quote"] = raw.hex()
    report = _verify(monkeypatch, att)
    assert report.scorecard.event_log_replayed is False
    assert report.scorecard.tee_debug_disabled is False


def test_os_image_hash_disagreement_between_log_and_vm_config(monkeypatch):
    att = json.loads(json.dumps(_capture()))
    vc = json.loads(att["attestation"]["evidence"]["vm_config"])
    vc["os_image_hash"] = "ab" * 32
    att["attestation"]["evidence"]["vm_config"] = json.dumps(vc)
    report = _verify(monkeypatch, att)
    assert report.scorecard.event_log_replayed is False
    assert report.details["measurements"]["detached_json_disagreements"][
        "os_image_hash"]["log"].startswith("bd369a8c")


def test_quote_rtmr_tamper_fails_replay(monkeypatch):
    att = json.loads(json.dumps(_capture()))
    raw = bytearray(bytes.fromhex(att["attestation"]["evidence"]["quote"]))
    raw[376] ^= 0x10  # RTMR0
    att["attestation"]["evidence"]["quote"] = raw.hex()
    att["intel_quote"] = raw.hex()
    report = _verify(monkeypatch, att)
    assert report.scorecard.event_log_replayed is False
    assert "does not replay" in report.details["measurements"]["error"]


def test_legacy_shape_reports_layers_unproven(monkeypatch):
    legacy = {"intel_quote": _capture()["attestation"]["evidence"]["quote"],
              "nonce": _capture()["nonce"],
              "nonce_source": "client", "tee_provider": "phala",
              "signing_address": "0x79a5061efe5a46b0d1f33b11cf1c5adbedae6b79",
              "signing_public_key": _capture()["signing_public_key"],
              "info": {"tcb_info": {"app_compose": '{"docker_compose_file": ""}'}}}
    report = _verify(monkeypatch, legacy)
    sc = report.scorecard
    assert sc.event_log_replayed is None
    assert sc.tee_boot_config is None and sc.tee_hardware_config is None
    assert sc.tee_debug_disabled is True  # the quote itself still carries the bit
    assert sc.tcb_current is True


def test_live_capture_binds_gateway_keyset_but_is_not_valid(monkeypatch):
    report = _verify(monkeypatch, _capture())
    sc = report.scorecard
    assert sc.nonce_bound is True
    assert sc.report_data_binds_key is True
    assert sc.key_derives_to_address is True
    assert all(report.details["keyset_binding"].values())
    assert sc.gpu_attested is None
    assert report.details["gpu_evidence_omitted"] is True
    assert report.details["downstream_tls_binding"]["domain"] == "api.redpill.ai"
    assert report.valid is False
    assert report.error is None
    assert report.details["verification_reason"] == venice.GATEWAY_ONLY


@pytest.mark.parametrize("mutation", [
    lambda a: a["service_capabilities"].update(serving=None),
    lambda a: a["service_capabilities"].update(serving="model"),
    lambda a: a.pop("api_version"),
])
def test_unattested_fields_cannot_make_gateway_valid(monkeypatch, mutation):
    att = json.loads(json.dumps(_capture()))
    mutation(att)
    assert _verify(monkeypatch, att).valid is False


def _mutate(path_fn):
    att = json.loads(json.dumps(_capture()))
    path_fn(att)
    return att


@pytest.mark.parametrize("mutation,check", [
    (lambda a: a["attestation"]["workload_keyset"]["e2ee_public_keys"][0].update(
        public_key="04" + "11" * 64), "keyset_digest_recomputes"),
    (lambda a: a.update(workload_keyset_digest="sha256:" + "00" * 32), "keyset_digest_recomputes"),
    (lambda a: a["attestation"]["workload_keyset"].update(e2ee_public_keys=[]), "signing_key_in_keyset"),
    (lambda a: a["attestation"].update(report_data="0x" + "00" * 64), "report_data_echo_matches_quote"),
])
def test_keyset_binding_tamper_fails_report_data_binding(monkeypatch, mutation, check):
    report = _verify(monkeypatch, _mutate(mutation))
    assert report.details["keyset_binding"][check] is False
    assert report.scorecard.report_data_binds_key is False


def test_nonce_echo_mismatch_fails_nonce_binding(monkeypatch):
    report = _verify(monkeypatch, _mutate(lambda a: a.update(nonce="ff" * 32)))
    assert report.scorecard.nonce_bound is False


def test_malformed_signing_key_fails_closed(monkeypatch):
    report = _verify(monkeypatch, _mutate(lambda a: a.update(signing_public_key="04abcd")))
    assert report.scorecard.key_derives_to_address is False
    assert "unexpected pubkey length" in report.details["key_derivation_error"]


def test_unknown_api_version_fails_closed(monkeypatch):
    report = _verify(monkeypatch, _mutate(lambda a: a.update(api_version="aci/2")))
    assert report.error == "unsupported attestation api_version: 'aci/2'"
    assert report.valid is False


def test_aci1_without_evidence_raises(monkeypatch):
    with pytest.raises(KeyError, match="evidence"):
        _verify(monkeypatch, _mutate(lambda a: a["attestation"].pop("evidence")))


def test_404_reports_no_attestation(monkeypatch):
    class Resp:
        status_code = 404
    monkeypatch.setattr(venice.requests, "get", lambda *a, **k: Resp())
    report = venice.verify("key", venice.DEFAULT_BASE_URL, "e2ee-gemma-4-31b")
    assert report.error == "no TEE attestation available for this model (404)"
    assert report.valid is False
