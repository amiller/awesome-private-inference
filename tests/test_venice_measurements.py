"""Venice verifier controls against the 2026-11-05 live capture.

tests/fixtures/venice_tee_attestation_e2ee-glm-5-1.json is a verbatim
unauthenticated capture from https://api.venice.ai/api/v1/tee/attestation
(2026-11-05T20:30:09Z). Transport (Phala verifier, dcap collateral) is mocked;
the quote, event log, vm_config and app_compose are the real captured bytes.
"""
import json
from pathlib import Path

import pytest

from verifiers import dstack_tdx, venice

FIXTURE = (Path(__file__).resolve().parents[1] / "tests" / "fixtures"
           / "venice_tee_attestation_e2ee-glm-5-1.json")


def _capture():
    return json.loads(FIXTURE.read_text())["response"]


def _patch(monkeypatch, att, dcap_status="UpToDate", dcap_error=None):
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

    async def appraisal(q):
        if dcap_error:
            raise dcap_error
        return {"tcb_status": dcap_status, "advisory_ids": []}

    monkeypatch.setattr(venice, "_local_dcap_appraisal", appraisal)


def _verify(monkeypatch, att, **kw):
    _patch(monkeypatch, att, **kw)
    return venice.verify("key", venice.DEFAULT_BASE_URL, "e2ee-glm-5-1")


def test_live_capture_passes_measurement_layers(monkeypatch):
    report = _verify(monkeypatch, _capture())
    sc = report.scorecard
    assert sc.tdx_verified is True
    assert sc.event_log_replayed is True
    assert sc.tee_debug_disabled is True
    assert sc.boot_registers_derived is True  # vm_config exposes the shape
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


def test_dcap_failure_is_recorded_not_swallowed(monkeypatch):
    report = _verify(monkeypatch, _capture(),
                     dcap_error=RuntimeError("PCS unreachable"))
    assert report.scorecard.tcb_current is None
    assert "PCS unreachable" in report.details["dcap_appraisal"]["error"]


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
    assert report.scorecard.boot_registers_derived is False

def test_vm_config_shape_swap_fails_boot_registers(monkeypatch):
    att = json.loads(json.dumps(_capture()))
    vc = json.loads(att["attestation"]["evidence"]["vm_config"])
    vc["cpu_count"] = 8
    att["attestation"]["evidence"]["vm_config"] = json.dumps(vc)
    report = _verify(monkeypatch, att)
    assert report.scorecard.boot_registers_derived is False
    assert any("not pinned" in r for r in report.details["measurements"]
               ["boot_registers"]["reasons"])


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
    assert sc.boot_registers_derived is None
    assert sc.tee_debug_disabled is True  # the quote itself still carries the bit
    assert sc.tcb_current is True
