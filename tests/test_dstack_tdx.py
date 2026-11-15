"""Offline controls for dstack TDX quote parsing and event-log replay.

Runs against retained real evidence (data/observations/evidence): the NEAR
capture 03fc9bdac… holds gateway and model-CVM quotes plus full event logs.
Negative controls mutate one authenticated input at a time and assert the
check rejects it.
"""
from pathlib import Path

import pytest

from verifiers import dstack_tdx

EVIDENCE = (Path(__file__).resolve().parents[1] / "data" / "observations"
            / "evidence" / "sha256"
            / "03fc9bdac69490b0b77366cbabb4644396184d2bbe6de299ec702e992fa30213.json")

# TDX quote v4 body offsets (bytes), stable across both retained quotes.
OFF_TD_ATTRS = 168
OFF_MRTD = 184
OFF_RTMR = {0: 376, 1: 424, 2: 472, 3: 520}


def _attestations():
    import json
    d = json.loads(EVIDENCE.read_text())
    return [("gateway", d["gateway_attestation"]),
            *[(f"model{i}", m) for i, m in enumerate(d["model_attestations"])]]


def _flip_byte(quote_hex: str, offset: int, bit: int = 0) -> str:
    raw = bytearray(bytes.fromhex(quote_hex))
    raw[offset] ^= 1 << bit
    return raw.hex()


def test_parse_quote_returns_all_fields_for_real_quotes():
    for _, att in _attestations():
        fields = dstack_tdx.parse_quote(att["intel_quote"])
        for name in ("mrtd", "rtmr0", "rtmr1", "rtmr2", "rtmr3", "mrseam"):
            assert len(fields[name]) == 96
        assert len(fields["td_attributes"]) == 16
        assert fields["report_data"]


def test_replay_matches_all_four_quote_rtmrs():
    for name, att in _attestations():
        log = att["info"]["tcb_info"]["event_log"]
        replayed = dstack_tdx.replayed_registers(log)
        quoted = dstack_tdx.parse_quote(att["intel_quote"])
        for i in range(4):
            assert replayed[f"rtmr{i}"] == quoted[f"rtmr{i}"], (name, i)
        assert dstack_tdx.covered_imrs(log) == {0, 1, 2, 3}


def test_debug_bit_clear_on_real_quotes_and_set_when_flipped():
    for name, att in _attestations():
        assert dstack_tdx.tee_debug_disabled(
            dstack_tdx.parse_quote(att["intel_quote"])["td_attributes"]) is True, name
        tampered = _flip_byte(att["intel_quote"], OFF_TD_ATTRS, bit=0)
        assert dstack_tdx.tee_debug_disabled(
            dstack_tdx.parse_quote(tampered)["td_attributes"]) is False, name


@pytest.mark.parametrize("register", ["rtmr0", "rtmr1", "rtmr2", "rtmr3"])
def test_replayed_register_mismatch_is_visible(register):
    """Flipping the quoted register breaks equality with the replayed log."""
    for _, att in _attestations():
        replayed = dstack_tdx.replayed_registers(att["info"]["tcb_info"]["event_log"])
        quoted = dstack_tdx.parse_quote(_flip_byte(
            att["intel_quote"], OFF_RTMR[int(register[-1])], bit=3))
        assert quoted[register] != replayed[register]


def test_runtime_events_carry_authenticated_values():
    for _, att in _attestations():
        log = att["info"]["tcb_info"]["event_log"]
        compose = dstack_tdx.single_runtime_event(log, "compose-hash")
        app_id = dstack_tdx.single_runtime_event(log, "app-id")
        os_image = dstack_tdx.single_runtime_event(log, "os-image-hash")
        assert len(compose) == 64 and len(os_image) == 64
        assert len(app_id) == 40
        # The detached JSON info must agree with the replayed log, and does here.
        assert compose == att["info"]["tcb_info"]["compose_hash"].removeprefix("0x").lower()
        assert app_id == att["info"]["app_id"].removeprefix("0x").lower()
        assert os_image == att["info"]["tcb_info"]["os_image_hash"].removeprefix("0x").lower()


def test_runtime_event_digest_rejects_tampered_payload():
    log = _attestations()[0][1]["info"]["tcb_info"]["event_log"]
    for entry in log:
        if entry.get("event") == "compose-hash":
            tampered = dict(entry)
            tampered["event_payload"] = "ff" + tampered["event_payload"][2:]
            with pytest.raises(dstack_tdx.EventLogError, match="does not match"):
                dstack_tdx.replay_event_log([tampered])
            return
    raise AssertionError("no compose-hash event in fixture")


def test_runtime_event_digest_rejects_missing_entry():
    log = _attestations()[0][1]["info"]["tcb_info"]["event_log"]
    stripped = [e for e in log if e.get("event") != "compose-hash"]
    with pytest.raises(dstack_tdx.EventLogError, match="exactly one"):
        dstack_tdx.single_runtime_event(stripped, "compose-hash")


def test_replay_rejects_dropped_and_added_events():
    _, att = _attestations()[0]
    quoted = dstack_tdx.parse_quote(att["intel_quote"])
    log = att["info"]["tcb_info"]["event_log"]
    # dropping any event changes the replay
    for i in range(len(log)):
        dropped = log[:i] + log[i + 1:]
        if dstack_tdx.covered_imrs(dropped) == {0, 1, 2, 3}:
            replayed = dstack_tdx.replayed_registers(dropped)
            assert any(replayed[f"rtmr{k}"] != quoted[f"rtmr{k}"] for k in range(4))
    # replaying a runtime event twice changes RTMR3
    twice = log + [dict(e) for e in log if e.get("event") == "system-ready"]
    assert dstack_tdx.replayed_registers(twice)["rtmr3"] != quoted["rtmr3"]


def test_replay_rejects_out_of_range_imr_and_bad_hex():
    log = _attestations()[0][1]["info"]["tcb_info"]["event_log"]
    bad_imr = dict(log[0], imr=4)
    with pytest.raises(dstack_tdx.EventLogError, match="out of range"):
        dstack_tdx.replay_event_log([bad_imr])
    bad_digest = dict(log[0], digest="zz")
    with pytest.raises(dstack_tdx.EventLogError, match="stored digest"):
        dstack_tdx.replay_event_log([bad_digest])


def test_parse_quote_rejects_truncated_quote():
    with pytest.raises(Exception):
        dstack_tdx.parse_quote("0400")
