"""Full-verify controls for the NEAR dstack measurement wiring.

Replays retained real evidence 03fc9bdac… through near_ai.verify(). Transport
is mocked (attestation fetch, Base RPC replayed from the captured block,
anchor = the pinned policy captured with the evidence); dcap-qvl collateral
appraisal is stubbed with a parameterizable status because it needs Intel PCS.
Quotes, event logs and compose preimages are the real retained bytes; every
negative control mutates one authenticated input and asserts the wired layer
rejects it.
"""
import json
from pathlib import Path

import pytest

from verifiers import near_ai

EVIDENCE = (Path(__file__).resolve().parents[1] / "data" / "observations"
            / "evidence" / "sha256"
            / "03fc9bdac69490b0b77366cbabb4644396184d2bbe6de299ec702e992fa30213.json")


def _load():
    return json.loads(EVIDENCE.read_text())


def _fake_check_tdx(status="UpToDate", advisories=None, gateway_status=None):
    from verifiers import dstack_tdx

    async def check(att):
        parsed = dstack_tdx.parse_quote(att["intel_quote"])
        s = gateway_status if (gateway_status and not att.get("model_name")) else status
        return {
            "quote": {"body": {"reportdata": parsed["report_data"],
                               "mrconfig": parsed["mrconfigid"]}},
            "verified": s in ("UpToDate", "OutOfDate"),
            "tcb_status": s,
            "advisory_ids": list(advisories or []),
            "intel_quote": att["intel_quote"],
        }
    return check


def _patch(monkeypatch, evidence, status="UpToDate", advisories=None,
           gateway_status=None):
    monkeypatch.setenv("NEARAI_VERIFIER_PATH", "")
    monkeypatch.setattr(near_ai, "_check_tdx",
                        _fake_check_tdx(status, advisories, gateway_status))
    monkeypatch.setattr(near_ai, "_anchored_model_composes",
                        lambda: evidence["anchor_policy"])

    authorized = {q["compose_hash"] for q in evidence["model_authorization_queries"]
                  if q.get("chain_authorized")}
    gw_query = evidence["gateway_authorization_query"]
    if gw_query.get("authorized"):
        authorized.add(gw_query["compose_hash"].removeprefix("0x").lower())
    block = evidence["chain_snapshot"]

    def rpc(method, params):
        if method == "eth_getBlockByNumber":
            return {"number": hex(block["block_number"]), "hash": block["block_hash"]}
        if method == "eth_chainId":
            return hex(block["chain_id"])
        if method == "eth_call":
            return "0x1" if params[0]["data"][10:].lower() in authorized else "0x0"
        if method in ("eth_getCode",):
            return "0x" + "60" * 32
        if method == "eth_getStorageAt":
            return "0x0"
        raise AssertionError(method)

    monkeypatch.setattr(near_ai, "_rpc", rpc)

    class Resp:
        status_code = 200

        def json(self):
            return {"gateway_attestation": evidence["gateway_attestation"],
                    "model_attestations": evidence["model_attestations"],
                    "tls_certificate": evidence.get("tls_certificate")}

    monkeypatch.setattr(near_ai.requests, "get", lambda *a, **k: Resp())
    # report_data embeds the captured nonce, so send that nonce
    monkeypatch.setattr(near_ai.secrets, "token_hex", lambda n: evidence["nonce"])


def _verify(monkeypatch, evidence, **status_kwargs):
    _patch(monkeypatch, evidence, **status_kwargs)
    return near_ai.verify("key", "https://cloud-api.near.ai", evidence["requested_model"])


def test_retained_evidence_replays_with_new_layers_true(monkeypatch):
    evidence = _load()
    report = _verify(monkeypatch, evidence)
    sc = report.scorecard
    # Measurement layers all pass on the real captured quotes and logs.
    assert sc.tdx_verified is True
    assert sc.event_log_replayed is True
    assert sc.tee_debug_disabled is True
    assert sc.tcb_current is True
    # This capture honestly fails the compose policy: served model differs from
    # the request and its compose is not in the pinned anchor (anchored=false
    # in the retained authorization query). Those layers must stay False.
    assert sc.compose_hash_committed is False
    assert report.details["verification_status"] == "rejected"
    # per-quote TCB evidence retained
    assert report.details["tdx"]["gateway"]["tcb_status"] == "UpToDate"
    assert report.details["tdx"]["models"][0]["tcb_status"] == "UpToDate"
    assert report.details["tcb_policy"]["passing_status"] == ["UpToDate"]
    gw_meas = report.details["tdx"]["gateway"]["measurements"]
    assert gw_meas["ok"] and gw_meas["replay_matches_quote"]
    assert len(gw_meas["registers"]["mrtd"]) == 96
    assert gw_meas["debug_disabled"] is True
    assert gw_meas["log_compose_hash"] == gw_meas["detached_json_disagreements"] == {} \
        or not gw_meas["detached_json_disagreements"]
    # gateway image da9a3d5c… is published: pins match, but RTMR0 is un-pinnable
    # without vm_config, so the layer honestly fails with that reason.
    assert report.scorecard.boot_registers_derived is False
    gw_boot = gw_meas["boot_registers"]
    assert gw_boot["per_register"] == {"mrtd": True, "rtmr1": True,
                                       "rtmr2": True, "rtmr0": None}
    assert any("vm_config" in r for r in gw_boot["reasons"])
    # model image a6eafc5f… has no published archive: rejected with that reason
    m_boot = report.details["tdx"]["models"][0]["measurements"]["boot_registers"]
    assert m_boot["ok"] is False
    assert any("no pinned derivation" in r for r in m_boot["reasons"])


def test_outofdate_gateway_flips_tcb_current_and_keeps_advisories(monkeypatch):
    evidence = _load()
    report = _verify(monkeypatch, evidence, gateway_status="OutOfDate",
                     advisories=["INTEL-SA-01192"])
    assert report.scorecard.tcb_current is False
    assert report.scorecard.tdx_verified is True  # signature appraisal still passed
    assert report.details["tdx"]["gateway"]["tcb_status"] == "OutOfDate"
    assert report.details["tdx"]["gateway"]["advisory_ids"] == ["INTEL-SA-01192"]
    assert report.details["tdx"]["models"][0]["tcb_status"] == "UpToDate"
    assert report.details["tcb_statuses"]["gateway"] == "OutOfDate"


@pytest.mark.parametrize("status", ["SWHardeningNeeded", "Revoked",
                                    "ConfigurationAndSWHardeningNeeded"])
def test_verdicts_that_fail_appraisal_reject_the_row(monkeypatch, status):
    """UpToDate/OutOfDate are the only statuses dcap appraisal accepts (ported
    upstream semantics); every other verdict rejects the quote outright, which
    subsumes the currency policy for those."""
    evidence = _load()
    report = _verify(monkeypatch, evidence, status=status)
    assert report.error == "gateway TDX quote did not verify"
    assert report.details["gateway_intel"]["tcb_status"] == status
    assert report.details["verification_status"] == "rejected"


def test_debug_bit_flip_in_gateway_quote_fails_only_debug_layer(monkeypatch):
    evidence = _load()
    tampered = json.loads(json.dumps(evidence))
    quote = tampered["gateway_attestation"]["intel_quote"]
    raw = bytearray(bytes.fromhex(quote))
    raw[168] |= 0x01  # TD_ATTRIBUTES debug bit (byte 0, bit 0)
    tampered["gateway_attestation"]["intel_quote"] = raw.hex()
    report = _verify(monkeypatch, tampered)
    assert report.scorecard.tee_debug_disabled is False
    assert report.scorecard.event_log_replayed is True  # registers untouched
    assert report.details["tdx"]["gateway"]["measurements"]["debug_disabled"] is False


def test_event_log_tamper_fails_replay_and_compose(monkeypatch):
    evidence = _load()
    tampered = json.loads(json.dumps(evidence))
    log = tampered["model_attestations"][0]["info"]["tcb_info"]["event_log"]
    for entry in log:
        if entry.get("event") == "compose-hash":
            entry["event_payload"] = "ff" + entry["event_payload"][2:]
    report = _verify(monkeypatch, tampered)
    assert report.scorecard.event_log_replayed is False
    assert report.scorecard.compose_hash_committed is False
    m_meas = report.details["tdx"]["models"][0]["measurements"]
    assert m_meas["ok"] is False and "does not match" in m_meas["error"]


def test_detached_json_disagreement_with_log_fails_replay(monkeypatch):
    evidence = _load()
    tampered = json.loads(json.dumps(evidence))
    tcb = tampered["model_attestations"][0]["info"]["tcb_info"]
    tcb["compose_hash"] = "ab" * 32  # log still replays; detached claim now lies
    report = _verify(monkeypatch, tampered)
    assert report.scorecard.event_log_replayed is False
    m_meas = report.details["tdx"]["models"][0]["measurements"]
    assert m_meas["detached_json_disagreements"]["compose_hash"]["log"] != \
        m_meas["detached_json_disagreements"]["compose_hash"]["detached"]


def test_rtmr3_tamper_in_quote_breaks_replay_equality(monkeypatch):
    evidence = _load()
    tampered = json.loads(json.dumps(evidence))
    quote = tampered["gateway_attestation"]["intel_quote"]
    raw = bytearray(bytes.fromhex(quote))
    raw[520] ^= 0x08  # RTMR3 first byte
    tampered["gateway_attestation"]["intel_quote"] = raw.hex()
    report = _verify(monkeypatch, tampered)
    assert report.scorecard.event_log_replayed is False
    assert "rtmr3" in report.details["tdx"]["gateway"]["measurements"]["error"]
