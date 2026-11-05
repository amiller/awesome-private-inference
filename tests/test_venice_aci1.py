"""Venice ACI/1 gateway-format verification against retained live captures.

Fixtures were captured 2026-11-05 from the public endpoint
https://api.venice.ai/api/v1/tee/attestation?model=<id>&nonce=<64 hex>
(the endpoint ignores the Authorization header, so no credential is involved).
The `phala_appraisal_*` fixtures are the retained responses of
cloud-api.phala.network for the captured quotes — including a genuine
`verified: false` appraisal for a one-nibble-tampered quote — so every step
of the chain under test runs on real evidence; only HTTP transport is mocked.

Each passing check has a companion test proving it fails on tampered input.
"""
import json
import os
from copy import deepcopy
from unittest.mock import Mock

import pytest

from verifiers import venice

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def load(name):
    with open(os.path.join(FIXTURES, name)) as fh:
        return json.load(fh)


def aci_fixture(model="e2ee-glm-5-2-p"):
    return load(f"venice_aci1_{model}.json")


def appraisal_for(fixture):
    model = fixture["model"]
    return load(f"venice_aci1_phala_appraisal_{model}.json")


def run_verify(monkeypatch, fixture, *, nonce=None, mutate=None, appraisal=None):
    """Run venice.verify against a retained capture with only transport mocked.

    The Phala transport mock answers only for a quote it holds a retained
    appraisal of, so a response whose quote was swapped cannot be paired with
    another quote's appraisal.
    """
    response = deepcopy(fixture["response"])
    if mutate:
        mutate(response)
    quotes = {}
    if appraisal is None:
        appraisal = appraisal_for(fixture)
    quotes[response.get("attestation", {}).get("evidence", {}).get("quote")
           or response.get("intel_quote")] = appraisal

    def fake_post(url, json=None, timeout=None, **kwargs):
        try:
            body = quotes[json["hex"]]
        except KeyError:
            raise AssertionError("appraisal requested for an unretained quote")
        return Mock(raise_for_status=lambda: None, json=lambda: body)

    monkeypatch.setattr(venice.requests, "get", Mock(return_value=Mock(
        status_code=200, json=lambda: response)))
    monkeypatch.setattr(venice.phala_tdx.requests, "post", fake_post)
    return venice.verify("", "https://api.venice.ai/api/v1", fixture["model"],
                         nonce=nonce or fixture["client_nonce"])


def test_real_aci1_capture_verifies_gateway_bindings():
    fixture = aci_fixture()
    report = run_verify(pytest.MonkeyPatch(), fixture)
    assert report.error is None
    assert report.valid is True
    sc = report.scorecard
    assert sc.tdx_verified is True
    assert sc.nonce_bound is True
    assert sc.report_data_binds_key is True
    assert sc.key_derives_to_address is True
    assert sc.compose_hash_committed is True
    # The gateway/backend distinction is scored, not assumed.
    assert sc.backend_attested is False
    assert sc.gpu_attested is None
    assert report.details["attested_cvm"] == "gateway"
    assert report.details["serving"] == "aggregator"
    assert report.details["num_gpus"] == 0
    assert report.details["gateway_app_id_event"] == \
        "fdb7a14e5a6675f752e2cb69c9067a98ca402918"
    for layer in ("backend_attested", "gpu_attested", "prod_os_image",
                  "serving_code_attested", "code_measurement_reproducible"):
        assert layer in report.details["unproven_reasons"], layer


def test_all_retained_aci1_captures_share_one_gateway_cvm():
    """Six models, one attested CVM: every ACI/1 capture replays to the same
    RTMR3/MRConfigID/MRTD in its retained appraisal, so the attested machine is
    the shared private-ai-gateway, not a per-model inference host.
    e2ee-qwen3-6-35b-a3b-uncensored-p is excluded here: it carries an
    nvidia_payload, whose NRAS verification belongs to another lane."""
    identity = {}
    reference = aci_fixture()
    for fixture in [aci_fixture(m) for m in (
            "e2ee-glm-5-1", "e2ee-glm-5-2-p", "e2ee-glm-5",
            "e2ee-gpt-oss-120b-p", "e2ee-gpt-oss-20b-p")]:
        report = run_verify(pytest.MonkeyPatch(), fixture)
        assert report.valid is True, fixture["model"]
        body = appraisal_body(fixture)
        observed = {
            "signing_address": report.signing_address.lower(),
            "rtmr3": body.get("rtmr3", "").lower(),
            "mrconfig": body.get("mrconfig", "").lower(),
            "mrtd": body.get("mrtd", "").lower(),
            "workload_keyset_digest": report.details["workload_keyset_digest"],
        }
        for field, value in observed.items():
            assert identity.setdefault(field, value) == value, (fixture["model"], field)
        assert observed["workload_keyset_digest"] == \
            reference["response"]["workload_keyset_digest"]


def appraisal_body(fixture):
    appraisal = appraisal_for(fixture)
    return (appraisal.get("quote") or {}).get("body", {})


# ---------------------------------------------------------------------------
# Negative controls: each passing check must fail on tampered input.
# ---------------------------------------------------------------------------

def test_wrong_nonce_is_rejected():
    fixture = aci_fixture()
    report = run_verify(pytest.MonkeyPatch(), fixture, nonce="00" * 32)
    assert report.valid is False
    assert report.scorecard.nonce_bound is False
    assert report.scorecard.report_data_binds_key is False
    # The gateway bindings that do not involve the nonce still pass, proving
    # the failure is the nonce binding and not a parsing error.
    assert report.scorecard.tdx_verified is True
    assert report.scorecard.compose_hash_committed is True


def test_tampered_quote_is_rejected_by_real_appraisal():
    """One flipped nibble inside the signed quote: the retained (genuine)
    Phala appraisal for exactly that tampered quote says verified=false."""
    fixture = aci_fixture()

    def mutate(response):
        quote = response["attestation"]["evidence"]["quote"]
        i = len(quote) // 2
        quote = quote[:i] + ("1" if quote[i] != "1" else "2") + quote[i + 1:]
        response["attestation"]["evidence"]["quote"] = quote

    report = run_verify(pytest.MonkeyPatch(), fixture, mutate=mutate,
                        appraisal=load("venice_aci1_phala_appraisal_tampered-quote.json"))
    assert report.valid is False
    assert report.scorecard.tdx_verified is False


def test_appraisal_verdict_is_not_ignored():
    fixture = aci_fixture()
    appraisal = appraisal_for(fixture)
    appraisal["quote"]["verified"] = False
    report = run_verify(pytest.MonkeyPatch(), fixture, appraisal=appraisal)
    assert report.scorecard.tdx_verified is False
    assert report.valid is False


def test_bindings_read_the_appraised_quote_body_not_response_echoes():
    """Tamper the reportdata inside the retained appraisal: every binding that
    claims to come from the quote must fail, even though the response echoes
    a perfectly consistent report_data."""
    fixture = aci_fixture()
    appraisal = appraisal_for(fixture)
    body = appraisal["quote"]["body"]
    body["reportdata"] = "0x" + "ab" * 64
    report = run_verify(pytest.MonkeyPatch(), fixture, appraisal=appraisal)
    assert report.scorecard.nonce_bound is False
    assert report.scorecard.report_data_binds_key is False
    assert report.valid is False


def test_altered_event_payload_with_unchanged_digest_is_rejected():
    fixture = aci_fixture()

    def mutate(response):
        evidence = response["attestation"]["evidence"]
        events = json.loads(evidence["event_log"])
        target = next(e for e in events if e["imr"] == 3)
        target["event_payload"] = "bb" * 32  # digest left as declared
        evidence["event_log"] = json.dumps(events)

    report = run_verify(pytest.MonkeyPatch(), fixture, mutate=mutate)
    assert report.details["event_payloads_bound"] is False
    assert report.scorecard.compose_hash_committed is False
    assert report.valid is False


def test_compose_claim_moved_after_boot_boundary_is_rejected():
    fixture = aci_fixture()

    def mutate(response):
        evidence = response["attestation"]["evidence"]
        events = json.loads(evidence["event_log"])
        compose_event = next(e for e in events
                             if e["imr"] == 3 and e["event"] == "compose-hash")
        events.remove(compose_event)
        boundary = next(e for e in events if e["event"] == "boot-mr-done")
        events.insert(events.index(boundary) + 1, compose_event)
        evidence["event_log"] = json.dumps(events)

    report = run_verify(pytest.MonkeyPatch(), fixture, mutate=mutate)
    assert report.details["event_payloads_bound"] is True  # replay arithmetic intact
    assert report.scorecard.compose_hash_committed is False
    assert report.valid is False


def test_altered_compose_manifest_is_rejected():
    """The manifest is bound twice — MRConfigID and the RTMR3 compose-hash
    event — so editing app_compose without touching the quote must fail both."""
    fixture = aci_fixture()

    def mutate(response):
        response["attestation"]["evidence"]["app_compose"] = \
            response["attestation"]["evidence"]["app_compose"].replace("image:", "IMAGE:")

    report = run_verify(pytest.MonkeyPatch(), fixture, mutate=mutate)
    assert report.scorecard.compose_hash_committed is False
    assert report.valid is False


def test_keyset_not_recomputed_from_declared_digest_is_rejected():
    fixture = aci_fixture()

    def mutate(response):
        keyset = response["attestation"]["workload_keyset"]
        keyset["not_after"] = keyset["not_after"] + 3600  # digest left as declared

    report = run_verify(pytest.MonkeyPatch(), fixture, mutate=mutate)
    assert report.details["keyset_digest_recomputes"] is False
    assert report.scorecard.report_data_binds_key is False
    assert report.valid is False


def test_signing_key_outside_the_keyset_is_rejected():
    fixture = aci_fixture()

    def mutate(response):
        keys = response["attestation"]["workload_keyset"]["e2ee_public_keys"]
        keys[0]["public_key"] = "04" + "11" * 64

    report = run_verify(pytest.MonkeyPatch(), fixture, mutate=mutate)
    assert report.details["signing_key_in_keyset"] is False
    assert report.scorecard.report_data_binds_key is False
    assert report.valid is False


def test_report_data_echo_diverging_from_quote_is_rejected():
    fixture = aci_fixture()

    def mutate(response):
        response["attestation"]["report_data"] = "cd" * 64

    report = run_verify(pytest.MonkeyPatch(), fixture, mutate=mutate)
    assert report.details["report_data_echo_matches_quote"] is False
    assert report.scorecard.report_data_binds_key is False
    assert report.valid is False


def test_mismatched_signing_key_is_rejected():
    """Swap in a different valid secp256k1 key and its address: the quote's
    reportdata no longer binds it, and the address no longer derives."""
    from verifiers.common import keccak_eth_address
    eth_keys = pytest.importorskip("eth_keys")
    fixture = aci_fixture()
    other = eth_keys.keys.PrivateKey(b"\x07" * 32).public_key
    spk = "04" + other.to_bytes().hex()[2:]
    addr = keccak_eth_address(spk)

    def mutate(response):
        response["signing_public_key"] = spk
        response["signing_address"] = addr

    report = run_verify(pytest.MonkeyPatch(), fixture, mutate=mutate)
    assert report.scorecard.key_derives_to_address is True  # the pair is consistent…
    assert report.scorecard.report_data_binds_key is False  # …but not what the quote binds
    assert report.valid is False


def test_swapped_signing_address_is_rejected():
    fixture = aci_fixture()

    def mutate(response):
        response["signing_address"] = "0x" + "de" * 20

    report = run_verify(pytest.MonkeyPatch(), fixture, mutate=mutate)
    assert report.scorecard.key_derives_to_address is False
    assert report.scorecard.report_data_binds_key is False
    assert report.valid is False


def test_gateway_quote_cannot_be_presented_as_backend():
    """Provider-asserted fields claiming a direct model endpoint must not flip
    the backend score: the authenticated evidence still describes a gateway."""
    fixture = aci_fixture()

    def mutate(response):
        response["service_capabilities"]["serving"] = "direct"
        vm = json.loads(response["attestation"]["evidence"]["vm_config"])
        vm["num_gpus"] = 8
        response["attestation"]["evidence"]["vm_config"] = json.dumps(vm)

    report = run_verify(pytest.MonkeyPatch(), fixture, mutate=mutate)
    assert report.scorecard.backend_attested is False
    assert report.details["attested_cvm"] == "gateway"
    assert "names no model host" in report.details["unproven_reasons"]["backend_attested"]
    # The gateway checks themselves are unaffected by the self-asserted fields.
    assert report.valid is True


def test_unknown_api_version_fails_closed():
    fixture = aci_fixture()

    def mutate(response):
        response["api_version"] = "aci/2"

    report = run_verify(pytest.MonkeyPatch(), fixture, mutate=mutate)
    assert report.valid is False
    assert report.error == "unsupported attestation api_version: 'aci/2'"


def test_empty_api_version_fails_closed_too():
    fixture = aci_fixture()

    def mutate(response):
        response["api_version"] = ""

    report = run_verify(pytest.MonkeyPatch(), fixture, mutate=mutate)
    assert report.valid is False
    assert "unsupported attestation api_version" in report.error


def test_missing_quote_is_an_error_not_a_zero_score():
    fixture = aci_fixture()

    def mutate(response):
        response["attestation"]["evidence"]["quote"] = ""

    report = run_verify(pytest.MonkeyPatch(), fixture, mutate=mutate)
    assert report.valid is False
    assert report.error == "no gateway quote in ACI/1 evidence"


def test_404_capture_still_reports_unavailable():
    fixture = load("venice_404_e2ee-gemma-4-31b.json")
    mp = pytest.MonkeyPatch()
    mp.setattr(venice.requests, "get", Mock(return_value=Mock(
        status_code=fixture["http_status"], json=lambda: fixture["response"])))
    try:
        report = venice.verify("", "https://api.venice.ai/api/v1", fixture["model"])
    finally:
        mp.undo()
    assert report.valid is False
    assert report.error == "no TEE attestation available for this model (404)"


# ---------------------------------------------------------------------------
# The dstack path (no api_version) must keep working unchanged.
# ---------------------------------------------------------------------------

def test_dstack_capture_still_verifies_through_the_dstack_path():
    fixture = load("venice_dstack_e2ee-qwen3-6-35b-a3b.json")
    appraisal = load("venice_dstack_phala_appraisal_e2ee-qwen3-6-35b-a3b.json")
    quotes = {fixture["response"]["intel_quote"]: appraisal}

    def fake_post(url, json=None, timeout=None, **kwargs):
        return Mock(raise_for_status=lambda: None,
                    json=lambda: quotes[json["hex"]])

    mp = pytest.MonkeyPatch()
    mp.setattr(venice.requests, "get", Mock(return_value=Mock(
        status_code=200, json=lambda: fixture["response"])))
    mp.setattr(venice.phala_tdx.requests, "post", fake_post)
    try:
        report = venice.verify("", "https://api.venice.ai/api/v1",
                               fixture["model"], nonce=fixture["client_nonce"])
    finally:
        mp.undo()
    assert report.error is None
    assert report.scorecard.tdx_verified is True
    assert report.scorecard.report_data_binds_key is True
    assert report.scorecard.key_derives_to_address is True
    assert report.scorecard.compose_hash_committed is True
    # valid additionally gates on this capture's nvidia_payload through
    # nvidia_nras, which another lane owns; its verdict is out of scope here.
    assert "gpu_error" in report.details or report.scorecard.gpu_attested is not None


def test_aci1_body_is_not_parsed_by_the_dstack_path():
    """Before the fix, this body scored valid=true through the echo fields
    with compose_hash_committed=None. It must now take the ACI/1 path and
    require the gateway bindings."""
    fixture = aci_fixture()
    report = run_verify(pytest.MonkeyPatch(), fixture, nonce="ff" * 32)
    assert report.valid is False
    assert report.details["format"] == "aci/1 gateway"
    assert report.scorecard.compose_hash_committed is True  # now actually checked
