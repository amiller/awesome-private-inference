"""Offline controls for model-scoped references and reproducible chain lookups."""
from verifiers import near_ai


def test_model_anchor_does_not_accept_another_models_compose():
    app = near_ai._MODELS_APP.removeprefix("0x")
    anchor = {"models": {
        "model-a": {"app_id": app, "compose_hashes": ["aa" * 32]},
        "model-b": {"app_id": app, "compose_hashes": ["bb" * 32]},
    }}
    assert near_ai._anchor_matches_model(anchor, "model-a", "model-a", app, "aa" * 32)
    assert not near_ai._anchor_matches_model(anchor, "model-a", "model-a", app, "bb" * 32)
    assert not near_ai._anchor_matches_model(anchor, "model-a", "model-b", app, "aa" * 32)
    assert not near_ai._anchor_matches_model(anchor, "model-a", "model-a", "cc" * 20, "aa" * 32)


def test_chain_authorization_uses_captured_block(monkeypatch):
    calls = []

    def rpc(method, params):
        calls.append((method, params))
        if method == "eth_getBlockByNumber":
            return {"number": "0x2a", "hash": "0x" + "ab" * 32}
        if method == "eth_chainId":
            return "0x2105"
        if method == "eth_call":
            return "0x1"
        raise AssertionError(method)

    monkeypatch.setattr(near_ai, "_rpc", rpc)
    snapshot = near_ai._chain_snapshot()
    assert snapshot["chain_id"] == 8453
    assert snapshot["block_number"] == 42
    assert near_ai._allowed_on_chain(near_ai._MODELS_APP, "aa" * 32,
                                     snapshot["block_tag"])
    assert calls[-1][1][-1] == "0x2a"
    near_ai._assert_same_block(snapshot)


def test_chain_reorg_invalidates_pinned_queries(monkeypatch):
    monkeypatch.setattr(near_ai, "_rpc", lambda method, params: {
        "number": "0x2a", "hash": "0x" + "ff" * 32})
    import pytest
    with pytest.raises(ValueError, match="block changed"):
        near_ai._assert_same_block({"block_tag": "0x2a", "block_hash": "0x" + "aa" * 32})


def test_near_raw_evidence_whitelists_protocol_fields():
    raw = near_ai._public_attestation_fields({
        "intel_quote": "quote", "nvidia_payload": "gpu", "signing_address": "0xabc",
        "info": {"model_name": "model-a", "app_id": "0x123", "tcb_info": {
            "app_compose": "exact-compose-bytes", "internal_token": "secret"}},
        "authorization": "Bearer secret", "prompt": "private prompt",
    })
    assert raw["intel_quote"] == "quote"
    assert raw["info"]["tcb_info"]["app_compose"] == "exact-compose-bytes"
    assert "authorization" not in raw and "prompt" not in raw
    assert "internal_token" not in raw["info"]["tcb_info"]


def test_near_raw_evidence_withholds_potential_compose_secret():
    compose = 'services:\n  worker:\n    environment:\n      HF_TOKEN: "opaque-value-with-length"\n'
    raw = near_ai._public_attestation_fields({
        "model_name": "model-a", "info": {"tcb_info": {"app_compose": compose}}})
    tcb = raw["info"]["tcb_info"]
    assert raw["model_name"] == "model-a"
    assert "app_compose" not in tcb
    assert tcb["app_compose_sha256"] == near_ai.sha256_hex(compose)
    assert tcb["app_compose_preimage_status"] == "withheld_potential_secret"


def test_near_raw_evidence_keeps_variable_reference_compose():
    compose = 'services:\n  worker:\n    environment:\n      HF_TOKEN: "${HF_TOKEN}"\n'
    raw = near_ai._public_attestation_fields({"info": {"tcb_info": {
        "app_compose": compose}}})
    assert raw["info"]["tcb_info"]["app_compose"] == compose
