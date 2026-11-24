"""Every instance NEAR lists for one model must pass (teep c1f253a, da6cbcf).

Fixture: details.raw_evidence of a live verify of z-ai/glm-5.3-flash on
2026-11-15, three model_attestations entries sharing one signing key.
"""
import json
from pathlib import Path

from eth_keys import keys

from tests.test_near_measurements import _verify

FIXTURE = Path(__file__).parent / "fixtures" / "near_glm53_three_instances.json"
LAYERS = ("tdx_verified", "nonce_bound", "report_data_binds_key", "key_derives_to_address",
          "gpu_attested", "tee_debug_disabled", "event_log_replayed", "tee_boot_config",
          "tcb_current")


def _load():
    return json.loads(FIXTURE.read_text())


def _ids(evidence):
    return [m["info"]["instance_id"] for m in evidence["model_attestations"]]


def test_all_three_instances_pass_and_are_keyed_by_id(monkeypatch):
    evidence = _load()
    report = _verify(monkeypatch, evidence)
    d = report.details
    assert all(getattr(report.scorecard, layer) is True for layer in LAYERS)
    assert report.scorecard.compose_hash_committed is False  # capture has no compose_manager_attestation
    assert d["instance_count"] == 3 and d["instance_ids"] == _ids(evidence)
    assert list(d["instances"]) == _ids(evidence)
    assert all(r["instance_id_bound"] for r in d["instances"].values())
    assert d["signing_key_shared"] is True
    assert "invisible" in d["instance_limit"]
    assert [c["instance_id"] for c in d["model_composes"]] == _ids(evidence)


def test_one_tampered_instance_rejects_the_layer(monkeypatch):
    evidence = _load()
    log = evidence["model_attestations"][2]["info"]["tcb_info"]["event_log"]
    for entry in log:
        if entry["event"] == "compose-hash":
            entry["event_payload"] = "ff" + entry["event_payload"][2:]
    report = _verify(monkeypatch, evidence)
    ids, inst = _ids(evidence), report.details["instances"]
    assert report.scorecard.event_log_replayed is False
    assert inst[ids[2]]["event_log_replayed"] is False
    assert inst[ids[0]]["event_log_replayed"] and inst[ids[1]]["event_log_replayed"]
    assert report.details["verification_status"] == "rejected"


def test_instance_id_not_in_event_log_rejects(monkeypatch):
    evidence = _load()
    evidence["model_attestations"][1]["info"]["instance_id"] = "ab" * 20
    report = _verify(monkeypatch, evidence)
    inst = report.details["instances"]
    assert inst["ab" * 20]["instance_id_bound"] is False
    assert inst["ab" * 20]["event_log_replayed"] is True
    assert report.scorecard.event_log_replayed is False


def test_mismatched_signing_key_rejects(monkeypatch):
    evidence = _load()
    other = keys.PrivateKey(b"\x11" * 32).public_key
    evidence["model_attestations"][1]["signing_public_key"] = other.to_bytes().hex()
    evidence["model_attestations"][1]["signing_address"] = other.to_checksum_address()
    report = _verify(monkeypatch, evidence)
    assert report.error == "model_attestations entries do not share one signing key"
    assert report.details["signing_key_shared"] is False


# GLM lane rejected since ~11-20: the gateway lists cc796618 twice with different quotes.
DUPLICATE = (Path(__file__).resolve().parents[1] / "data" / "observations" / "evidence" / "sha256" /
             "2ca9798d1dc54122816c2cd56ded9fae81b7d4fd7e6037527b213efd70b09c82.json")


def _duplicate_listing(monkeypatch):
    from verifiers import near_ai
    evidence = json.loads(DUPLICATE.read_text())
    # captured by the early-reject path, so it has no chain context; replay against an empty one
    evidence.update(chain_snapshot={"block_number": 1, "block_hash": "0x" + "11" * 32, "chain_id": 8453},
                    model_authorization_queries=[], gateway_authorization_query={"compose_hash": ""})
    monkeypatch.setattr(near_ai.near_deployments, "appraise",
                        lambda *a, **k: {"ok": False, "checks": {}, "deployments": []})
    monkeypatch.setattr(near_ai.near_deployments, "load_archive", lambda: {})
    return evidence


def test_agreeing_duplicate_instance_is_appraised_twice(monkeypatch):
    evidence = _duplicate_listing(monkeypatch)
    report = _verify(monkeypatch, evidence)
    d = report.details
    assert report.error is None
    assert d["instance_entries"][_ids(evidence)[0]] == 2
    assert len(d["entries"]) == 4 and len(d["tdx"]["models"]) == 4


def test_conflicting_duplicate_instance_rejects(monkeypatch):
    evidence = _duplicate_listing(monkeypatch)
    evidence["model_attestations"][3]["tls_cert_fingerprint"] = "00" * 32
    report = _verify(monkeypatch, evidence)
    assert report.error == f"instance {_ids(evidence)[0]} listed with conflicting identities"


def test_more_than_eight_entries_rejects(monkeypatch):
    evidence = _load()
    evidence["model_attestations"] = (evidence["model_attestations"] * 3)[:9]
    report = _verify(monkeypatch, evidence)
    assert report.error == "9 model_attestations entries exceed the cap of 8"
