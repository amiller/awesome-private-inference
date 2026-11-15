"""NEAR compose-manager deployment-log appraisal on two real glm-5.3-flash instances.

DCAP and the public-file fetch are stubbed; quotes, logs and nonces are the
captured bytes. Each negative control changes one input.
"""
import copy
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

from verifiers import near_deployments as nd

FIXTURE = Path(__file__).parent / "fixtures" / "near_compose_manager_two_instances.json"
NOW = datetime(2026, 11, 16, tzinfo=timezone.utc)
DAY = 24 * 3600


def _instances():
    return json.loads(FIXTURE.read_text())["instances"]


def _public(cm):
    return {(d["commit"], d["file"]): d["file_sha256"] for d in nd.running_deployments(cm["actions"])}


def _archive(cm, age):
    return {nd.archive_key(d): {"file_sha256": d["file_sha256"], "tag": d["tag"],
                                "first_seen": (NOW - age).isoformat()}
            for d in nd.running_deployments(cm["actions"])}


def _appraise(inst, cm=None, quote=None, nonce=None, archive=None, public=None, status="UpToDate"):
    cm = cm or inst["compose_manager_attestation"]
    table = public if public is not None else _public(inst["compose_manager_attestation"])
    return nd.appraise(cm, quote or inst["intel_quote"], nonce or cm["nonce"],
                       archive if archive is not None else {}, DAY, NOW,
                       fetch_sha256=lambda c, f: table[(c, f)],
                       verify_quote=lambda q: SimpleNamespace(status=status))


def test_real_log_binds_but_is_not_aged_without_archive():
    for inst in _instances():
        r = _appraise(inst)
        assert {k for k, v in r["checks"].items() if not v} == {"deployments_aged"}
        assert r["ok"] is False


def test_real_log_passes_once_archive_has_seen_it_long_enough():
    inst = _instances()[0]
    cm = inst["compose_manager_attestation"]
    assert _appraise(inst, archive=_archive(cm, timedelta(days=2)))["ok"] is True
    assert _appraise(inst, archive=_archive(cm, timedelta(hours=2)))["ok"] is False


def test_tampered_actions_list_fails_hash_and_report_data():
    inst = _instances()[0]
    cm = copy.deepcopy(inst["compose_manager_attestation"])
    up = next(a for a in reversed(cm["actions"]) if a["action"] == "compose_up")
    up["commit"] = "0" * 40
    r = _appraise(inst, cm=cm, public={**_public(inst["compose_manager_attestation"]),
                                       ("0" * 40, up["file"]): up.get("file_sha256")})
    assert r["checks"]["actions_hash_recomputed"] is False
    assert r["checks"]["report_data_binds_log_and_nonce"] is False


def test_wrong_nonce_fails_binding():
    inst = _instances()[0]
    r = _appraise(inst, nonce="ab" * 32)
    assert r["checks"]["report_data_binds_log_and_nonce"] is False


def test_quote_from_another_instance_fails_same_cvm():
    a, b = _instances()
    r = _appraise(a, quote=b["intel_quote"])
    assert r["checks"]["same_cvm_as_model"] is False


def test_file_not_matching_public_bytes_fails():
    inst = _instances()[0]
    public = {k: "f" * 64 for k in _public(inst["compose_manager_attestation"])}
    assert _appraise(inst, public=public)["checks"]["deployments_public"] is False


def test_outofdate_tcb_fails_only_tcb_check():
    inst = _instances()[0]
    r = _appraise(inst, status="OutOfDate")
    assert r["checks"]["cm_quote_verified"] is True
    assert r["checks"]["cm_tcb_current"] is False


def test_archive_entry_with_other_bytes_is_not_aged():
    inst = _instances()[0]
    cm = inst["compose_manager_attestation"]
    archive = _archive(cm, timedelta(days=2))
    first = next(iter(archive))
    archive[first]["file_sha256"] = "e" * 64
    assert _appraise(inst, archive=archive)["checks"]["deployments_aged"] is False


def test_running_set_tracks_up_and_down():
    acts = [
        {"action": "compose_up", "file": "a.yaml", "commit": "c1", "file_sha256": "h1", "services": ["x", "y"]},
        {"action": "compose_down", "file": "a.yaml", "commit": "c1", "services": ["x"]},
        {"action": "compose_up", "file": "b.yaml", "commit": "c2", "file_sha256": "h2"},
        {"action": "compose_down", "file": "b.yaml", "commit": "c2"},
        {"action": "compose_up", "file": "c.yaml", "commit": "c3"},
    ]
    running = {(d["file"], tuple(d["services"]), d["file_sha256"]) for d in nd.running_deployments(acts)}
    assert running == {("a.yaml", ("y",), "h1"), ("c.yaml", ("*",), None)}


def test_deployment_without_file_hash_is_not_public():
    acts = [{"action": "compose_up", "file": "c.yaml", "commit": "c3", "timestamp": "t"}]
    cm = {"actions": acts, "actions_hash": nd.actions_hash(acts), "nonce": "00" * 32, "quote": ""}
    inst = _instances()[0]
    cm["quote"] = inst["compose_manager_attestation"]["quote"]
    r = _appraise(inst, cm=cm, public={})
    assert r["checks"]["deployments_public"] is False


def test_record_adds_only_publicly_matched_and_new():
    deps = [{"commit": "c", "file": "f", "file_sha256": "h", "tag": "t", "public_sha256_matches": True},
            {"commit": "d", "file": "f", "file_sha256": "h", "tag": "t", "public_sha256_matches": False}]
    archive = {}
    assert nd.record(deps, archive, NOW) == 1
    assert nd.record(deps, archive, NOW + timedelta(days=1)) == 0
    assert archive["c:f"]["first_seen"] == NOW.isoformat()
