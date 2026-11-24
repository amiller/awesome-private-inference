"""Per-machine NEAR archive (tasks/near-machine-archive-plan.md §6, tests 2-4).

Replays the 11-20 GLM capture (cc796618 listed twice, compose-manager logs on every
entry). Transport and appraisal are stubbed; quotes and logs are the captured bytes.
"""
import copy
import json
from datetime import date, datetime, timezone
from pathlib import Path

from probes import near_machines as nm
from verifiers import near_ai
from verifiers.common import AttestationReport

CAPTURE = (Path(__file__).resolve().parents[1] / "data" / "observations" / "evidence" / "sha256" /
           "2ca9798d1dc54122816c2cd56ded9fae81b7d4fd7e6037527b213efd70b09c82.json")

def _capture():
    return json.loads(CAPTURE.read_text())


def _setup(monkeypatch, tmp_path, fetch, nonce=None):
    monkeypatch.setattr(nm, "OUT", tmp_path / "near-machines")
    monkeypatch.setattr(nm, "EVIDENCE", tmp_path / "evidence")
    monkeypatch.setattr(nm, "ROOT", tmp_path)
    monkeypatch.setattr(nm, "DIRECT_UNTIL", date(2000, 1, 1))
    models = ["z-ai/glm-5.3-flash", "Qwen/Qwen3.8-27B"]
    monkeypatch.setattr(nm, "get_json", lambda url, **p: {"total": 2, "models": [
        {"modelId": m, "metadata": {"attestationSupported": True, "ownedBy": "nearai"}} for m in models]})
    monkeypatch.setattr(near_ai, "fetch_report", fetch)
    monkeypatch.setattr(near_ai, "appraise_report", lambda report, model, nonce, *a: AttestationReport(
        provider="near-ai", model=model, valid=False, verified_at="", attestation_type="tdx+gpu",
        details={"verification_status": "rejected"}))
    if nonce:
        monkeypatch.setattr(nm.secrets, "token_hex", lambda n: nonce)


def _actions(tmp_path, iid):
    return [json.loads(line) for line in
            (tmp_path / "near-machines" / iid / "actions.jsonl").read_text().splitlines()]


def test_one_failed_model_fails_the_run_and_keeps_the_others(monkeypatch, tmp_path):
    """#18: `|| true` and exception-to-row turned a 503 into a green run."""
    def fetch(key, base, model, nonce):
        if model == "Qwen/Qwen3.8-27B":
            raise near_ai.FetchError("HTTP 503: upstream unavailable")
        return _capture()
    _setup(monkeypatch, tmp_path, fetch)
    assert nm.main([]) == 1
    run = json.loads(next((tmp_path / "near-machines" / "runs").glob("*.json")).read_text())
    assert run["status"] == "failed" and run["failed"] == ["Qwen/Qwen3.8-27B"]
    assert run["models"]["Qwen/Qwen3.8-27B"]["status"] == "fetch_failed"
    caps = list((tmp_path / "near-machines").glob("*/captures/*.json"))
    assert len(caps) == 3  # cc796618, 19aea169, a8a25faa from the GLM report
    index = json.loads((tmp_path / "near-machines" / "index.json").read_text())
    assert index["last_live_run"]["status"] == "failed"


def test_replayed_log_is_archived_unbound(monkeypatch, tmp_path):
    """A compose-manager log whose report_data binds someone else's nonce is kept, never as fresh."""
    capture = _capture()
    _setup(monkeypatch, tmp_path, lambda *a: copy.deepcopy(capture), nonce="ab" * 32)
    nm.main([])
    iid = capture["model_attestations"][0]["info"]["instance_id"]
    actions = _actions(tmp_path, iid)
    assert actions and not any(a["bound"] for a in actions)
    cap = json.loads(next((tmp_path / "near-machines" / iid / "captures").glob("*.json")).read_text())
    cm = cap["entries"][0]["compose_manager"]
    assert cm["recomputed_ok"] and cm["same_cvm_as_model"] and not cm["report_data_binds_nonce"]
    assert nm.facts(cap).get("running") is None  # unbound logs do not report running deployments

    # control: the nonce the log was bound to makes the same bytes fresh
    _setup(monkeypatch, tmp_path, lambda *a: copy.deepcopy(capture), nonce=capture["nonce"])
    nm.main([])
    assert any(a["bound"] for a in _actions(tmp_path, iid))


def test_pruned_log_keeps_every_archived_action(monkeypatch, tmp_path):
    """compose-manager prunes after 7 days; the archive must not."""
    monkeypatch.setattr(nm, "OUT", tmp_path)
    long_log = [{"timestamp": f"2026-11-{d:02d}T00:00:00+00:00", "action": "compose_up", "file": "f.yaml",
                 "commit": "c", "tag": "v1", "file_sha256": "aa", "services": ["s"]} for d in range(1, 11)]
    twin = {**long_log[-1], "file_sha256": "bb"}  # differs only in file bytes
    now = datetime(2026, 11, 12, tzinfo=timezone.utc)
    nm.update_actions("m", [(long_log + [twin], True)], "t1", "cap1", now)
    findings = nm.update_actions("m", [(long_log[-3:], True)], "t2", "cap2", now)
    archived = [json.loads(line) for line in (tmp_path / "m" / "actions.jsonl").read_text().splitlines()]
    assert len(archived) == 11
    assert {a["action"]["file_sha256"] for a in archived
            if a["action"]["timestamp"].startswith("2026-11-10")} == {"aa", "bb"}
    # 11-06, 11-07 and the twin are within 6 days of `now` but absent from the pruned log
    assert findings == [{"kind": "actions_missing_within_retention", "instance_id": "m",
                         "sha256": sorted(nm.digest(a) for a in (long_log[5], long_log[6], twin))}]
