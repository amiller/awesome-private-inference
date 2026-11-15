"""Controls for the dstack boot-register policy (independent derivation pins).

Expected values come from verifiers/dstack_boot_registers.json, derived with
dstack-mr from published OS image archives. Tests replay every retained NEAR
evidence quote against the pins and mutate single inputs to prove rejection.
"""
import json
from pathlib import Path

import pytest

from verifiers import dstack_boot_registers, dstack_tdx

REPO = Path(__file__).resolve().parents[1]
EVIDENCE_DIR = REPO / "data" / "observations" / "evidence" / "sha256"


def _near_attestations():
    for f in sorted(EVIDENCE_DIR.glob("*.json")):
        d = json.loads(f.read_text())
        if "cloud-api.near.ai" not in d.get("source", ""):
            continue
        yield f.name, d


def _quotes():
    """(label, os_image_hash, parsed registers) for every retained NEAR quote."""
    for name, d in _near_attestations():
        for role, att in [("gateway", d.get("gateway_attestation") or {})] + [
                (f"model{i}", m) for i, m in enumerate(d.get("model_attestations") or [])]:
            os_hash = ((att.get("info") or {}).get("tcb_info") or {}).get("os_image_hash")
            if os_hash:
                yield f"{name[:12]}/{role}", os_hash, dstack_tdx.parse_quote(att["intel_quote"])

def test_all_retained_near_quotes_validate_against_pins():
    pinned = {e["os_image_hash"] for e in
              json.loads(dstack_boot_registers.POLICY_PATH.read_text())["entries"]}
    matched, unpublished = 0, 0
    for label, os_hash, parsed in _quotes():
        result = dstack_boot_registers.check_boot_registers(os_hash, parsed)
        if os_hash in pinned:
            assert result["boot_config"] is True, label
            matched += 1
        else:
            assert result["boot_config"] is False
            assert any("no pinned derivation" in r for r in result["reasons"])
            unpublished += 1
    # the corpus exercises both branches: published images and the
    # unpublished a6eafc5f… archive
    assert matched > 20 and unpublished > 10


def test_tampering_each_register_is_rejected():
    _, os_hash, parsed = next(iter(_quotes()))
    for reg in ("mrtd", "rtmr1", "rtmr2"):
        bad = dict(parsed)
        bad[reg] = ("0" if bad[reg][0] != "0" else "1") + bad[reg][1:]
        result = dstack_boot_registers.check_boot_registers(os_hash, bad)
        assert result["boot_config"] is False
        assert any(reg in r for r in result["reasons"])


def test_unknown_os_image_is_rejected_not_skipped():
    result = dstack_boot_registers.check_boot_registers("ab" * 32, {})
    assert result["boot_config"] is False
    assert any("no pinned derivation" in r for r in result["reasons"])


def test_image_without_derived_rtmr0_leaves_hardware_unproven():
    entry = next(e for e in json.loads(
        dstack_boot_registers.POLICY_PATH.read_text())["entries"] if not e.get("vm_shapes"))
    result = dstack_boot_registers.check_boot_registers(entry["os_image_hash"], {
        "mrtd": entry["mrtd_single_pass"], "rtmr0": "00" * 48,
        "rtmr1": entry["rtmr1"], "rtmr2": entry["rtmr2"]})
    assert result["boot_config"] is True
    assert result["hardware_config"] is None


def _venice_registers():
    evidence = json.loads((REPO / "tests" / "fixtures" / "venice_tee_attestation_e2ee-glm-5-1.json")
                          .read_text())["response"]["attestation"]["evidence"]
    m = dstack_tdx.attestation_measurements(evidence["quote"], json.loads(evidence["event_log"]))
    return m["log_os_image_hash"], m["registers"]


def test_venice_quote_matches_pinned_tuple():
    os_hash, registers = _venice_registers()
    result = dstack_boot_registers.check_boot_registers(os_hash, registers)
    assert result["boot_config"] is True and result["hardware_config"] is True


@pytest.mark.parametrize("register", ["mrtd", "rtmr0"])
def test_tuple_mismatch_fails_hardware_config(register):
    os_hash, registers = _venice_registers()
    bad = dict(registers)
    if register == "mrtd":  # other derived page-add variant: valid boot config, wrong tuple
        bad["mrtd"] = next(e for e in json.loads(dstack_boot_registers.POLICY_PATH.read_text())
                           ["entries"] if e["os_image_hash"] == os_hash)["mrtd_single_pass"]
    else:
        bad["rtmr0"] = "00" * 48
    result = dstack_boot_registers.check_boot_registers(os_hash, bad)
    assert result["hardware_config"] is False
    assert result["boot_config"] is True


@pytest.mark.parametrize("field", ["mrtd_two_pass", "rtmr1", "rtmr2", "os_image_hash"])
def test_malformed_policy_is_a_policy_error(monkeypatch, tmp_path, field):
    data = json.loads(dstack_boot_registers.POLICY_PATH.read_text())
    data["entries"][0][field] = "ab" * 10
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(data))
    monkeypatch.setattr(dstack_boot_registers, "POLICY_PATH", path)
    dstack_boot_registers._policy.cache_clear()
    with pytest.raises(dstack_boot_registers.PolicyError):
        dstack_boot_registers.check_boot_registers(data["entries"][0]["os_image_hash"], {})
    dstack_boot_registers._policy.cache_clear()
