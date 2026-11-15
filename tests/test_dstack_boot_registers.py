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
    matched, unpublished = 0, 0
    for _, os_hash, parsed in _quotes():
        result = dstack_boot_registers.check_boot_registers(os_hash, parsed)
        entry = json.loads(dstack_boot_registers.POLICY_PATH.read_text())
        published = any(e["os_image_hash"] == os_hash for e in entry["entries"])
        if published:
            # every published-image quote must match mrtd/rtmr1/rtmr2; rtmr0 is
            # unpinned for NEAR (no vm_config), which keeps ok False by design.
            assert result["per_register"]["mrtd"] is True, os_hash[:8]
            assert result["per_register"]["rtmr1"] is True, os_hash[:8]
            assert result["per_register"]["rtmr2"] is True, os_hash[:8]
            assert result["per_register"]["rtmr0"] is None
            assert result["ok"] is False
            assert any("vm_config" in r or "VM shape" in r for r in result["reasons"])
            matched += 1
        else:
            assert result["ok"] is False
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
        assert result["per_register"][reg] is False
        assert result["ok"] is False
        assert any(reg in r for r in result["reasons"])


def test_unknown_os_image_is_rejected_not_skipped():
    result = dstack_boot_registers.check_boot_registers("ab" * 32, {})
    assert result["ok"] is False
    assert result["per_register"] == {}
    assert any("no pinned derivation" in r for r in result["reasons"])


def test_venice_shape_pins_all_four_registers():
    attestation = json.loads((REPO / "tests" / "fixtures"
                              / "venice_tee_attestation_e2ee-glm-5-1.json").read_text())["response"]
    evidence = attestation["attestation"]["evidence"]
    quote = evidence["quote"]
    vm_config = json.loads(evidence["vm_config"])
    measurements = dstack_tdx.attestation_measurements(quote, json.loads(evidence["event_log"]))
    result = dstack_boot_registers.check_boot_registers(
        vm_config["os_image_hash"], measurements["registers"], vm_config)
    assert all(v is True for v in result["per_register"].values())
    assert result["ok"] is True


def test_venice_unpinned_shape_is_rejected():
    attestation = json.loads((REPO / "tests" / "fixtures"
                              / "venice_tee_attestation_e2ee-glm-5-1.json").read_text())["response"]
    evidence = attestation["attestation"]["evidence"]
    vm_config = json.loads(evidence["vm_config"])
    vm_config["cpu_count"] = 64  # a real shape, but not one we have derived pins for
    quote = evidence["quote"]
    measurements = dstack_tdx.attestation_measurements(quote, json.loads(evidence["event_log"]))
    result = dstack_boot_registers.check_boot_registers(
        vm_config["os_image_hash"], measurements["registers"], vm_config)
    assert result["ok"] is False
    assert result["per_register"]["rtmr0"] is False
    assert any("not pinned" in r for r in result["reasons"])


def test_vm_shape_without_vm_config_cannot_pass_rtmr0():
    entry = next(e for e in json.loads(
        dstack_boot_registers.POLICY_PATH.read_text())["entries"] if e.get("vm_shapes"))
    os_hash = entry["os_image_hash"]
    result = dstack_boot_registers.check_boot_registers(os_hash, {
        "mrtd": entry["mrtd_two_pass"], "rtmr1": entry["rtmr1"],
        "rtmr2": entry["rtmr2"], "rtmr0": entry["vm_shapes"][0]["rtmr0"]})
    assert result["ok"] is False
    assert result["per_register"]["rtmr0"] is None
    assert any("does not expose" in r for r in result["reasons"])


@pytest.mark.parametrize("field", ["mrtd_two_pass", "rtmr1", "rtmr2"])
def test_malformed_policy_is_a_policy_error(monkeypatch, field):
    data = json.loads(dstack_boot_registers.POLICY_PATH.read_text())
    data["entries"][0][field] = "ab" * 10
    import tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        json.dump(data, fh)
        path = fh.name
    monkeypatch.setattr(dstack_boot_registers, "POLICY_PATH", Path(path))
    dstack_boot_registers._policy.cache_clear()
    with pytest.raises(dstack_boot_registers.PolicyError):
        dstack_boot_registers.check_boot_registers(data["entries"][0]["os_image_hash"], {})
    dstack_boot_registers._policy.cache_clear()
