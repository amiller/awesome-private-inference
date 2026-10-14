import json
from probes.instrument import capture


def test_adapter_edit_changes_instrument_even_when_upstream_pin_does_not(tmp_path):
    (tmp_path / "verifiers").mkdir()
    (tmp_path / "data").mkdir()
    (tmp_path / "data/instrument.json").write_text(json.dumps({"nearai_verifier_revision": "a" * 40}))
    source = tmp_path / "verifiers/adapter.py"
    source.write_text("first")
    before = capture(tmp_path)
    source.write_text("second")
    after = capture(tmp_path)
    assert before["revision"] != after["revision"]
    assert before["upstream_expected_revision"] == after["upstream_expected_revision"]
