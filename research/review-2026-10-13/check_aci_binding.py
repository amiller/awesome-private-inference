"""Offline counterexample against the reviewed revision; no provider requests.

Mocks an authenticated quote result, then checks whether mismatching, untrusted
JSON report_data can nevertheless produce a passing registry result.
This demonstrates a verifier acceptance gap, not a production exploit.
Run with the existing project venv from anywhere inside this git repository.
"""
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

REV = "cbf555f661e81c838ba8daa3f7bb131691d5dbae"


def main():
    with tempfile.TemporaryDirectory(prefix="reference-review-") as tmp:
        root = Path(tmp)
        for name in ("__init__.py", "aci.py", "common.py", "phala_tdx.py"):
            dest = root / "verifiers" / name
            dest.parent.mkdir(exist_ok=True)
            dest.write_bytes(subprocess.check_output([
                "git", "show", f"{REV}:verifiers/{name}"]))
        sys.path.insert(0, tmp)
        from verifiers import aci

        host = "tee.example.test"
        compose = json.dumps({"docker_compose_file": json.dumps({
            "configs": {"gateway-config": {"content": json.dumps({
                "middleware": {"tee_only_domains": [host]}})}}})})
        events = [{"imr": 3, "digest": "bb" * 48,
                   "event": "compose-hash", "event_payload": aci.sha256_hex(compose)}]
        keyset = {"keys": []}
        digest = "sha256:" + aci.sha256_hex(aci._jcs(keyset))
        nonce = bytes(32).hex()
        statement = '{"keyset_digest":"%s","nonce":"%s","purpose":"%s"}' % (
            digest, nonce, aci.PURPOSE)
        reported = aci.sha256_hex(statement)
        quote_body = {"rtmr3": aci._replayed_rtmr3(events),
                      "reportdata": "00" * 64}
        envelope = {"workload_keyset_digest": digest, "attestation": {
            "workload_keyset": keyset, "report_data": reported,
            "evidence": {"quote": "mock-authenticated-quote",
                         "event_log": json.dumps(events), "app_compose": compose,
                         "vm_config": json.dumps({"os_image_hash": "aa" * 32,
                                                  "image": "mock-production"})}}}

        class Response:
            def __init__(self, value):
                self.value = value

            def json(self):
                return self.value

        with patch.object(aci.os, "urandom", return_value=bytes(32)), \
             patch.object(aci.requests, "get", side_effect=[
                 Response(envelope), Response({"data": ["mock-model"]})]), \
             patch.object(aci, "verify_tdx_quote", return_value={}), \
             patch.object(aci, "quote_body", return_value=quote_body), \
             patch.object(aci, "is_verified", return_value=True), \
             patch.object(aci, "_os_image_is_production", return_value=True), \
             patch.object(aci, "_sessions_carry_evidence", return_value=(True, "mock")):
            result = aci.verify("", "", host)
        print(json.dumps({"revision": REV, "offline_mock_only": True,
                          "authenticated_quote_reportdata": quote_body["reportdata"],
                          "untrusted_envelope_report_data": reported,
                          "registry_valid": result.valid,
                          "registry_nonce_bound": result.scorecard.nonce_bound,
                          "registry_key_bound": result.scorecard.report_data_binds_key}, indent=2))
        assert result.valid, "Reviewed acceptance behavior has changed"


if __name__ == "__main__":
    main()
