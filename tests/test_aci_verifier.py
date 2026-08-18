"""The ACI shape's own arithmetic, checked against fixed vectors rather than the network."""
import hashlib
import json

from verifiers import aci
from verifiers.common import REQUIRED_LAYERS_BY_SHAPE


def test_statement_binding_matches_spec_template():
    # spec/aci.md §3.2: exact bytes, this field order, no whitespace.
    digest = "sha256:" + "ab" * 32
    nonce = "cd" * 32
    statement = '{"keyset_digest":"%s","nonce":"%s","purpose":"aci.report_data.v1"}' % (digest, nonce)
    assert hashlib.sha256(statement.encode()).hexdigest() == hashlib.sha256(
        json.dumps({"keyset_digest": digest, "nonce": nonce,
                    "purpose": aci.PURPOSE}, separators=(",", ":")).encode()).hexdigest()


def test_rtmr3_replay_folds_only_imr3_events():
    log = [{"imr": 0, "digest": "aa" * 48}, {"imr": 3, "digest": "bb" * 48},
           {"imr": 3, "digest": "cc" * 48}]
    expected = bytes(48)
    for digest in ("bb" * 48, "cc" * 48):
        expected = hashlib.sha384(expected + bytes.fromhex(digest)).digest()
    assert aci._replayed_rtmr3(log) == expected.hex()


def test_tee_only_domains_comes_from_the_measured_compose():
    compose = """
services:
  launcher:
    image: example@sha256:abc
configs:
  gateway-config:
    content: |
      {
        "bind": "0.0.0.0:8086",
        "middleware": { "tee_only_domains": ["tee.example.com"] }
      }
"""
    assert aci._tee_only_domains(compose) == ["tee.example.com"]


def test_attested_serving_is_required_by_the_shape():
    # The layer that differs between hostnames on one shared attestation must be
    # required, or the open host would score identically to the TEE-only ones.
    assert "attested_serving_enforced" in REQUIRED_LAYERS_BY_SHAPE["aci-gateway"]
