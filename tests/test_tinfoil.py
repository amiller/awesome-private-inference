"""Tinfoil verifier tests — uses a saved ATC bundle fixture so no network."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from verifiers import tinfoil, tinfoil_sev

FIXTURE = Path(__file__).parent / "fixtures" / "tinfoil_atc_bundle.json"


@pytest.fixture(scope="module")
def bundle():
    return tinfoil._Bundle.from_json(json.loads(FIXTURE.read_text()))


def test_sev_report_parses(bundle):
    rep = bundle.sev_report()
    assert rep.version == 3
    assert rep.debug is False
    assert rep.vmpl == 0
    assert rep.signature_algo == 1
    assert len(rep.measurement) == 48
    assert len(rep.report_data) == 64


def test_att_doc_hash_matches_hatt_san(bundle):
    sans = tinfoil._bundle_san_uris(bundle.enclave_cert_pem)
    hatt = tinfoil._decode_dcode([s for s in sans if isinstance(s, str)], "hatt").decode()
    assert hatt == bundle.att_doc_hash()


def test_hpke_san_matches_report_data(bundle):
    sans = tinfoil._bundle_san_uris(bundle.enclave_cert_pem)
    hpke = tinfoil._decode_dcode([s for s in sans if isinstance(s, str)], "hpke")
    assert hpke == bundle.sev_report().report_data[32:64]


def test_bundle_cert_spki_matches_report_data(bundle):
    rep = bundle.sev_report()
    assert tinfoil._spki_sha256_from_pem(bundle.enclave_cert_pem) == rep.report_data[:32].hex()


def test_san_regex_matches_real_run():
    san = (
        "https://github.com/tinfoilsh/confidential-model-router/"
        ".github/workflows/tinfoil-release.yml@refs/tags/v0.0.89"
    )
    assert tinfoil._san_regex("tinfoilsh/confidential-model-router").match(san)


def test_san_regex_rejects_other_repo():
    san = (
        "https://github.com/tinfoilsh/confidential-gpt-oss-120b/"
        ".github/workflows/release.yml@refs/tags/v0.0.22"
    )
    assert tinfoil._san_regex("tinfoilsh/confidential-gpt-oss-120b").match(san)
    assert not tinfoil._san_regex("tinfoilsh/confidential-model-router").match(san)


def test_verify_bundle_offline_skips_live_tls(bundle, monkeypatch):
    """The fixture's expected SPKI is what the live host serves — but in CI
    we may be offline. Stub the live TLS check to return the expected hash so
    the rest of the pipeline can run."""
    expected = bundle.sev_report().report_data[:32].hex()
    monkeypatch.setattr(tinfoil, "_live_tls_spki_sha256", lambda host, **kw: expected)
    report = tinfoil.verify_bundle(bundle, model="test")
    assert report.valid, report.error
    sc = report.scorecard
    assert sc.code_measurement_reproducible is True
    assert sc.tls_pubkey_pinned is True
    assert sc.hpke_pubkey_attested is True
    assert sc.client_nonce_supported is False
    assert report.attestation_type == "tinfoil-sev-snp-v2"


def test_verify_detects_measurement_mismatch(bundle, monkeypatch):
    expected = bundle.sev_report().report_data[:32].hex()
    monkeypatch.setattr(tinfoil, "_live_tls_spki_sha256", lambda host, **kw: expected)
    monkeypatch.setattr(
        tinfoil, "_extract_snp_measurement", lambda *a, **k: "00" * 48,
    )
    report = tinfoil.verify_bundle(bundle, model="test")
    assert not report.valid
    assert "measurement mismatch" in (report.error or "")
    assert report.scorecard.code_measurement_reproducible is None


def test_verify_detects_live_tls_mismatch(bundle, monkeypatch):
    monkeypatch.setattr(tinfoil, "_live_tls_spki_sha256", lambda host, **kw: "ff" * 32)
    report = tinfoil.verify_bundle(bundle, model="test")
    assert not report.valid
    assert "live TLS SPKI" in (report.error or "")
    assert report.scorecard.tls_pubkey_pinned is False
    assert report.scorecard.code_measurement_reproducible is True


def test_parse_rejects_wrong_length():
    with pytest.raises(ValueError, match="1184-byte"):
        tinfoil_sev.parse(b"\x00" * 100)


def _decode_predicate(bundle):
    import base64
    sb = bundle.sigstore_bundle
    payload = base64.b64decode(sb["dsseEnvelope"]["payload"])
    return json.loads(payload)["predicate"]


def test_audit_decodes_attested_config(bundle):
    predicate = _decode_predicate(bundle)
    audit = tinfoil._audit_attested_config(predicate)
    assert audit.cvm_version == "0.7.5"
    assert audit.container_count == 1
    proxy = audit.containers[0]
    assert proxy["name"] == "proxy"
    assert proxy["image_pinned_by_digest"] is True
    assert proxy["env_external"] == ["DOMAIN"]
    assert "REFRESH_INTERVAL" in proxy["env_attested"]
    assert proxy["secrets_external"] == ["USAGE_REPORTER_SECRET"]
    assert audit.fully_attested is False


def test_audit_rejects_cmdline_hash_mismatch(bundle):
    predicate = _decode_predicate(bundle)
    bad = dict(predicate)
    bad["cmdline"] = predicate["cmdline"].replace(
        "tinfoil-config-hash=", "tinfoil-config-hash=" + "0" * 64 + " other="
    )
    with pytest.raises(ValueError, match="config hash mismatch"):
        tinfoil._audit_attested_config(bad)


def test_audit_fully_attested_when_no_external_slots(bundle):
    import base64
    predicate = dict(_decode_predicate(bundle))
    cfg_yaml = (
        "cvm-version: 0.0.0\n"
        "containers:\n"
        '  - name: "x"\n'
        '    image: "ghcr.io/x@sha256:abcd"\n'
        '    env:\n'
        '      - HARDCODED: "value"\n'
    )
    cfg_bytes = cfg_yaml.encode()
    predicate["config"] = base64.b64encode(cfg_bytes).decode()
    predicate["cmdline"] = (
        f"x=y tinfoil-config-hash={__import__('hashlib').sha256(cfg_bytes).hexdigest()}"
    )
    audit = tinfoil._audit_attested_config(predicate)
    assert audit.fully_attested is True
    assert audit.containers[0]["env_attested"] == ["HARDCODED"]


def test_verify_bundle_surfaces_audit(bundle, monkeypatch):
    expected = bundle.sev_report().report_data[:32].hex()
    monkeypatch.setattr(tinfoil, "_live_tls_spki_sha256", lambda host, **kw: expected)
    report = tinfoil.verify_bundle(bundle, model="test")
    assert report.valid
    assert report.scorecard.runtime_config_fully_attested is False
    cfg = report.details["attested_config"]
    assert cfg["total_env_external"] == 1
    assert cfg["total_secrets_external"] == 1


PER_HOST_FIXTURE = Path(__file__).parent / "fixtures" / "tinfoil_per_host_gpt_oss.json"


@pytest.fixture(scope="module")
def per_host_bundle():
    raw = json.loads(PER_HOST_FIXTURE.read_text())
    return tinfoil._Bundle(
        domain=raw["host"],
        digest=raw["digest"],
        report_format=raw["enclaveAttestationReport"]["format"],
        report_body_b64=raw["enclaveAttestationReport"]["body"],
        sigstore_bundle=raw["sigstoreBundle"],
        enclave_cert_pem=raw["enclaveCert"],
        vcek_b64="",
    )


def test_per_host_bundle_fully_attested(per_host_bundle, monkeypatch):
    expected = per_host_bundle.sev_report().report_data[:32].hex()
    monkeypatch.setattr(tinfoil, "_live_tls_spki_sha256", lambda host, **kw: expected)
    report = tinfoil.verify_bundle(
        per_host_bundle, model="gpt-oss-120b",
        repo="tinfoilsh/confidential-gpt-oss-120b",
    )
    assert report.valid, report.error
    assert report.scorecard.runtime_config_fully_attested is True
    cfg = report.details["attested_config"]
    assert cfg["total_env_external"] == 0
    assert cfg["total_secrets_external"] == 0
    assert cfg["containers"][0]["image_pinned_by_digest"] is True


def test_per_host_rejects_wrong_repo_identity(per_host_bundle):
    with pytest.raises(Exception):
        tinfoil.verify_bundle(
            per_host_bundle, model="gpt-oss-120b",
            repo="tinfoilsh/confidential-model-router",  # wrong repo for this bundle
        )


def test_tinfoil_models_catalog_shape():
    for model, (host, repo) in tinfoil.TINFOIL_MODELS.items():
        assert isinstance(host, str) and host
        assert repo.startswith("tinfoilsh/confidential-") or model == "router"
