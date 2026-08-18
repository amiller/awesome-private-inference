"""Tinfoil attestation verifier.

Trust chain we re-verify (bundle path):
  1. Fetch ATC bundle: {domain, enclaveAttestationReport, digest, sigstoreBundle, vcek, enclaveCert}
  2. Decompress + parse the SEV-SNP report (predicate sev-snp-guest/v2)
  3. Verify the sigstore-signed in-toto statement for the bundle's digest under
     the GitHub Actions identity for tinfoilsh/confidential-model-router.
     Extract `snp_measurement` from the predicate.
  4. Compare predicate snp_measurement == report.measurement.
  5. Open a live TLS connection to bundle.domain; assert
     sha256(SPKI) == report_data[:32].
  6. Decode the bundle's enclaveCert SANs (dcode format) and assert the
     embedded HPKE pubkey == report_data[32:64] and the embedded "hatt"
     hash == sha256(format||body) of the attestation document.

Out of scope for v1:
  - VCEK chain verification to AMD's Genoa root (we trust the report's
    self-claimed measurement to be checked structurally + by sigstore equality).
  - HPKE handshake to actually encrypt a prompt.
  - Per-request client nonce — Tinfoil's report_data has no nonce slot.
"""
from __future__ import annotations

import base64
import gzip
import hashlib
import json
import re
import socket
import ssl
import threading
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import requests
import yaml
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from sigstore.models import Bundle as SigstoreBundle
from sigstore.verify import Verifier as SigstoreVerifier
from sigstore.verify import policy as sigstore_policy

from . import tinfoil_sev
from .common import AttestationReport, ScoreCard, now_iso

DEFAULT_BASE_URL = "https://api.tinfoil.sh/v1"
ATC_BUNDLE_URL = "https://atc.tinfoil.sh/attestation"
DEFAULT_REPO = "tinfoilsh/confidential-model-router"
GH_OIDC_ISSUER = "https://token.actions.githubusercontent.com"
GITHUB_PROXY = "https://github-proxy.tinfoil.sh"
ATT_DOC_PATH = "/.well-known/tinfoil-attestation"

# Per-model enclave catalog: model_name → (host, repo).
# Mirrors tinfoilsh/confidential-model-router/config.yml. Each entry uses the
# first enclave host from that catalog.
TINFOIL_MODELS: Dict[str, Tuple[str, str]] = {
    "router": ("inference.tinfoil.sh", "tinfoilsh/confidential-model-router"),
    "gpt-oss-120b": ("gpt-oss-120b-0.inf6.tinfoil.sh", "tinfoilsh/confidential-gpt-oss-120b"),
    "llama3-3-70b": ("llama3-3-70b.tinfoil.containers.tinfoil.dev", "tinfoilsh/confidential-llama3-3-70b"),
    "gemma4-31b": ("gemma4-31b-inf6.tinfoil.containers.tinfoil.dev", "tinfoilsh/confidential-gemma4-31b"),
    "deepseek-v4-pro": ("deepseek-v4-pro.tinfoil.containers.tinfoil.dev", "tinfoilsh/confidential-deepseek-v4-pro"),
    "kimi-k2-6": ("kimi-k2-6.tinfoil.containers.tinfoil.dev", "tinfoilsh/confidential-kimi-k2-6"),
}

PREDICATE_SEV_V2 = "https://tinfoil.sh/predicate/sev-snp-guest/v2"
PREDICATE_MULTIPLATFORM_V1 = "https://tinfoil.sh/predicate/snp-tdx-multiplatform/v1"


def _san_regex(repo: str) -> re.Pattern[str]:
    return re.compile(
        r"^https://github\.com/" + re.escape(repo) +
        r"/\.github/workflows/[^@]+@refs/tags/[^@]+$"
    )


@dataclass
class _Bundle:
    domain: str
    digest: str
    report_format: str
    report_body_b64: str
    sigstore_bundle: dict
    enclave_cert_pem: str
    vcek_b64: str

    @classmethod
    def from_json(cls, raw: dict) -> "_Bundle":
        rep = raw["enclaveAttestationReport"]
        return cls(
            domain=raw["domain"],
            digest=raw["digest"],
            report_format=rep["format"],
            report_body_b64=rep["body"],
            sigstore_bundle=raw["sigstoreBundle"],
            enclave_cert_pem=raw["enclaveCert"],
            vcek_b64=raw["vcek"],
        )

    def att_doc_hash(self) -> str:
        return hashlib.sha256((self.report_format + self.report_body_b64).encode()).hexdigest()

    def sev_report(self) -> tinfoil_sev.SnpReport:
        if self.report_format != PREDICATE_SEV_V2:
            raise ValueError(f"unsupported predicate {self.report_format} (only SEV-SNP v2 today)")
        return tinfoil_sev.parse(gzip.decompress(base64.b64decode(self.report_body_b64)))


class _SanRegexIdentity:
    """sigstore-python policy that matches a SAN URI against a regex.

    The upstream `policy.Identity` does exact-string matching; Tinfoil pins
    cert identity to a tag-prefixed regex, mirroring the Go reference.
    """

    def __init__(self, pattern: re.Pattern[str], issuer: str) -> None:
        self._pattern = pattern
        self._issuer = sigstore_policy.OIDCIssuer(issuer)

    def verify(self, cert: x509.Certificate) -> None:
        self._issuer.verify(cert)
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        for san in san_ext.get_values_for_type(x509.UniformResourceIdentifier):
            if self._pattern.match(san):
                return
        raise ValueError(
            f"no SAN matches {self._pattern.pattern}; SANs: "
            f"{san_ext.get_values_for_type(x509.UniformResourceIdentifier)}"
        )


_sigstore_verifier: Optional[SigstoreVerifier] = None
_sigstore_lock = threading.Lock()


def _get_sigstore_verifier() -> SigstoreVerifier:
    """Cache the sigstore verifier — TUF metadata refresh is expensive and races
    when multiple threads init concurrently."""
    global _sigstore_verifier
    with _sigstore_lock:
        if _sigstore_verifier is None:
            _sigstore_verifier = SigstoreVerifier.production()
        return _sigstore_verifier


def _verify_sigstore(bundle: _Bundle, repo: str) -> Tuple[Dict[str, Any], str]:
    """Verify the bundle's sigstore DSSE for `repo` and return (predicate, predicate_type)."""
    sb = SigstoreBundle.from_json(json.dumps(bundle.sigstore_bundle).encode())
    pol = _SanRegexIdentity(_san_regex(repo), GH_OIDC_ISSUER)
    payload_type, payload = _get_sigstore_verifier().verify_dsse(bundle=sb, policy=pol)
    if payload_type != "application/vnd.in-toto+json":
        raise ValueError(f"unexpected DSSE payload type {payload_type}")
    statement = json.loads(payload)
    subjects = statement.get("subject") or []
    if not any(s.get("digest", {}).get("sha256") == bundle.digest for s in subjects):
        raise ValueError(f"sigstore subject digests {subjects!r} do not include {bundle.digest}")
    return statement["predicate"], statement["predicateType"]


@dataclass
class _ConfigAudit:
    cvm_version: str
    container_count: int
    containers: List[Dict[str, Any]]
    total_env_external: int  # string-form env entries → external-config disk
    total_secrets_external: int

    @property
    def fully_attested(self) -> bool:
        return self.total_env_external == 0 and self.total_secrets_external == 0


def _audit_attested_config(predicate: Dict[str, Any]) -> _ConfigAudit:
    """Decode the predicate's attested /config.yml, verify its hash binds to the
    cmdline (which is itself in the launch measurement), and tally env/secret
    slots that pull values from the unattested external-config disk.

    The cmdline carries `tinfoil-config-hash=<sha256>`; the predicate also
    carries the raw config bytes. We require both fields and that they agree.
    """
    if "config" not in predicate or "cmdline" not in predicate:
        raise ValueError("sigstore predicate missing config or cmdline")
    config_bytes = base64.b64decode(predicate["config"])
    actual = hashlib.sha256(config_bytes).hexdigest()
    m = re.search(r"tinfoil-config-hash=([0-9a-f]{64})", predicate["cmdline"])
    if not m:
        raise ValueError("cmdline has no tinfoil-config-hash")
    if m.group(1) != actual:
        raise ValueError(
            f"attested config hash mismatch: cmdline={m.group(1)} sha256(config)={actual}"
        )

    cfg = yaml.safe_load(config_bytes) or {}
    containers_raw = cfg.get("containers") or []
    audit_entries: List[Dict[str, Any]] = []
    total_env_external = 0
    total_secrets_external = 0
    for c in containers_raw:
        env_external: List[str] = []
        env_attested: List[str] = []
        for entry in c.get("env") or []:
            if isinstance(entry, str):
                env_external.append(entry)
            elif isinstance(entry, dict):
                env_attested.extend(entry.keys())
        secrets = list(c.get("secrets") or [])
        total_env_external += len(env_external)
        total_secrets_external += len(secrets)
        audit_entries.append({
            "name": c.get("name"),
            "image": c.get("image"),
            "image_pinned_by_digest": "@sha256:" in (c.get("image") or ""),
            "env_external": env_external,
            "env_attested": env_attested,
            "secrets_external": secrets,
        })
    return _ConfigAudit(
        cvm_version=str(cfg.get("cvm-version", "")),
        container_count=len(containers_raw),
        containers=audit_entries,
        total_env_external=total_env_external,
        total_secrets_external=total_secrets_external,
    )


def _extract_snp_measurement(predicate: dict, predicate_type: str) -> str:
    if predicate_type in (PREDICATE_MULTIPLATFORM_V1,):
        return predicate["snp_measurement"]
    if predicate_type == PREDICATE_SEV_V2:
        return predicate["snp_measurement"]
    raise ValueError(f"unsupported predicate type {predicate_type}")


def _decode_dcode(sans: List[str], prefix: str) -> bytes:
    """Decode `NN<base32>.<prefix>.tinfoil.sh` SAN chunks into bytes."""
    pat = "." + prefix + "."
    chunks: List[Tuple[int, str]] = []
    for s in sans:
        if pat not in s:
            continue
        first = s.split(".")[0]
        if len(first) < 2:
            continue
        chunks.append((int(first[:2]), first[2:]))
    if not chunks:
        raise ValueError(f"no SAN with prefix {prefix}")
    chunks.sort()
    combined = "".join(c for _, c in chunks)
    pad = "=" * ((8 - len(combined) % 8) % 8)
    return base64.b32decode(combined.upper() + pad)


def _live_tls_spki_sha256(host: str, port: int = 443, timeout: float = 10.0) -> str:
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            der = ssock.getpeercert(binary_form=True)
    cert = x509.load_der_x509_certificate(der)
    spki = cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(spki).hexdigest()


def _spki_sha256_from_pem(pem: str) -> str:
    cert = x509.load_pem_x509_certificate(pem.encode())
    spki = cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(spki).hexdigest()


def _bundle_san_uris(pem: str) -> List[str]:
    cert = x509.load_pem_x509_certificate(pem.encode())
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    return [d.value for d in san]


def fetch_bundle(url: str = ATC_BUNDLE_URL, timeout: int = 30) -> _Bundle:
    resp = requests.get(url, timeout=timeout)
    resp.raise_for_status()
    return _Bundle.from_json(resp.json())


def _fetch_enclave_attestation(host: str, timeout: int = 30) -> Tuple[str, str]:
    """GET https://<host>/.well-known/tinfoil-attestation -> (format, body_b64)."""
    resp = requests.get(f"https://{host}{ATT_DOC_PATH}", timeout=timeout)
    resp.raise_for_status()
    j = resp.json()
    return j["format"], j["body"]


ROUTER_CONFIG_URL = (
    "https://raw.githubusercontent.com/tinfoilsh/confidential-model-router/main/config.yml"
)
CATALOG_URL = "https://inference.tinfoil.sh/v1/models"


def model_repo_anchor(timeout: int = 30) -> Dict[str, Any]:
    """Check every served model against the router's model -> repo trust anchor.

    Tinfoil's per-model enclaves stopped being publicly reachable in August 2026,
    and their hostnames now live in Tinfoil's backend rather than in the attested
    config, so a third party can no longer attest the enclave that runs a prompt.
    What is still checkable is that each model the router serves is pinned to a
    named confidential-* repo — an unpinned model would be one served from
    something nobody agreed to review.

    Weaker than the enclave probe it replaces, and differently bound: this anchor
    is a repo file compiled into the router release (sigstore attests digest <->
    repo), NOT the hardware-bound /config.yml, which carries only containers,
    shim, and machine shape.
    """
    pinned = (yaml.safe_load(requests.get(ROUTER_CONFIG_URL, timeout=timeout).text) or {}).get(
        "models") or {}
    served = [m["id"] for m in requests.get(CATALOG_URL, timeout=timeout).json().get("data", [])]
    unpinned = sorted(m for m in served if m not in pinned)
    return {
        "models_served": len(served),
        "models_pinned": len(pinned),
        "models_unpinned": unpinned,
        "repos": sorted({v["repo"] for v in pinned.values() if isinstance(v, dict) and "repo" in v}),
    }


def _fetch_sigstore_bundle_for_repo(repo: str, timeout: int = 30) -> Tuple[str, dict]:
    """Fetch latest release digest + sigstore bundle from github-proxy."""
    rel = requests.get(f"{GITHUB_PROXY}/repos/{repo}/releases/latest", timeout=timeout)
    rel.raise_for_status()
    tag = rel.json()["tag_name"]
    digest_resp = requests.get(
        f"{GITHUB_PROXY}/repos/{repo}/releases/download/{tag}/tinfoil.hash", timeout=timeout
    )
    digest_resp.raise_for_status()
    digest = digest_resp.text.strip()
    att_resp = requests.get(
        f"{GITHUB_PROXY}/repos/{repo}/attestations/sha256:{digest}", timeout=timeout
    )
    att_resp.raise_for_status()
    atts = att_resp.json().get("attestations") or []
    if not atts:
        raise ValueError(f"no sigstore attestations for {repo}@{digest}")
    return digest, atts[0]["bundle"]


def _fetch_live_cert_pem(host: str, port: int = 443, timeout: float = 10.0) -> str:
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            der = ssock.getpeercert(binary_form=True)
    cert = x509.load_der_x509_certificate(der)
    return cert.public_bytes(Encoding.PEM).decode()


def fetch_per_host_bundle(host: str, repo: str, timeout: int = 30) -> _Bundle:
    """Build a `_Bundle` from per-host attestation + GitHub-published sigstore data
    + a live TLS cert. Used for model enclaves that don't expose an ATC bundle."""
    fmt, body = _fetch_enclave_attestation(host, timeout=timeout)
    digest, sigstore_bundle = _fetch_sigstore_bundle_for_repo(repo, timeout=timeout)
    cert_pem = _fetch_live_cert_pem(host, timeout=timeout)
    return _Bundle(
        domain=host,
        digest=digest,
        report_format=fmt,
        report_body_b64=body,
        sigstore_bundle=sigstore_bundle,
        enclave_cert_pem=cert_pem,
        vcek_b64="",
    )


def verify_bundle(bundle: _Bundle, *, model: str = "", repo: str = DEFAULT_REPO) -> AttestationReport:
    """Run all checks on a fetched bundle and return an AttestationReport.

    The model parameter is just a label — Tinfoil attests the router enclave,
    which serves all models under the same measurement.
    """
    started = time.time()
    sc = ScoreCard(client_nonce_supported=False)  # report_data has no nonce slot
    details: Dict[str, Any] = {
        "domain": bundle.domain,
        "digest": bundle.digest,
        "predicate": bundle.report_format,
        "repo": repo,
    }

    report = bundle.sev_report()
    details["sev"] = {
        "version": report.version,
        "policy_hex": hex(report.policy),
        "debug": report.debug,
        "vmpl": report.vmpl,
        "measurement": report.measurement_hex,
        "report_data": report.report_data_hex,
    }
    if report.debug:
        return _err(model, "SEV report has DEBUG bit set", details, started, sc)

    predicate, predicate_type = _verify_sigstore(bundle, repo)
    details["sigstore_predicate_type"] = predicate_type
    sigstore_measurement = _extract_snp_measurement(predicate, predicate_type)
    details["sigstore_measurement"] = sigstore_measurement
    if sigstore_measurement != report.measurement_hex:
        return _err(
            model,
            f"measurement mismatch: sigstore={sigstore_measurement} report={report.measurement_hex}",
            details, started, sc,
        )
    sc.code_measurement_reproducible = True

    audit = _audit_attested_config(predicate)
    details["attested_config"] = {
        "cvm_version": audit.cvm_version,
        "container_count": audit.container_count,
        "total_env_external": audit.total_env_external,
        "total_secrets_external": audit.total_secrets_external,
        "containers": audit.containers,
    }
    sc.runtime_config_fully_attested = audit.fully_attested

    sans = _bundle_san_uris(bundle.enclave_cert_pem)
    details["enclave_cert_sans_count"] = len(sans)
    bundle_spki = _spki_sha256_from_pem(bundle.enclave_cert_pem)
    details["enclave_cert_spki_sha256"] = bundle_spki
    expected_tls_hash = report.report_data[:32].hex()
    if bundle_spki != expected_tls_hash:
        return _err(
            model,
            f"bundle enclaveCert SPKI {bundle_spki} != report_data[:32] {expected_tls_hash}",
            details, started, sc,
        )

    san_strings = [s for s in sans if isinstance(s, str)]
    hpke_from_san = _decode_dcode(san_strings, "hpke").hex()
    if hpke_from_san != report.report_data[32:64].hex():
        return _err(
            model,
            f"HPKE pubkey mismatch: SAN={hpke_from_san} report={report.report_data[32:64].hex()}",
            details, started, sc,
        )
    details["hpke_pubkey"] = hpke_from_san
    sc.hpke_pubkey_attested = any(b != 0 for b in report.report_data[32:64])

    expected_doc_hash = bundle.att_doc_hash()
    hatt_from_san = _decode_dcode(san_strings, "hatt").decode()
    details["att_doc_hash"] = expected_doc_hash
    if hatt_from_san != expected_doc_hash:
        return _err(
            model,
            f"hatt SAN {hatt_from_san} != sha256(format||body) {expected_doc_hash}",
            details, started, sc,
        )

    live_spki = _live_tls_spki_sha256(bundle.domain)
    details["live_tls_spki_sha256"] = live_spki
    sc.tls_pubkey_pinned = (live_spki == expected_tls_hash)
    if not sc.tls_pubkey_pinned:
        return _err(
            model,
            f"live TLS SPKI {live_spki} != report_data[:32] {expected_tls_hash}",
            details, started, sc,
        )

    return AttestationReport(
        provider="tinfoil",
        model=model or bundle.domain,
        valid=True,
        verified_at=now_iso(),
        attestation_type="tinfoil-sev-snp-v2",
        signing_address="",
        signing_public_key=hpke_from_san,
        signing_algo="hpke",
        scorecard=sc,
        details=details,
        latency_s=round(time.time() - started, 2),
    )


def _err(
    model: str, msg: str, details: Dict[str, Any], started: float, sc: ScoreCard
) -> AttestationReport:
    return AttestationReport(
        provider="tinfoil",
        model=model,
        valid=False,
        verified_at=now_iso(),
        attestation_type="tinfoil-sev-snp-v2",
        scorecard=sc,
        details=details,
        error=msg,
        latency_s=round(time.time() - started, 2),
    )


def verify(api_key: str, base_url: str, model: str) -> AttestationReport:
    """Standard verifier entry point matching probes/attestation.py contract.

    Tinfoil's attestation is fully public — `api_key` is unused for this step
    (it's only needed for catalog/inference probes).

    Dispatch:
      - "router" or unknown model → ATC bundle path (verifies the gateway enclave).
      - Known model name in TINFOIL_MODELS → per-host path (verifies the actual
        model enclave that runs the user's prompt).
    """
    del api_key, base_url
    if model in TINFOIL_MODELS and model != "router":
        host, repo = TINFOIL_MODELS[model]
        return verify_bundle(fetch_per_host_bundle(host, repo), model=model, repo=repo)

    report = verify_bundle(fetch_bundle(), model=model or "router")
    # The per-model enclaves went unreachable in Aug 2026, so this is what is left
    # of per-model coverage: every served model must name a repo in the anchor.
    anchor = model_repo_anchor()
    report.details.update(anchor)
    if anchor["models_unpinned"]:
        report.valid = False
        report.error = (
            f"router serves {len(anchor['models_unpinned'])} model(s) with no repo pin in the "
            f"trust anchor: {', '.join(anchor['models_unpinned'])}"
        )
    return report
