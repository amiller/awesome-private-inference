"""ACI gateway verifier — Attested Confidential Inference (`spec/aci.md`).

One workload serves several hostnames: the quote, the workload keyset and the
measured Compose are shared, and `tee_only_domains` inside that Compose decides
per host whether attested serving is enforced. That last layer is why each
hostname is its own row — on 2026-08-18 `api.redpill.ai` shared everything else
with `tee.redpill.ai` and served 42 models the TEE-only hosts refuse.

`model` is therefore a hostname, and `base_url` is ignored.

Layers proved here:
  nonce_bound              report_data == sha256(statement) over OUR nonce (§3.2)
  report_data_binds_key    the keyset digest in that statement recomputes from
                           the served keyset's JCS form (§3.1)
  tdx_verified             Phala's appraisal service accepts the quote
  compose_hash_committed   the dstack event log replays to the quote's RTMR3 and
                           its compose-hash event equals sha256(app_compose)
  prod_os_image            the RTMR3 os-image-hash resolves, through dstack's
                           published archive, to a bound `is_dev: false`
  attested_serving_enforced  this hostname is in the measured tee_only_domains
  backend_attested         every published session carries §8.2 evidence
  catalog_serves           /v1/models answers with a non-empty catalog

Not proved here, deliberately: the receipt path (needs a paid request) and the
upstream model CVMs (separate workloads; the gateway's sessions record them).
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import tarfile
import urllib.request

import requests
import yaml

from verifiers.common import AttestationReport, ScoreCard, now_iso, sha256_hex
from verifiers.phala_tdx import is_verified, quote_body, verify_tdx_quote

DEFAULT_BASE_URL = "https://tee.redpill.ai"
PURPOSE = "aci.report_data.v1"
OS_IMAGE_ARCHIVE = "https://download.dstack.org/os-images/mr_{}.tar.gz"


def _jcs(obj) -> bytes:
    """ACI artifacts are ASCII keys and integer numbers, where RFC 8785 is just
    compact JSON with sorted keys (spec Appendix A)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _replayed_rtmr3(event_log: list) -> str:
    rtmr = bytes(48)
    for event in event_log:
        if event["imr"] == 3:
            rtmr = hashlib.sha384(rtmr + bytes.fromhex(event["digest"])).digest()
    return rtmr.hex()


def _os_image_is_production(os_image_hash: str) -> bool:
    """`is_dev` is bound to the attested hash: os_image_hash == sha256(sha256sum.txt),
    and sha256sum.txt pins metadata.json, so the download server cannot flip it."""
    request = urllib.request.Request(
        OS_IMAGE_ARCHIVE.format(os_image_hash),
        headers={"User-Agent": "awesome-private-inference/1"},
    )
    with urllib.request.urlopen(request, timeout=180) as response:
        archive = tarfile.open(fileobj=io.BytesIO(response.read()))
    names = archive.getnames()
    sums = archive.extractfile([n for n in names if n.endswith("sha256sum.txt")][0]).read()
    if hashlib.sha256(sums).hexdigest() != os_image_hash:
        raise ValueError(f"os image archive does not hash to {os_image_hash}")
    metadata = archive.extractfile([n for n in names if n.endswith("metadata.json")][0]).read()
    if hashlib.sha256(metadata).hexdigest() not in sums.decode():
        raise ValueError("metadata.json is not listed in sha256sum.txt")
    return not json.loads(metadata)["is_dev"]


def _sessions_carry_evidence(base: str) -> tuple[bool, str]:
    """§8.1 keeps `evidence.digest` on list entries, so one request tells us whether
    any adapter publishes sessions no client can deep-audit (§9.2 steps 2 and 4)."""
    sessions = requests.get(f"{base}/v1/aci/sessions", timeout=60).json()["sessions"]
    missing = [s["verifier_id"] for s in sessions if not (s.get("evidence") or {}).get("digest")]
    counts = {v: missing.count(v) for v in sorted(set(missing))}
    return not missing, f"{len(sessions) - len(missing)}/{len(sessions)} with evidence" + (
        f"; missing: {counts}" if counts else "")


def verify(api_key: str, base_url: str, model: str) -> AttestationReport:
    host = model
    base = f"https://{host}"
    nonce = os.urandom(32).hex()

    report = requests.get(f"{base}/v1/aci/attestation?nonce={nonce}", timeout=60).json()
    attestation = report["attestation"]
    evidence = attestation["evidence"]
    keyset = attestation["workload_keyset"]

    served_digest = report["workload_keyset_digest"]
    keyset_recomputes = served_digest == "sha256:" + sha256_hex(_jcs(keyset))
    statement = '{"keyset_digest":"%s","nonce":"%s","purpose":"%s"}' % (
        served_digest, nonce, PURPOSE)
    nonce_bound = attestation["report_data"] == sha256_hex(statement.encode())

    quote_response = verify_tdx_quote(evidence["quote"])
    body = quote_body(quote_response)
    tdx_verified = is_verified(quote_response)

    event_log = json.loads(evidence["event_log"])
    compose_event = next(e for e in event_log if e.get("event") == "compose-hash")
    compose_bound = (
        _replayed_rtmr3(event_log) == body["rtmr3"].removeprefix("0x")
        and compose_event["event_payload"] == sha256_hex(evidence["app_compose"])
    )

    vm_config = json.loads(evidence["vm_config"])
    app_compose = json.loads(evidence["app_compose"])
    tee_only = _tee_only_domains(app_compose["docker_compose_file"])

    sessions_ok, sessions_note = _sessions_carry_evidence(base)
    catalog = requests.get(f"{base}/v1/models", timeout=60).json()

    scorecard = ScoreCard(
        nonce_bound=nonce_bound,
        report_data_binds_key=keyset_recomputes,
        tdx_verified=tdx_verified,
        compose_hash_committed=compose_bound,
        prod_os_image=_os_image_is_production(vm_config["os_image_hash"]),
        attested_serving_enforced=host in tee_only,
        backend_attested=sessions_ok,
        catalog_serves=bool(catalog.get("data")),
    )
    return AttestationReport(
        provider="aci-gateway", model=host,
        valid=all(getattr(scorecard, f) for f in (
            "nonce_bound", "report_data_binds_key", "tdx_verified",
            "compose_hash_committed", "prod_os_image", "attested_serving_enforced")),
        verified_at=now_iso(), attestation_type="aci-gateway",
        scorecard=scorecard,
        details={
            "workload_keyset_digest": served_digest,
            "os_image": vm_config["image"],
            "compose_hash": compose_event["event_payload"],
            "repo_commit": (attestation.get("source_provenance") or {}).get("repo_commit"),
            "tee_only_domains": tee_only,
            "models": len(catalog.get("data") or []),
            "sessions": sessions_note,
            "tcb_status": (quote_response.get("quote") or {}).get("tcb_status"),
        },
    )


def _tee_only_domains(docker_compose_file: str) -> list:
    """The hosts that force attested serving live in a compose `configs:` block, so
    they are measured with the rest of the file rather than set at runtime."""
    config = yaml.safe_load(docker_compose_file)["configs"]["gateway-config"]["content"]
    return json.loads(config)["middleware"]["tee_only_domains"]
