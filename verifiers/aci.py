"""ACI gateway verifier — Attested Confidential Inference (`spec/aci.md`).

One workload serves several hostnames: the quote, the workload keyset and the
measured Compose are shared, and `tee_only_domains` inside that Compose decides
per host whether attested serving is enforced. That last layer is why each
hostname is its own row — on 2026-08-18 `api.redpill.ai` shared everything else
with `tee.redpill.ai` and served 42 models the TEE-only hosts refuse.

`model` is therefore a hostname, and `base_url` is ignored.

Layers proved here:
  nonce_bound              quoted report_data == sha256(statement) over OUR nonce
  report_data_binds_key    the keyset digest in that statement recomputes from
                           the served keyset's JCS form (§3.1)
  tdx_verified             Phala's appraisal service accepts the quote
  compose_hash_committed   the dstack event log replays to the quote's RTMR3 and
                           its compose-hash event equals sha256(app_compose)
  os_image_archive_declares_production  the RTMR3 os-image-hash resolves to an
                           archive whose metadata says `is_dev: false`
  attested_serving_enforced  this hostname is in the measured tee_only_domains
  sessions_publish_evidence_digests  list entries carry evidence digests
  catalog_nonempty         /v1/models lists at least one model

Not proved here: the receipt path (needs a paid request), upstream model CVMs,
the actual ability to serve the catalog entries. The base OS boot registers
are not compared with independently computed image measurements, so whether
the production OS actually ran remains unproven. The deployed gateway uses
the older ACI draft without workload_id or keyset endorsement. That profile
binds its keyset directly in the quote but does not prove identity continuity.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import tarfile
import urllib.request
from functools import lru_cache
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, utils

import requests
import yaml

from verifiers.common import AttestationReport, ScoreCard, now_iso, public_compose_preimage, sha256_hex
from verifiers.phala_tdx import is_verified, quote_body, verify_tdx_quote

DEFAULT_BASE_URL = "https://tee.redpill.ai"
PURPOSE = "aci.report_data.v1"
OS_IMAGE_ARCHIVE = "https://download.dstack.org/os-images/mr_{}.tar.gz"
MAX_OS_ARCHIVE_BYTES = 32 * 1024 * 1024
MAX_OS_MEMBER_BYTES = 1024 * 1024
MAX_OS_EXPANDED_BYTES = 64 * 1024 * 1024


class ArchiveTooLarge(ValueError):
    """The bounded metadata check cannot inspect this image archive."""


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


def _event_payload(event: dict) -> bytes:
    """dstack serializes event_payload as hex, not as literal text."""
    return bytes.fromhex(event["event_payload"].removeprefix("0x"))


def _events_bind_payloads(event_log: list) -> bool:
    """dstack cc-eventlog V1: SHA384(native LE u32 || ':' || name || ':' || payload).

    Boot IMR 0-2 entries can be stripped; require preimages for every IMR3 entry.
    See dstack cc-eventlog/src/lib.rs at cfa4cc4, lines 33-88.
    """
    try:
        for event in event_log:
            if event["imr"] != 3:
                continue
            event_type = event["event_type"]
            if not isinstance(event_type, int) or not 0 <= event_type < 2**32:
                return False
            preimage = (event_type.to_bytes(4, "little") + b":" +
                        event["event"].encode() + b":" + _event_payload(event))
            if hashlib.sha384(preimage).hexdigest() != event["digest"].removeprefix("0x").lower():
                return False
    except (KeyError, ValueError, TypeError, AttributeError):
        return False
    return True


def _unique_event(event_log: list, name: str) -> dict | None:
    matches = [e for e in event_log if e.get("imr") == 3 and e.get("event") == name]
    return matches[0] if len(matches) == 1 else None


def _event_precedes_boot_boundary(event_log: list, event: dict | None) -> bool:
    boundary = _unique_event(event_log, "boot-mr-done")
    return bool(event is not None and boundary is not None and
                event_log.index(event) < event_log.index(boundary))


def _quote_binds_digest(body: dict, digest: str) -> bool:
    """TDX report_data is 64 bytes: the ACI digest followed by zero padding."""
    try:
        raw = bytes.fromhex(body["reportdata"].removeprefix("0x"))
        return raw == bytes.fromhex(digest) + bytes(32)
    except (KeyError, ValueError, TypeError, AttributeError):
        return False


def _keyset_identity(keyset: dict) -> str:
    return "sha256:" + sha256_hex(_jcs(keyset["workload_identity"]["public_key"]))


def _endorsement_verifies(attestation: dict, digest: str) -> bool:
    """ACI §4.3 requires the identity key to endorse each rotating keyset."""
    try:
        key = attestation["workload_keyset"]["workload_identity"]["public_key"]
        endorsement = attestation["keyset_endorsement"]
        if key["algo"] != endorsement["algo"]:
            return False
        payload = _jcs({"purpose": "aci.keyset.endorsement.v1",
                        "workload_keyset_digest": digest})
        signature = bytes.fromhex(endorsement["value"])
        public_key = bytes.fromhex(key["public_key"].removeprefix("0x"))
        if key["algo"] == "ed25519":
            ed25519.Ed25519PublicKey.from_public_bytes(public_key).verify(signature, payload)
        elif key["algo"] == "ecdsa-secp256k1":
            if len(signature) != 64:
                return False
            r, s = int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")
            ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), public_key).verify(
                utils.encode_dss_signature(r, s), hashlib.sha256(payload).digest(),
                ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        else:
            return False
        return True
    except (KeyError, ValueError, TypeError, InvalidSignature):
        return False


def _manifest_binds_metadata(sums: bytes, metadata: bytes) -> bool:
    """Require a sha256sum entry naming metadata.json, not a loose digest substring."""
    expected = hashlib.sha256(metadata).hexdigest()
    try:
        for line in sums.decode("utf-8").splitlines():
            parts = line.split(maxsplit=1)
            if len(parts) != 2:
                continue
            digest, filename = parts
            if (digest.lower() == expected and
                    filename.lstrip("*").removeprefix("./").rsplit("/", 1)[-1] == "metadata.json"):
                return True
    except UnicodeDecodeError:
        return False
    return False


@lru_cache(maxsize=128)
def _os_image_is_production(os_image_hash: str) -> bool:
    """`is_dev` is bound to the attested hash: os_image_hash == sha256(sha256sum.txt),
    and sha256sum.txt pins metadata.json, so the download server cannot flip it."""
    request = urllib.request.Request(
        OS_IMAGE_ARCHIVE.format(os_image_hash),
        headers={"User-Agent": "awesome-private-inference/1"},
    )
    with urllib.request.urlopen(request, timeout=180) as response:
        length = response.headers.get("Content-Length")
        if length is not None and int(length) > MAX_OS_ARCHIVE_BYTES:
            raise ArchiveTooLarge("OS image archive exceeds 32 MiB compressed cap")
        compressed = response.read(MAX_OS_ARCHIVE_BYTES + 1)
    if len(compressed) > MAX_OS_ARCHIVE_BYTES:
        raise ArchiveTooLarge("OS image archive exceeds 32 MiB compressed cap")
    contents = {"sha256sum.txt": [], "metadata.json": []}
    expanded = 0
    with tarfile.open(fileobj=io.BytesIO(compressed), mode="r|gz") as archive:
        for member in archive:
            expanded += member.size
            if expanded > MAX_OS_EXPANDED_BYTES:
                raise ArchiveTooLarge("OS image archive exceeds 64 MiB expanded cap")
            for filename in contents:
                if member.name.endswith(filename):
                    if member.size > MAX_OS_MEMBER_BYTES:
                        raise ArchiveTooLarge("OS image metadata exceeds 1 MiB member cap")
                    if not member.isfile():
                        raise ValueError("OS image metadata member is not a regular file")
                    contents[filename].append(archive.extractfile(member).read())
    if any(len(entries) != 1 for entries in contents.values()):
        raise ValueError("OS image archive missing unique metadata or manifest")
    sums = contents["sha256sum.txt"][0]
    metadata = contents["metadata.json"][0]
    if hashlib.sha256(sums).hexdigest() != os_image_hash:
        raise ValueError(f"os image archive does not hash to {os_image_hash}")
    if not _manifest_binds_metadata(sums, metadata):
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
    # The deployed draft has no workload_id/endorsement; the newer aci/1
    # profile adds both. Never silently accept a partial newer profile.
    workload_id = report.get("workload_id")
    identity_ok = True
    if workload_id is not None:
        try:
            identity_ok = (workload_id == _keyset_identity(keyset) and
                           _endorsement_verifies(attestation, served_digest))
        except (KeyError, ValueError, TypeError):
            identity_ok = False
    statement = {"keyset_digest": served_digest, "nonce": nonce, "purpose": PURPOSE}
    if workload_id is not None:
        statement = {"workload_id": workload_id, "workload_keyset_digest": served_digest,
                     "nonce": nonce, "purpose": PURPOSE}
        del statement["keyset_digest"]
    expected_report_data = sha256_hex(_jcs(statement))

    quote_response = verify_tdx_quote(evidence["quote"])
    body = quote_body(quote_response)
    tdx_verified = is_verified(quote_response)
    quote_binds = tdx_verified and _quote_binds_digest(body, expected_report_data)
    nonce_bound = (attestation["report_data"].removeprefix("0x").lower() ==
                   expected_report_data and quote_binds)

    event_log = json.loads(evidence["event_log"])
    compose_event = _unique_event(event_log, "compose-hash")
    os_event = _unique_event(event_log, "os-image-hash")
    event_payloads_bound = _events_bind_payloads(event_log)
    event_log_bound = (tdx_verified and event_payloads_bound and
                       _replayed_rtmr3(event_log) == body.get("rtmr3", "").removeprefix("0x").lower())
    compose_bound = (
        event_log_bound and compose_event is not None
        and _event_precedes_boot_boundary(event_log, compose_event)
        and _event_payload(compose_event).hex() == sha256_hex(evidence["app_compose"])
    )

    vm_config = json.loads(evidence["vm_config"])
    os_hash = vm_config["os_image_hash"].removeprefix("0x").lower()
    os_bound = (event_log_bound and os_event is not None and
                _event_payload(os_event).hex() == os_hash)
    app_compose = json.loads(evidence["app_compose"])
    tee_only = _tee_only_domains(app_compose["docker_compose_file"])

    sessions_ok, sessions_note = _sessions_carry_evidence(base)
    catalog = requests.get(f"{base}/v1/models", timeout=60).json()

    archive_status = "not_checked"
    if os_bound:
        try:
            archive_prod = _os_image_is_production(os_hash)
            archive_status = "checked"
        except ArchiveTooLarge:
            archive_prod = None
            archive_status = "size_cap_exceeded"
    else:
        archive_prod = False
        archive_status = "event_binding_failed"
    scorecard = ScoreCard(
        nonce_bound=nonce_bound,
        report_data_binds_key=keyset_recomputes and nonce_bound and identity_ok,
        tdx_verified=tdx_verified,
        compose_hash_committed=compose_bound,
        prod_os_image=None,
        os_image_archive_declares_production=archive_prod,
        attested_serving_enforced=compose_bound and host in tee_only,
        sessions_publish_evidence_digests=sessions_ok,
        catalog_nonempty=bool(catalog.get("data")),
    )
    binding_ok = all(getattr(scorecard, f) is True for f in (
        "nonce_bound", "report_data_binds_key", "tdx_verified", "compose_hash_committed",
        "attested_serving_enforced")) and os_bound
    checked_ok = binding_ok and archive_prod is True
    raw_evidence = {
        "source": f"{base}/v1/aci/attestation",
        "nonce": nonce,
        "api_version": report.get("api_version"),
        "workload_id": workload_id,
        "workload_keyset_digest": served_digest,
        "workload_keyset": keyset,
        "keyset_endorsement": attestation.get("keyset_endorsement"),
        "report_data": attestation.get("report_data"),
        "quote": evidence["quote"],
        "event_log": event_log,
        "vm_config": evidence["vm_config"],
        "source_provenance": attestation.get("source_provenance"),
        "appraisal": {"verified": tdx_verified, "body": body,
                      "tcb_status": (quote_response.get("quote") or {}).get("tcb_status")},
    }
    raw_evidence.update(public_compose_preimage(evidence["app_compose"]))
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
            "compose_hash": (_event_payload(compose_event).hex()
                             if compose_event and event_payloads_bound else None),
            "event_payloads_bound": event_payloads_bound,
            "quote_report_data_bound": quote_binds,
            "os_image_event_bound": os_bound,
            "workload_identity_endorsed": identity_ok if workload_id is not None else None,
            "identity_continuity": "not available in deployed ACI draft" if workload_id is None else "checked",
            "backend_evidence_verified": False,
            "catalog_serving_tested": False,
            "verification_status": "not_checked" if binding_ok and archive_prod is not False else "rejected",
            "verification_reason": (
                "OS archive exceeded bounded metadata check; boot measurements and request path remain unverified"
                if binding_ok and archive_prod is None else
                "OS boot measurements MRTD/RTMR0-2 and request path were not verified"
                if checked_ok else "one or more authenticated quote, event, OS event, or host-policy checks failed"),
            "raw_evidence": raw_evidence,
            "raw_evidence_completeness": (
                "complete" if raw_evidence["app_compose_preimage_status"] == "captured"
                else "partial_sensitive_preimage_withheld"),
            "os_archive_metadata_status": archive_status,
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
