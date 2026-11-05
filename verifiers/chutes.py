"""Chutes direct confidential-inference verifier (api.chutes.ai, Bittensor subnet 64).

This hits the Chutes control plane directly through the E2E discovery and
evidence endpoints.

Fleet census (#7): the full `/e2e/instances/{chute_id}` array is retained and
evidence is fetched for EVERY listed instance, so fleet size is an exact daily
count and per-instance churn (MRTD, matched published configuration row, TCB
status, GPU outcome) is measurable.

Per `-TEE` instance, we verify the crypto core (live-confirmed sound):
  - report_data[0:32] == SHA256(nonce || e2e_pubkey)      (E2E key binding, fresh)
  - report_data[32:64] == SHA256(SPKI of evidence cert)   (attestation-svc cert binding)
  - td_attributes bit0 == 0                                (debug mode disabled)
  - MRTD AND RTMR0-3 match ONE exact published row of
    /servers/tee/measurements (boot RTMR0-2, runtime RTMR3) — recording which
    configuration row matched and the digest of the captured publication
  - TDX quote accepted by Phala's DCAP verifier, plus a local dcap_qvl
    appraisal that keeps the TCB status (UpToDate/OutOfDate) and advisory IDs
    Phala's response does not carry (#18)
  - GPU evidence: the per-GPU evidence blobs are submitted to NVIDIA's public
    NRAS endpoint; every returned JWT is signature-verified against NVIDIA's
    published JWKS, nonce-bound to the TD's report_data[0:32] (which the blobs
    themselves embed — the CPU↔GPU association), and counted against the
    matched row's gpu_count (see verifiers/nvidia_nras.py)

Row verdict semantics: verification_status is "not_checked" (crypto core sound,
serving-code gap below remains) only if EVERY listed instance passes every
check above. Any instance failing a check, running measurements that match no
published row, or yielding no obtainable evidence makes the row "rejected"
with the dissenting instance and reason preserved.

…the headline gap: the serve.py on the prompt-plaintext path is unmeasured
(CFSV-excluded, in no RTMR), and nothing binds which model runs (MRTD/RTMRs are
identical across different -TEE models). So `serving_code_attested` is False by
construction — the operator (or Chutes) can read/exfiltrate the decrypted prompt
AND substitute the model, neither detectable from the quote.
See providers/chutes.md and chutesai/chutes#75.

Quote offsets per chutes-api/api/server/quote.py (td_report = quote[48:]):
td_attributes 120:128, MRTD 136:184, RTMR0-3 328:520, report_data 520:584.
RTMR offsets cross-checked against Phala's independent parse for all 150
retained evidence quotes (2026-11-05).
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import secrets
import time
from functools import lru_cache
from typing import Any, Dict, List, Optional, Tuple

import requests

from pathlib import Path

from .common import (
    AttestationReport, ScoreCard, load_audit_ledger, now_iso,
    sha256_nonce_pubkey_binding,
)
from . import nvidia_nras, phala_tdx

_TEE_AUDITS = Path(__file__).resolve().parents[1] / "data" / "audits" / "chutes_tee.json"

DEFAULT_BASE_URL = "https://api.chutes.ai"

# Model label → chute_id. Add/prune as the catalog rotates.
CHUTE_IDS: Dict[str, str] = {
    "Qwen3-32B-TEE": "ac059e33-eb27-541c-b9a9-24b214036475",
    "gemma-4-31B-TEE": "42ee92ba-a537-5a73-8741-876067750db7",
    "GLM-5.1-TEE": "b048fe26-0352-5c46-acf7-335e527e7f3d",
    "GLM-5.2-TEE": "08901219-159f-55a7-87cf-9d0d02744668",
    "DeepSeek-V3.2-TEE": "398651e1-5f85-5e50-a513-7c5324e8e839",
    "Kimi-K2.6-TEE": "aac09863-35b4-5d9b-9b67-6e6a9d54273a",
}

_GOLDEN_FIELDS = ("name", "version", "fingerprint", "mrtd", "boot_rtmrs",
                  "runtime_rtmrs", "expected_gpus", "gpu_count")


def _parse_quote(quote_b64: str) -> Dict[str, str]:
    decoded = base64.b64decode(quote_b64, validate=True)
    if len(decoded) < 48 + 584:
        raise ValueError("truncated TDX quote body")
    body = decoded[48:]
    return {
        "td_attributes": body[120:128].hex(),
        "mrtd": body[136:184].hex().lower(),
        "rtmr0": body[328:376].hex().lower(),
        "rtmr1": body[376:424].hex().lower(),
        "rtmr2": body[424:472].hex().lower(),
        "rtmr3": body[472:520].hex().lower(),
        "report_data": body[520:584].hex(),  # 64 bytes
    }


def _match_golden_rows(meas: Dict[str, str],
                       golden_entries: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """Exact full-row match: MRTD + boot RTMR0-2 + runtime RTMR3.

    Returns (matching_rows, None) on a match — possibly several rows that share
    the same measurements but differ in fingerprint — or ([], reason) when no
    published row carries these measurements. A row whose boot and runtime
    RTMR0-2 disagree, or that lacks either RTMR set, is ambiguous and never
    matches; the reason names the first such case only when the MRTD matched.
    """
    matches: List[Dict[str, Any]] = []
    mrtd_matched = False
    for row in golden_entries:
        if str(row.get("mrtd") or "").lower() != meas["mrtd"]:
            continue
        mrtd_matched = True
        boot = row.get("boot_rtmrs") or {}
        runtime = row.get("runtime_rtmrs") or {}
        if not boot or not runtime:
            return [], "mrtd-matching row lacks boot_rtmrs/runtime_rtmrs"
        if any(str(boot.get(k) or "").lower() != str(runtime.get(k) or "").lower()
               for k in ("RTMR0", "RTMR1", "RTMR2")):
            return [], "mrtd-matching row has ambiguous boot/runtime RTMR0-2"
        if (str(boot.get("RTMR0") or "").lower() == meas["rtmr0"]
                and str(boot.get("RTMR1") or "").lower() == meas["rtmr1"]
                and str(boot.get("RTMR2") or "").lower() == meas["rtmr2"]
                and str(runtime.get("RTMR3") or "").lower() == meas["rtmr3"]):
            matches.append(row)
    if matches:
        return matches, None
    return [], ("no published configuration row matches mrtd+rtmr0-3"
                if mrtd_matched else "mrtd matches no published configuration row")


def _row_identity(row: Dict[str, Any]) -> Dict[str, Any]:
    return {k: row.get(k) for k in _GOLDEN_FIELDS if k not in ("boot_rtmrs", "runtime_rtmrs")}


def _row_sha256(row: Dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(
        {k: row.get(k) for k in _GOLDEN_FIELDS if k in row},
        sort_keys=True, separators=(",", ":")).encode()).hexdigest()


@lru_cache(maxsize=32)
def _tcb_appraisal(quote_hex: str) -> Dict[str, Any]:
    """Local dcap_qvl appraisal keeping TCB status and advisories.

    Phala's verify response carries no TCB field at all (established live
    2026-11-05 by replaying a retained quote: only body/cert_data/header/
    verified are returned), which is why retained evidence holds tcb_status
    null. Errors propagate to the caller and are recorded per instance.
    """
    import dcap_qvl
    import asyncio

    async def _run():
        return await dcap_qvl.get_collateral_and_verify(bytes.fromhex(quote_hex))

    result = asyncio.run(_run())
    return {"tcb_status": result.status, "advisory_ids": list(result.advisory_ids)}


def _cert_spki_sha256(cert_der_b64: str) -> str:
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    cert = x509.load_der_x509_certificate(base64.b64decode(cert_der_b64))
    spki = cert.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha256(spki).hexdigest().lower()


def verify(api_key: str, base_url: str, model: str) -> AttestationReport:
    started = time.time()
    api_base = base_url.rstrip("/")
    headers = {"Authorization": f"Bearer {api_key}"}
    nonce = secrets.token_hex(32)

    def _fail(err: str, **details) -> AttestationReport:
        return AttestationReport(
            provider="chutes", model=model, valid=False,
            verified_at=now_iso(), attestation_type="chutes-tee",
            error=err, details=details,
            latency_s=round(time.time() - started, 2),
        )

    chute_id = CHUTE_IDS.get(model)
    if not chute_id:
        return _fail(f"unknown chute_id for model {model!r}")

    def _get(path: str) -> Any:
        r = requests.get(f"{api_base}{path}", headers=headers, timeout=90)
        if r.status_code != 200:
            raise RuntimeError(f"HTTP {r.status_code} on {path}: {r.text[:160]}")
        return r.json()

    try:
        golden_response = _get("/servers/tee/measurements")
        instances = _get(f"/e2e/instances/{chute_id}")["instances"]
    except (requests.RequestException, RuntimeError, KeyError) as exc:
        return _fail(f"{type(exc).__name__}: {exc}")
    if not isinstance(instances, list) or not instances:
        return _fail(f"no instances listed for chute {chute_id}")

    golden_entries = [{k: item[k] for k in _GOLDEN_FIELDS if k in item}
                      for item in golden_response]
    golden = {c["mrtd"].lower() for c in golden_entries}
    golden_digest = hashlib.sha256(json.dumps(
        golden_entries, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    golden_publication = {
        "url": f"{api_base}/servers/tee/measurements",
        "captured_at": now_iso(),
        "canonical_json_sha256": hashlib.sha256(json.dumps(
            golden_response, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
        "rows": len(golden_entries),
    }
    audit_set, _ = load_audit_ledger(_TEE_AUDITS, "mrtd")

    census: List[Dict[str, Any]] = []
    jwks: Optional[Dict[str, Any]] = None
    for inst in instances:
        entry: Dict[str, Any] = {
            "instance_id": inst.get("instance_id"), "e2e_pubkey": inst.get("e2e_pubkey"),
        }
        census.append(entry)
        try:
            ev = _get(f"/instances/{entry['instance_id']}/evidence?nonce={nonce}")
        except (requests.RequestException, RuntimeError, KeyError, TypeError) as exc:
            entry.update(outcome="unavailable",
                         reason=f"{type(exc).__name__}: {exc}")
            continue

        entry["quote_b64"] = ev.get("quote")
        entry["certificate_der_b64"] = ev.get("certificate")
        entry["gpu_evidence"] = ev.get("gpu_evidence")
        try:
            q = _parse_quote(ev["quote"])
            cert_spki = _cert_spki_sha256(ev["certificate"])
        except (KeyError, TypeError, ValueError, binascii.Error) as exc:
            entry.update(outcome="rejected",
                         reason=f"malformed quote or evidence certificate: {type(exc).__name__}",
                         verification_status="rejected")
            continue

        entry["measurements"] = {k: q[k] for k in ("mrtd", "rtmr0", "rtmr1", "rtmr2", "rtmr3")}
        entry["report_data_binds_key"] = sha256_nonce_pubkey_binding(
            q["report_data"], nonce, entry["e2e_pubkey"] or "")
        entry["cert_spki_bound"] = q["report_data"][64:128] == cert_spki
        entry["debug_disabled"] = (int(q["td_attributes"], 16) & 1) == 0
        entry["mrtd_in_golden_set"] = q["mrtd"] in golden
        entry["mrtd_audited"] = q["mrtd"] in audit_set
        matched, no_match_reason = _match_golden_rows(q, golden_entries)
        entry["matched_rows"] = [_row_identity(r) for r in matched]
        entry["matched_row_sha256"] = [_row_sha256(r) for r in matched]
        entry["golden_row_full_match"] = bool(matched)
        entry["no_match_reason"] = no_match_reason

        tdx = phala_tdx.verify_tdx_quote(base64.b64decode(ev["quote"]).hex())
        entry["tdx_verified"] = phala_tdx.is_verified(tdx)
        entry["quote_appraisal"] = {
            "verified": entry["tdx_verified"], "body": phala_tdx.quote_body(tdx),
        }
        try:
            entry.update(_tcb_appraisal(base64.b64decode(ev["quote"]).hex()))
            entry["tcb_status_source"] = "dcap_qvl"
        except Exception as exc:  # recorded, never silently None (#18)
            entry["tcb_status_error"] = f"{type(exc).__name__}: {exc}"
        # A plausible detached report_data is not an authenticated binding when
        # the hardware quote itself was rejected.
        entry["report_data_binds_key"] = bool(entry["tdx_verified"] and entry["report_data_binds_key"])

        gpu_counts = {r.get("gpu_count") for r in matched}
        gpu_count = gpu_counts.pop() if len(gpu_counts) == 1 else None
        entry["gpu_count_ambiguous"] = len(gpu_counts) != 1 and bool(matched)
        if entry["gpu_evidence"] in (None, []):
            entry["gpu_attested"] = None
            entry["gpu_reason"] = "no_gpu_evidence_in_response"
        else:
            try:
                if jwks is None:
                    jwks = nvidia_nras.fetch_jwks()
                # CPU↔GPU association: the TD-bound report_data[0:32] is the
                # nonce every GPU evidence blob must embed and every NRAS
                # token must echo (see verifiers/nvidia_nras.py).
                entry["gpu_appraisal"] = nvidia_nras.appraise_gpu_attestation(
                    entry["gpu_evidence"], q["report_data"][:64], jwks, gpu_count)
                entry["gpu_attested"] = entry["gpu_appraisal"]["gpu_attested"]
            except (requests.RequestException, ValueError) as exc:
                # NVIDIA's endpoints unreachable: the GPU layer is unverified,
                # not silently passed. Same distinction the Phala verifier draws
                # between "could not ask" and "quote rejected".
                entry["gpu_attested"] = None
                entry["gpu_reason"] = f"nras_unreachable: {type(exc).__name__}: {exc}"

        failures = [f"{k}=False" for k in
                    ("tdx_verified", "report_data_binds_key", "cert_spki_bound",
                     "debug_disabled") if entry.get(k) is False]
        if entry.get("golden_row_full_match") is False:
            failures.append(str(entry.get("no_match_reason") or "golden_row_full_match"))
        if entry.get("gpu_attested") is False:
            failures.append(f"gpu_appraisal_rejected: {entry['gpu_appraisal'].get('reason')}")
        elif entry.get("gpu_attested") is None:
            # unverified is not a pass: the row can only read not_checked when
            # every layer of every sampled instance actually passed
            failures.append(f"gpu_layer_unverified: {entry.get('gpu_reason')}")
        entry["outcome"] = "verified_core" if not failures else "rejected"
        entry["reason"] = "; ".join(failures) if failures else None

    appraised = [e for e in census if e.get("outcome") in ("verified_core", "rejected")]
    all_pass = bool(census) and all(e["outcome"] == "verified_core" for e in census)

    details: Dict[str, Any] = {
        "shape": "chutes-tee",
        "instance_id": census[0]["instance_id"],
        "mrtd": ((appraised[0].get("measurements") or {}).get("mrtd")
                 if appraised else None),
        "fleet_size": len(census),
        "fleet_size_semantics": (
            "count of instances listed by /e2e/instances at verification time; "
            "the response carries no pagination or total-fleet field, so a "
            "listing cap cannot be ruled out from the response alone"),
        "fleet_all_instances_pass": all_pass,
        "fleet": [{"instance_id": e["instance_id"], "outcome": e["outcome"],
                   "reason": e.get("reason"), "mrtd": (e.get("measurements") or {}).get("mrtd"),
                   "rtmr0": (e.get("measurements") or {}).get("rtmr0"),
                   "rtmr1": (e.get("measurements") or {}).get("rtmr1"),
                   "rtmr2": (e.get("measurements") or {}).get("rtmr2"),
                   "rtmr3": (e.get("measurements") or {}).get("rtmr3"),
                   "matched_rows": e.get("matched_rows"),
                   "no_match_reason": e.get("no_match_reason"),
                   "tcb_status": e.get("tcb_status"),
                   "tcb_status_error": e.get("tcb_status_error"),
                   "advisory_ids": e.get("advisory_ids"),
                   "gpu_attested": e.get("gpu_attested"), "gpu_reason": e.get("gpu_reason")}
                  for e in census],
        "golden_set_sha256": golden_digest,
        "golden_publication": golden_publication,
        "gpu_evidence_count": len(census[0].get("gpu_evidence") or []),
    }

    sc = ScoreCard()
    for field, key in (("tdx_verified", "tdx_verified"),
                       ("report_data_binds_key", "report_data_binds_key")):
        values = [e.get(key) for e in appraised]
        setattr(sc, field, all(values) if values else None)
    sc.nonce_bound = sc.report_data_binds_key
    gpu_values = [e.get("gpu_attested") for e in appraised]
    if any(v is False for v in gpu_values):
        sc.gpu_attested = False
    elif gpu_values and all(v is True for v in gpu_values):
        sc.gpu_attested = True

    details["raw_evidence"] = {
        "source": f"{api_base}/instances/{census[0]['instance_id']}/evidence",
        "chute_id": chute_id, "instance_id": census[0]["instance_id"],
        "nonce": nonce, "e2e_pubkey": census[0]["e2e_pubkey"],
        "quote_b64": census[0].get("quote_b64"),
        "certificate_der_b64": census[0].get("certificate_der_b64"),
        "golden_measurements": golden_entries,
        "golden_set_sha256": golden_digest,
        "golden_publication": golden_publication,
        "fleet_census": [{k: v for k, v in e.items()
                          if k not in ("quote_appraisal",)} for e in census],
    }
    if appraised and "quote_appraisal" in appraised[0]:
        details["raw_evidence"]["quote_appraisal"] = dict(
            appraised[0]["quote_appraisal"], tcb_status=appraised[0].get("tcb_status"))

    # Headline gap: the serve.py on the prompt-plaintext path is unmeasured
    # (CFSV-excluded, in no RTMR), so the operator can read/exfiltrate the decrypted
    # prompt; and with the model in no measured register (MRTD/RTMRs identical across
    # -TEE models) it can also substitute the model. Neither is detectable from the
    # quote. False by construction.
    sc.serving_code_attested = False

    if all_pass:
        details["verification_status"] = "not_checked"
        details["verification_reason"] = (
            "all sampled instances pass the crypto core, but serving code and "
            "selected model are not measured or verified")
    else:
        details["verification_status"] = "rejected"
        dissenting = [f"{e['instance_id']}: {e.get('reason') or e['outcome']}"
                      for e in census if e["outcome"] != "verified_core"]
        details["verification_reason"] = (
            "instance(s) failed appraisal or evidence unavailable — " + "; ".join(dissenting))

    return AttestationReport(
        provider="chutes", model=model, valid=False,
        verified_at=now_iso(), attestation_type="chutes-tee",
        signing_address=census[0]["instance_id"], signing_public_key=census[0]["e2e_pubkey"],
        scorecard=sc, details=details,
        latency_s=round(time.time() - started, 2),
    )
