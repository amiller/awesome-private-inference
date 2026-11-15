"""Offline dstack TDX quote and event-log primitives.

Parsing and replay only: no network, no collateral fetch. Quote fields come
from dcap-qvl's offline parser (`parse_quote`); the event-log replay mirrors
dstack's cc-eventlog and teep's ReplayEventLog (internal/attestation/eventlog.go),
which itself mirrors dstack-TEE/private-ai-gateway src/aci/verifier/dstack.rs.

A dstack runtime event (type 0x08000001) authenticates its own name and payload:
its RTMR digest must equal SHA384(le32(event_type) || ':' || event || ':' ||
payload) and the stored digest must match that recomputation, so free-text
fields that later checks read (app-id, compose-hash, os-image-hash) cannot be
swapped while the replay still matches the quote.
"""
from __future__ import annotations

import asyncio
import hashlib
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List

DSTACK_RUNTIME_EVENT_TYPE = 0x08000001
# teep tee_tcb_current parity: every other Intel PCS verdict means known-vulnerable
# firmware or missing mitigations, so tcb_current is False with advisories retained.
TCB_CURRENT_STATUSES = frozenset({"UpToDate"})
RTMR_COUNT = 4
RTMR_LEN = 48


class EventLogError(ValueError):
    """The event log is malformed or self-inconsistent; replay is rejected."""


def parse_quote(quote_hex: str) -> Dict[str, str]:
    """Offline-parse a TDX quote body. Returns hex fields (no 0x prefix).

    Raises on any structural failure; callers must not fall back to trusting
    provider-parsed fields.
    """
    import dcap_qvl  # lazy: only the nearai extra provides it

    raw = bytes.fromhex(quote_hex.removeprefix("0x"))
    report = dcap_qvl.parse_quote(raw).report
    fields = {
        "mrtd": report.mr_td.hex(),
        "rtmr0": report.rt_mr0.hex(),
        "rtmr1": report.rt_mr1.hex(),
        "rtmr2": report.rt_mr2.hex(),
        "rtmr3": report.rt_mr3.hex(),
        "mrconfigid": report.mr_config_id.hex(),
        "report_data": report.report_data.hex(),
        "td_attributes": report.td_attributes.hex(),
        "mrseam": report.mr_seam.hex(),
    }
    for name in ("mrtd", "rtmr0", "rtmr1", "rtmr2", "rtmr3", "mrseam"):
        if len(fields[name]) != 2 * RTMR_LEN:
            raise ValueError(f"quote field {name} has unexpected length {len(fields[name]) // 2}")
    return fields


def _run(coro):
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    with ThreadPoolExecutor(max_workers=1) as ex:
        return ex.submit(asyncio.run, coro).result()


def dcap_verify(quote_hex: str):
    """dcap-qvl collateral fetch + appraisal (Intel PCS); errors propagate."""
    import dcap_qvl
    return _run(dcap_qvl.get_collateral_and_verify(bytes.fromhex(quote_hex.removeprefix("0x"))))


def quote_debug_disabled(quote_hex: str) -> bool:
    return tee_debug_disabled(parse_quote(quote_hex)["td_attributes"])


def tee_debug_disabled(td_attributes_hex: str) -> bool:
    """TD_ATTRIBUTES byte 0 bit 0 (Intel TDX Module ABI; teep tdxDebugBit).

    Set means a debug TD whose memory the host can inspect.
    """
    attrs = bytes.fromhex(td_attributes_hex.removeprefix("0x"))
    if len(attrs) != 8:
        raise ValueError(f"TD_ATTRIBUTES must be 8 bytes, got {len(attrs)}")
    return not (attrs[0] & 0x01)


def runtime_event_digest(event: Dict) -> bytes:
    """SHA384(le32(event_type) || ':' || event || ':' || payload_bytes)."""
    event_type = event["event_type"]
    if not isinstance(event_type, int) or not 0 <= event_type < 2**32:
        raise EventLogError(f"runtime event {event.get('event')!r}: bad event_type")
    try:
        payload = bytes.fromhex(str(event["event_payload"]).removeprefix("0x"))
        name = event["event"].encode()
    except (KeyError, ValueError) as exc:
        raise EventLogError(f"runtime event {event.get('event')!r}: {exc}") from exc
    h = hashlib.sha384()
    h.update(event_type.to_bytes(4, "little"))
    h.update(b":")
    h.update(name)
    h.update(b":")
    h.update(payload)
    return h.digest()


def _extend(rtmr: bytes, digest: bytes) -> bytes:
    if len(digest) < RTMR_LEN:
        digest = digest + b"\x00" * (RTMR_LEN - len(digest))
    return hashlib.sha384(rtmr + digest).digest()


def replay_event_log(entries: List[Dict]) -> List[bytes]:
    """Replay entries to all four RTMRs (zero-initialized, SHA384 chains).

    Non-runtime events contribute their stored digest; runtime events must
    recompute from their fields AND match any stored digest. Any malformation
    raises EventLogError — no partial or default result.
    """
    rtmrs = [bytes(RTMR_LEN) for _ in range(RTMR_COUNT)]
    for i, event in enumerate(entries):
        try:
            imr = event["imr"]
        except (KeyError, TypeError) as exc:
            raise EventLogError(f"event {i}: no imr") from exc
        if not isinstance(imr, int) or not 0 <= imr < RTMR_COUNT:
            raise EventLogError(f"event {i}: imr index {imr} out of range [0,3]")
        if event.get("event_type") == DSTACK_RUNTIME_EVENT_TYPE:
            digest = runtime_event_digest(event)
            stored = str(event.get("digest") or "").removeprefix("0x")
            if stored and stored.lower() != digest.hex():
                raise EventLogError(
                    f"runtime event {event.get('event')!r}: stored digest does not "
                    "match its payload")
        else:
            try:
                digest = bytes.fromhex(str(event["digest"]).removeprefix("0x"))
            except (KeyError, ValueError) as exc:
                raise EventLogError(f"event {i}: invalid stored digest: {exc}") from exc
        rtmrs[imr] = _extend(rtmrs[imr], digest)
    return rtmrs


def replayed_registers(entries: List[Dict]) -> Dict[str, str]:
    rtmrs = replay_event_log(entries)
    return {f"rtmr{i}": rtmrs[i].hex() for i in range(RTMR_COUNT)}


def runtime_events(entries: List[Dict], name: str) -> List[str]:
    """Authenticated payload hex of every runtime event with this name."""
    payloads = []
    for event in entries:
        if event.get("imr") == 3 and event.get("event_type") == DSTACK_RUNTIME_EVENT_TYPE \
                and event.get("event") == name:
            runtime_event_digest(event)  # rejects payload/digest disagreement
            payloads.append(str(event["event_payload"]).removeprefix("0x").lower())
    return payloads


def single_runtime_event(entries: List[Dict], name: str) -> str:
    """Payload hex of the unique runtime event `name`, or raise EventLogError.

    Dstack emits app-id, compose-hash and os-image-hash exactly once each,
    before boot-mr-done; a duplicate or missing entry is not a value to pick
    from but a malformed log.
    """
    matches = runtime_events(entries, name)
    if len(matches) != 1:
        raise EventLogError(f"runtime event {name!r}: expected exactly one, got {len(matches)}")
    return matches[0]


def attestation_measurements(quote_hex: str, event_log: List[Dict]) -> Dict:
    """Bind one attestation's quote registers to its event log.

    All four RTMRs must equal the replay (teep parity). Returns the quote
    registers plus the log-authenticated app-id, compose-hash and os-image-hash.
    Raises EventLogError on any mismatch or malformation.
    """
    quoted = parse_quote(quote_hex)
    replayed = replayed_registers(event_log)
    mismatches = [f"rtmr{i}" for i in range(RTMR_COUNT)
                  if replayed[f"rtmr{i}"] != quoted[f"rtmr{i}"]]
    if mismatches:
        raise EventLogError(
            f"event log does not replay to the quote: {', '.join(mismatches)} mismatch")
    return {
        "registers": {k: quoted[k] for k in ("mrtd", "rtmr0", "rtmr1", "rtmr2", "rtmr3")},
        "replay_matches_quote": True,
        "log_app_id": single_runtime_event(event_log, "app-id"),
        "log_compose_hash": single_runtime_event(event_log, "compose-hash"),
        "log_os_image_hash": single_runtime_event(event_log, "os-image-hash"),
        "mrconfigid": quoted["mrconfigid"],
    }
