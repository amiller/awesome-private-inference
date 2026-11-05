"""Fleet census, full-register golden-row matching and TCB retention in the
Chutes adapter. Chutes transport and the NRAS GPU appraisal verdict are
mocked here (their real-evidence paths are covered by test_nvidia_nras.py
and test_chutes_gpu_replay.py); register matching is additionally replayed
against real retained evidence in test_chutes_registers.py."""
import base64
import hashlib

from verifiers import chutes


NONCE = "01" * 32
PUBKEY = "public-key"
CERT_HASH = bytes.fromhex("bb" * 32)
MRTD = bytes.fromhex("aa" * 48)
RTMRS = [bytes([0x11 + i]) * 48 for i in range(4)]
KEY_HASH = hashlib.sha256((NONCE + PUBKEY).encode()).digest()


def _quote_bytes(*, mrtd=MRTD, rtmrs=None, report_data=None):
    rtmrs = rtmrs if rtmrs is not None else RTMRS
    body = bytearray(584)
    body[136:184] = mrtd
    body[328:376] = rtmrs[0]
    body[376:424] = rtmrs[1]
    body[424:472] = rtmrs[2]
    body[472:520] = rtmrs[3]
    body[520:584] = (KEY_HASH if report_data is None else report_data) + CERT_HASH
    return bytes(48) + body


def _quote_b64(**kwargs):
    return base64.b64encode(_quote_bytes(**kwargs)).decode()


GOLDEN_ROW = {
    "name": "8xh200 [10.2.1]", "version": "1.3.1", "fingerprint": None,
    "mrtd": MRTD.hex(),
    "boot_rtmrs": {"RTMR0": RTMRS[0].hex().upper(), "RTMR1": RTMRS[1].hex().upper(),
                   "RTMR2": RTMRS[2].hex().upper(), "RTMR3": "00" * 48},
    "runtime_rtmrs": {"RTMR0": RTMRS[0].hex().upper(), "RTMR1": RTMRS[1].hex().upper(),
                      "RTMR2": RTMRS[2].hex().upper(), "RTMR3": RTMRS[3].hex().upper()},
    "expected_gpus": ["h200"], "gpu_count": 8,
}


def _golden(rows=(GOLDEN_ROW,)):
    return [dict(r) for r in rows]


def _instance(instance_id, pubkey=PUBKEY):
    return {"instance_id": instance_id, "e2e_pubkey": pubkey}


def _evidence(quote=None, gpu_evidence=None):
    return {"quote": quote if quote is not None else _quote_b64(),
            "certificate": "public-certificate",
            "gpu_evidence": (gpu_evidence if gpu_evidence is not None
                             else [{"arch": "HOPPER", "certificate": "x",
                                    "evidence": "eA=="}])}


class Response:
    status_code = 200

    def __init__(self, value):
        self.value = value

    def json(self):
        return self.value


def _run(monkeypatch, golden, instances_evidence,
         tcb={"tcb_status": "UpToDate", "advisory_ids": []}):
    """instances_evidence: list of (instance, evidence) or (instance, error)."""
    instances = [i for i, _ in instances_evidence]
    responses = [golden, {"instances": instances}] + [
        e for _, e in instances_evidence]
    seen = []

    def get(url, *, headers, timeout):
        seen.append(url)
        value = responses.pop(0)
        if isinstance(value, Exception):
            raise value
        return Response(value)

    monkeypatch.setattr(chutes.requests, "get", get)
    monkeypatch.setattr(chutes.secrets, "token_hex", lambda n: NONCE)
    monkeypatch.setattr(chutes, "_cert_spki_sha256", lambda v: CERT_HASH.hex())
    monkeypatch.setattr(chutes, "load_audit_ledger", lambda *a: ({MRTD.hex()}, {}))
    if isinstance(tcb, Exception):
        def fake_tcb(q, exc=tcb):
            raise exc
    else:
        def fake_tcb(q, tcb=tcb):
            return tcb
    monkeypatch.setattr(chutes, "_tcb_appraisal", fake_tcb)
    monkeypatch.setattr(chutes.phala_tdx, "verify_tdx_quote", lambda v: {"quote": {"verified": True}})
    monkeypatch.setattr(chutes.phala_tdx, "is_verified", lambda v: True)
    monkeypatch.setattr(chutes.phala_tdx, "quote_body", lambda v: {"reportdata": "mock"})
    monkeypatch.setattr(chutes.nvidia_nras, "fetch_jwks", lambda: {"keys": []})
    monkeypatch.setattr(chutes.nvidia_nras, "appraise_gpu_attestation",
                        lambda items, n, jwks, gc, **kw: {"gpu_attested": True,
                                                          "verified_gpu_count": 8})
    report = chutes.verify("test-token", "https://api.chutes.ai", "Qwen3-32B-TEE")
    return report, seen


def test_fleet_census_retains_every_instance(monkeypatch):
    report, seen = _run(monkeypatch, _golden(), [
        (_instance("inst-1"), _evidence()),
        (_instance("inst-2"), _evidence()),
    ])
    assert len(seen) == 4  # measurements + instances + one evidence per instance
    assert report.details["fleet_size"] == 2
    fleet = report.details["fleet"]
    assert [f["instance_id"] for f in fleet] == ["inst-1", "inst-2"]
    for f in fleet:
        assert f["outcome"] == "verified_core"
        assert f["mrtd"] == MRTD.hex()
        assert f["matched_rows"] == [
            {"name": "8xh200 [10.2.1]", "version": "1.3.1", "fingerprint": None,
             "mrtd": MRTD.hex(), "expected_gpus": ["h200"], "gpu_count": 8}]
        assert f["tcb_status"] == "UpToDate"
        assert f["advisory_ids"] == []
    census = report.details["raw_evidence"]["fleet_census"]
    assert [c["instance_id"] for c in census] == ["inst-1", "inst-2"]
    assert all(c["quote_b64"] for c in census)
    pub = report.details["golden_publication"]
    assert pub["url"] == "https://api.chutes.ai/servers/tee/measurements"
    assert pub["rows"] == 1 and len(pub["canonical_json_sha256"]) == 64
    assert report.details["verification_status"] == "not_checked"


def test_unpublished_image_instance_rejects_row_not_signature(monkeypatch):
    """A valid-signature quote whose measurements match no published row is a
    configuration mismatch, not a hardware-signature failure."""
    rogue = dict(GOLDEN_ROW, mrtd=("cd" * 48))
    report, _ = _run(monkeypatch, _golden(), [
        (_instance("inst-1"), _evidence()),
        (_instance("inst-2"), _evidence(quote=_quote_b64(mrtd=bytes.fromhex("cd" * 48)))),
    ])
    assert report.details["verification_status"] == "rejected"
    assert report.scorecard.tdx_verified is True  # signature itself still valid
    fleet = {f["instance_id"]: f for f in report.details["fleet"]}
    assert fleet["inst-1"]["outcome"] == "verified_core"
    assert fleet["inst-2"]["outcome"] == "rejected"
    assert "published configuration row" in fleet["inst-2"]["reason"]
    assert "inst-2" in report.details["verification_reason"]


def test_instance_with_unavailable_evidence_fails_row(monkeypatch):
    report, _ = _run(monkeypatch, _golden(), [
        (_instance("inst-1"), _evidence()),
        (_instance("inst-2"), RuntimeError("HTTP 400 on /instances/inst-2/evidence: "
                                            "requires chutes_version >= 0.6.0")),
    ])
    assert report.details["verification_status"] == "rejected"
    fleet = {f["instance_id"]: f for f in report.details["fleet"]}
    assert fleet["inst-2"]["outcome"] == "unavailable"
    assert "HTTP 400" in fleet["inst-2"]["reason"]
    assert "chutes_version" in report.details["verification_reason"]
    assert report.scorecard.tdx_verified is True  # verified core of inst-1 stands
    # the scorecard describes the appraised instances; the row verdict carries
    # the unavailability (documented semantics in docs/tasks/glm-chutes-20261105.md)
    assert report.details["fleet_all_instances_pass"] is False


def test_mutating_each_register_independently_rejects(monkeypatch):
    for register, body_start in (("mrtd", 136), ("rtmr0", 328), ("rtmr1", 376),
                                 ("rtmr2", 424), ("rtmr3", 472)):
        start = 48 + body_start  # offsets are td_report-relative; quote has a 48-byte header
        raw = bytearray(_quote_bytes())
        raw[start] ^= 0xFF
        report, _ = _run(monkeypatch, _golden(), [
            (_instance("inst-1"), _evidence(quote=base64.b64encode(bytes(raw)).decode())),
        ])
        fleet = report.details["fleet"][0]
        assert fleet["outcome"] == "rejected", register
        assert fleet["matched_rows"] == [], register
        assert register == "mrtd" and "mrtd matches no" in fleet["reason"] or \
            "no published configuration row matches mrtd+rtmr0-3" in fleet["reason"]
        assert report.details["verification_status"] == "rejected", register


def test_ambiguous_boot_runtime_row_never_matches(monkeypatch):
    ambiguous = dict(GOLDEN_ROW)
    ambiguous["boot_rtmrs"] = dict(GOLDEN_ROW["boot_rtmrs"],
                                   RTMR2=("ff" * 48).upper())
    report, _ = _run(monkeypatch, _golden((ambiguous,)), [
        (_instance("inst-1"), _evidence()),
    ])
    fleet = report.details["fleet"][0]
    assert fleet["outcome"] == "rejected"
    assert fleet["no_match_reason"] == "mrtd-matching row has ambiguous boot/runtime RTMR0-2"


def test_tcb_appraisal_error_is_recorded_not_silenced(monkeypatch):
    report, _ = _run(monkeypatch, _golden(), [(_instance("inst-1"), _evidence())],
                     tcb=ValueError("pcs unreachable"))
    fleet = report.details["fleet"][0]
    assert fleet["tcb_status"] is None
    assert fleet["tcb_status_error"] == "ValueError: pcs unreachable"
    assert fleet["outcome"] == "verified_core"  # TCB retention is recorded evidence


def test_out_of_date_tcb_status_is_retained_verbatim(monkeypatch):
    """#18: status and advisories must survive; OutOfDate is not a rejection
    (same semantics as the NEAR verifier: both count as verified)."""
    report, _ = _run(monkeypatch, _golden(), [(_instance("inst-1"), _evidence())],
                     tcb={"tcb_status": "OutOfDate",
                          "advisory_ids": ["INTEL-SA-01192", "INTEL-SA-01245"]})
    fleet = report.details["fleet"][0]
    assert fleet["tcb_status"] == "OutOfDate"
    assert fleet["advisory_ids"] == ["INTEL-SA-01192", "INTEL-SA-01245"]
    assert fleet["outcome"] == "verified_core"
