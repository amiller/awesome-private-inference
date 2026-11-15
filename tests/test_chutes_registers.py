"""Replay retained real Chutes evidence through the register matcher.

Every quote here was captured live by the daily probe (data/observations/
evidence/sha256). No mocks: the quotes, nonces and golden publications are the
real retained captures. Negative controls flip one byte of each authenticated
register independently and must destroy the full-row match.
"""
import base64
import glob
import json
from pathlib import Path

import pytest

from verifiers.chutes import _match_golden_rows, _parse_quote

EVIDENCE_DIR = Path(__file__).resolve().parents[1] / "data" / "observations" / "evidence" / "sha256"

_REGISTER_OFFSETS = {"mrtd": 136, "rtmr0": 328, "rtmr1": 376,
                     "rtmr2": 424, "rtmr3": 472}


def _chutes_files():
    files = []
    for path in sorted(EVIDENCE_DIR.glob("*.json")):
        data = json.loads(path.read_text())
        if data.get("chute_id"):
            files.append((path, data))
    if not files:
        pytest.fail("no retained Chutes evidence found")
    return files


def test_every_retained_quote_full_row_matches_publication():
    files = _chutes_files()
    for path, data in files:
        meas = _parse_quote(data["quote_b64"])
        matches, reason = _match_golden_rows(meas, data["golden_measurements"])
        assert matches, f"{path.name}: {reason}"
        assert reason is None
        # the recorded nonce/e2e key binding still holds on the real capture
        from verifiers.common import sha256_nonce_pubkey_binding
        assert sha256_nonce_pubkey_binding(meas["report_data"], data["nonce"], data["e2e_pubkey"])


def test_each_register_mutation_destroys_the_match():
    path, data = _chutes_files()[0]
    decoded = bytearray(base64.b64decode(data["quote_b64"]))
    for register, body_start in _REGISTER_OFFSETS.items():
        start = 48 + body_start  # td_report-relative; the quote has a 48-byte header
        tampered = bytes(decoded)
        tampered = tampered[:start] + bytes([tampered[start] ^ 0xFF]) + tampered[start + 1:]
        assert tampered[start] != decoded[start]
        meas = _parse_quote(base64.b64encode(tampered).decode())
        matches, reason = _match_golden_rows(meas, data["golden_measurements"])
        assert matches == [], register
        assert reason, register


def test_mutated_publication_row_rejects_real_quote():
    """Golden-set policy negative: the same real quote must stop matching when
    the publication row's RTMR3 is altered."""
    path, data = _chutes_files()[0]
    meas = _parse_quote(data["quote_b64"])
    rows = [dict(r) for r in data["golden_measurements"]]
    mutated = 0
    for row in rows:
        if row.get("mrtd", "").lower() == meas["mrtd"] and row.get("runtime_rtmrs"):
            row["runtime_rtmrs"] = dict(row["runtime_rtmrs"], RTMR3="ee" * 48)
            mutated += 1
    assert mutated
    matches, reason = _match_golden_rows(meas, rows)
    assert matches == []
    assert reason == "no published configuration row matches mrtd+rtmr0-3"


def test_matched_rows_carry_row_identity():
    for path, data in _chutes_files()[:25]:
        meas = _parse_quote(data["quote_b64"])
        matches, _ = _match_golden_rows(meas, data["golden_measurements"])
        for row in matches:
            assert row["name"] and row["gpu_count"]
