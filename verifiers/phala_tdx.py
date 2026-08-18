"""Wrapper around Phala's public TDX verifier API."""
from __future__ import annotations

from typing import Any, Dict

import requests

PHALA_TDX_VERIFIER = "https://cloud-api.phala.network/api/v1/attestations/verify"


def verify_tdx_quote(quote_hex: str, timeout: int = 30) -> Dict[str, Any]:
    """POST a hex-encoded TDX quote to Phala's verifier. Returns the raw JSON.

    Raises when the service does not answer with a verdict. Returning the body
    regardless would let `is_verified()` read a 5xx or an error envelope as
    `verified: false`, which lands on the dashboard as a red cell claiming the
    quote was rejected — a much stronger statement than "we could not ask".
    Observed live 2026-08-18: two rows in one run reported tdx_verified=False and
    passed on re-probe seconds later.
    """
    response = requests.post(PHALA_TDX_VERIFIER, json={"hex": quote_hex}, timeout=timeout)
    response.raise_for_status()
    body = response.json()
    if "quote" not in body:
        raise ValueError(f"TDX verifier returned no verdict: {str(body)[:200]}")
    return body


def is_verified(resp: Dict[str, Any]) -> bool:
    return bool((resp.get("quote") or {}).get("verified"))


def quote_body(resp: Dict[str, Any]) -> Dict[str, Any]:
    return (resp.get("quote") or {}).get("body", {})
