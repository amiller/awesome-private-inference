"""Wrapper around Phala's public TDX verifier API."""
from __future__ import annotations

from typing import Any, Dict

import requests

PHALA_TDX_VERIFIER = "https://cloud-api.phala.network/api/v1/attestations/verify"


def verify_tdx_quote(quote_hex: str, timeout: int = 30) -> Dict[str, Any]:
    """POST a hex-encoded TDX quote to Phala's verifier. Returns the raw JSON."""
    return requests.post(PHALA_TDX_VERIFIER, json={"hex": quote_hex}, timeout=timeout).json()


def is_verified(resp: Dict[str, Any]) -> bool:
    return bool((resp.get("quote") or {}).get("verified"))


def quote_body(resp: Dict[str, Any]) -> Dict[str, Any]:
    return (resp.get("quote") or {}).get("body", {})
