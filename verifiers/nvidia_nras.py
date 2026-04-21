"""Wrapper around NVIDIA's NRAS GPU attestation endpoint."""
from __future__ import annotations

from typing import Any, Dict, Optional

import requests

from .common import decode_nvidia_jwt_verdict

NVIDIA_NRAS = "https://nras.attestation.nvidia.com/v3/attest/gpu"


def attest_gpu(nvidia_payload: Dict[str, Any], timeout: int = 30) -> Optional[str]:
    """Returns the verdict string from NRAS ('PASS'/'FAIL'/etc.), or None on transport error."""
    resp = requests.post(NVIDIA_NRAS, json=nvidia_payload, timeout=timeout).json()
    # NRAS responds as [[nonce_hex, jwt], …] per GPU
    return decode_nvidia_jwt_verdict(resp[0][1])
