"""Provider dispatch + parallel model probe."""
from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Dict, List

from verifiers.common import AttestationReport, now_iso, ScoreCard
from verifiers import near_ai, redpill, venice


PROVIDERS: Dict[str, Callable[[str, str, str], AttestationReport]] = {
    "near-ai": near_ai.verify,
    "redpill": redpill.verify,
    "venice": venice.verify,
}

PROVIDER_BASE_URLS: Dict[str, str] = {
    "near-ai": near_ai.DEFAULT_BASE_URL,
    "redpill": redpill.DEFAULT_BASE_URL,
    "venice": venice.DEFAULT_BASE_URL,
}

PROVIDER_ENV_KEYS: Dict[str, str] = {
    "near-ai": "NEAR_API_KEY",
    "redpill": "REDPILL_API_KEY",
    "venice": "VENICE_API_KEY",
}


def probe_provider(
    provider: str, models: List[str], max_workers: int = 4
) -> List[AttestationReport]:
    api_key = os.environ.get(PROVIDER_ENV_KEYS[provider], "").strip()
    base_url = PROVIDER_BASE_URLS[provider]
    verify = PROVIDERS[provider]

    if not api_key:
        return [_missing_key_report(provider, m) for m in models]

    def _one(model: str) -> AttestationReport:
        try:
            return verify(api_key, base_url, model)
        except Exception as exc:
            return AttestationReport(
                provider=provider, model=model, valid=False,
                verified_at=now_iso(), attestation_type="error",
                error=f"{type(exc).__name__}: {exc}",
            )

    if not models:
        return []
    with ThreadPoolExecutor(max_workers=min(max_workers, len(models))) as ex:
        return list(ex.map(_one, models))


def _missing_key_report(provider: str, model: str) -> AttestationReport:
    return AttestationReport(
        provider=provider, model=model, valid=False,
        verified_at=now_iso(), attestation_type="skipped",
        error=f"{PROVIDER_ENV_KEYS[provider]} not set",
        scorecard=ScoreCard(),
    )
