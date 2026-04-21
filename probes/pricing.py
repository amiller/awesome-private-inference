"""Pricing sweep — asks "What's 2+2?" on each model and logs list $/M tokens.

For providers that publish per-token rates in their /models catalog we capture
prompt/completion $/M directly. Subscription math (RedPill Pro, Venice Pro+/Max,
Z.AI Coding Plan) is documented in the provider markdown pages, not computed here.
"""
from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional

import requests


@dataclass
class PriceRow:
    provider: str
    model: str
    list_in_per_m: Optional[float] = None
    list_out_per_m: Optional[float] = None
    prompt_tokens: Optional[int] = None
    completion_tokens: Optional[int] = None
    latency_s: Optional[float] = None
    list_cost: Optional[float] = None
    reply_ok: bool = False
    error: Optional[str] = None

    def as_dict(self) -> Dict:
        return asdict(self)


def _redpill_catalog(api_key: str) -> Dict[str, tuple]:
    """Returns {model_id: (prompt_per_m, completion_per_m)}."""
    r = requests.get(
        "https://api.red-pill.ai/api/models",
        headers={"Authorization": f"Bearer {api_key}"}, timeout=30,
    ).json()
    out = {}
    for m in r.get("data", []):
        p = m.get("pricing") or {}
        try:
            out[m["id"]] = (float(p["prompt"]) * 1e6, float(p["completion"]) * 1e6)
        except (KeyError, ValueError, TypeError):
            continue
    return out


def _venice_catalog(api_key: str) -> Dict[str, tuple]:
    r = requests.get(
        "https://api.venice.ai/api/v1/models",
        headers={"Authorization": f"Bearer {api_key}"}, timeout=30,
    ).json()
    out = {}
    for m in r.get("data", []):
        p = (m.get("model_spec") or {}).get("pricing") or m.get("pricing") or {}
        input_k = p.get("input") or p.get("prompt")
        output_k = p.get("output") or p.get("completion")
        try:
            # Venice publishes as USD per 1K tokens in some endpoints, USD per M in others.
            # Normalize to $/M.
            def _norm(v):
                v = float(v)
                return v * 1000 if v < 0.001 else v  # heuristic: treat <0.001 as per-token
            out[m["id"]] = (_norm(input_k), _norm(output_k))
        except (TypeError, ValueError):
            continue
    return out


def sweep(provider: str, models: List[str], max_workers: int = 3) -> List[PriceRow]:
    """Chat-complete "2+2" on each model, capture token counts and list cost.

    Uses raw httpx against /chat/completions. OpenAI-compatible shape.
    """
    import time as _t

    env_key = {"redpill": "REDPILL_API_KEY", "venice": "VENICE_API_KEY",
               "near-ai": "NEAR_API_KEY"}[provider]
    api_key = os.environ.get(env_key, "").strip()
    if not api_key:
        return [PriceRow(provider=provider, model=m, error=f"{env_key} not set")
                for m in models]

    base_url, catalog_fn = {
        "redpill": ("https://api.red-pill.ai/v1", _redpill_catalog),
        "venice": ("https://api.venice.ai/api/v1", _venice_catalog),
        "near-ai": ("https://cloud-api.near.ai/v1", None),
    }[provider]

    try:
        prices = catalog_fn(api_key) if catalog_fn else {}
    except Exception:
        prices = {}

    def _one(m: str) -> PriceRow:
        t0 = _t.time()
        try:
            resp = requests.post(
                f"{base_url}/chat/completions",
                headers={"Authorization": f"Bearer {api_key}"},
                json={
                    "model": m,
                    "messages": [{"role": "user",
                                  "content": "What's 2+2? Reply with just the number."}],
                    "max_tokens": 20,
                },
                timeout=60,
            )
        except requests.RequestException as exc:
            return PriceRow(
                provider=provider, model=m,
                latency_s=round(_t.time() - t0, 2),
                error=f"{type(exc).__name__}: {exc}",
            )
        if resp.status_code != 200:
            return PriceRow(
                provider=provider, model=m,
                latency_s=round(_t.time() - t0, 2),
                error=f"HTTP {resp.status_code}",
            )
        body = resp.json()
        u = body.get("usage") or {}
        pin, pout = prices.get(m, (None, None))
        p_tok = u.get("prompt_tokens")
        c_tok = u.get("completion_tokens")
        cost = None
        if pin is not None and pout is not None and p_tok is not None:
            cost = (p_tok * pin + (c_tok or 0) * pout) / 1e6
        return PriceRow(
            provider=provider, model=m,
            list_in_per_m=pin, list_out_per_m=pout,
            prompt_tokens=p_tok, completion_tokens=c_tok,
            latency_s=round(_t.time() - t0, 2),
            list_cost=cost, reply_ok=True,
        )

    if not models:
        return []
    with ThreadPoolExecutor(max_workers=min(max_workers, len(models))) as ex:
        return list(ex.map(_one, models))
