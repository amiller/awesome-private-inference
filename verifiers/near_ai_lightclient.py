"""NEAR AI light-client verifier.

Strict closed-chain verification using only on-chain anchoring + post-#30 inner
compose pinning. Drops the static-anchor maintenance burden of the hermes
strict-mode design.

What this checks:
  Block A:  TDX quote, GPU NRAS, report_data binds (signing_addr || nonce)
  On-chain: info.compose_hash ∈ DstackApp(info.app_id).authorizedSet (Base)
  Inner:    compose_manager_attestation.actions[].compose_up matches a small
            per-model pin of (yaml_file, commit, file_sha256). Also verifies
            CM's quote binds report_data == actions_hash || nonce.

What this *doesn't* check (vs hermes strict mode):
  - Gateway compose hash. The gateway is transport under E2EE; if you trust
    the model TD's signing key (bound by its own report_data) you don't need
    to trust the routing layer.
  - kmsInfo (KMS root pubkey anchor). The model TD's signing key is bound
    directly by its own quote; chaining through KMS root is redundant.
  - Static os_image_hash / kms_provider_info anchors. Model substitution is
    detected via the compose_hash → yaml binding alone.

Usage:
  python -m verifiers.near_ai_lightclient --model "zai-org/GLM-5.1-FP8"
"""
from __future__ import annotations

import argparse
import asyncio
import contextlib
import io
import json
import os
import secrets
import sys
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests

_vendor = os.environ.get("NEARAI_VERIFIER_PATH")
if _vendor and _vendor not in sys.path:
    sys.path.insert(0, _vendor)

from .common import keccak_eth_address, sha256_hex

DEFAULT_BASE_URL = "https://cloud-api.near.ai"
_STDOUT_LOCK = threading.Lock()
REPO_ROOT = Path(__file__).resolve().parents[1]
STATIC_ONCHAIN_PATH = REPO_ROOT / "data" / "near-onchain-set-2026-05-07.json"

# Per-model inner-compose pins. Key = OpenAI-style model name returned by the
# /v1/models catalog; value = (yaml file in nearai/cvm-compose-files, expected
# git commit at deploy, expected file_sha256). Refresh by reading the latest
# `compose_up` for the file from a live attestation report; the binding
# `file_sha256 → HF --revision` is deterministic via the YAML contents at that
# commit (verified by curl + sha256sum against
# raw.githubusercontent.com/nearai/cvm-compose-files/<commit>/<file>).
MODEL_PINS: Dict[str, Dict[str, str]] = {
    "zai-org/GLM-5.1-FP8": {
        "yaml": "GLM-5.1.yaml",
        "commit": "a94d7c776cf902e5c083960baeafb6b084c473a1",
        "file_sha256": "10146e2f3249ab6217bd506138144001fd6be666f88dff678648f19660ea997c",
        "hf_revision": "f396cf805182f4ca10fa675e1a99815b3ca384db",  # informational; bound by file_sha256
    },
}


def _sync(coro):
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    from concurrent.futures import ThreadPoolExecutor
    def _worker():
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(coro)
        finally:
            loop.close()
    with ThreadPoolExecutor(max_workers=1) as ex:
        return ex.submit(_worker).result()


def _silent(coro_or_call):
    """Call a coroutine or callable while silencing stdout."""
    buf = io.StringIO()
    with _STDOUT_LOCK, contextlib.redirect_stdout(buf):
        if asyncio.iscoroutine(coro_or_call):
            return _sync(coro_or_call)
        return coro_or_call()


def fetch_onchain_set_static(app_id: str) -> List[str]:
    """Read captured-at-build-time set. Default for the prototype."""
    data = json.loads(STATIC_ONCHAIN_PATH.read_text())
    key = "0x" + app_id.lower().removeprefix("0x")
    return [h.lower() for h in data.get(key, [])]


def fetch_onchain_set_live(app_id: str, min_age_seconds: int = 0) -> List[str]:
    """Live Blockscout query for ComposeHashAdded events.

    `min_age_seconds`: only include hashes whose first on-chain authorization
    is older than this. Acts as a small upgrade-notice window — refusing brand
    new hashes gives observers time to detect a compromised owner key adding a
    malicious compose. ~2hrs covers Base→L1 batch posting + L1 finality;
    24hrs gives a real ERC-733 §5-style notice period.
    """
    import datetime
    addr = "0x" + app_id.lower().removeprefix("0x")
    topic = "0xfecb34306dd9d8b785b54d65489d06afc8822a0893ddacedff40c50a4942d0af"
    url = f"https://base.blockscout.com/api/v2/addresses/{addr}/logs"
    cutoff = datetime.datetime.now(datetime.timezone.utc).timestamp() - min_age_seconds
    first_seen: Dict[str, float] = {}
    params: Dict[str, Any] = {}
    for _ in range(20):
        r = requests.get(url, params=params, timeout=20,
                         headers={"User-Agent": "near-ai-lightclient/0.1"})
        r.raise_for_status()
        d = r.json()
        for item in d.get("items") or []:
            if (item.get("topics") or [""])[0].lower() != topic:
                continue
            data = item.get("data") or ""
            if not (data.startswith("0x") and len(data) >= 66):
                continue
            h = data[2:66].lower()
            ts_str = item.get("block_timestamp") or ""
            try:
                ts = datetime.datetime.fromisoformat(ts_str.replace("Z", "+00:00")).timestamp()
            except ValueError:
                continue
            # Track earliest timestamp per hash (idempotent re-additions don't reset the clock)
            if h not in first_seen or ts < first_seen[h]:
                first_seen[h] = ts
        npp = d.get("next_page_params")
        if not npp:
            break
        params = npp
    return sorted(h for h, ts in first_seen.items() if ts <= cutoff)


class VerificationError(Exception):
    pass


def verify(
    *,
    api_key: str,
    model_name: str,
    base_url: str = DEFAULT_BASE_URL,
    onchain: str = "static",  # "static" | "live" | "skip"
    min_age_seconds: int = 0,  # only used in live mode
    nonce: Optional[str] = None,
) -> Dict[str, Any]:
    """Returns dict with `valid`, `signing_address`, and per-step details.

    Raises VerificationError on any required step failing. `onchain="skip"`
    bypasses the on-chain set check (useful for offline testing).
    """
    try:
        from model_verifier import check_tdx_quote, check_report_data, check_gpu
    except ImportError:
        raise VerificationError(
            "nearai-cloud-verifier not installed; set NEARAI_VERIFIER_PATH"
        )

    nonce = nonce or secrets.token_hex(32)
    base = base_url.rstrip("/")
    if base.endswith("/v1"):
        base = base[:-3]

    r = requests.get(
        f"{base}/v1/attestation/report",
        params={
            "model": model_name,
            "nonce": nonce,
            "signing_algo": "ecdsa",
            "include_tls_fingerprint": "true",
        },
        headers={"Authorization": f"Bearer {api_key}"},
        timeout=30,
    )
    if r.status_code != 200:
        raise VerificationError(f"HTTP {r.status_code}: {r.text[:200]}")
    report = r.json()
    models = report.get("model_attestations") or []
    if not models:
        raise VerificationError("no model_attestations in response")
    m = models[0]
    info = m.get("info", {})

    # ---- Block A: TDX quote, GPU NRAS, report_data binding, key derivation
    intel = _silent(check_tdx_quote(m))
    if not (intel and intel.get("verified")):
        raise VerificationError(f"TDX quote did not verify: {intel}")
    rd = _silent(lambda: check_report_data(m, nonce, intel))
    if not (rd.get("binds_address") and rd.get("embeds_nonce")):
        raise VerificationError(f"report_data binding failed: {rd}")
    gpu = _silent(lambda: check_gpu(m, nonce))
    if gpu.get("verdict") not in ("PASS", True) or not gpu.get("nonce_matches"):
        raise VerificationError(f"GPU NRAS not PASS: {gpu}")

    spk = m.get("signing_public_key", "")
    addr = m.get("signing_address", "")
    if not (spk and addr and keccak_eth_address(spk).lower() == addr.lower()):
        raise VerificationError("signing_public_key does not derive to signing_address")

    # ---- On-chain set check
    app_id = info.get("app_id", "").lower()
    compose = info.get("compose_hash", "").lower()
    if not (app_id and compose):
        raise VerificationError("info missing app_id or compose_hash")

    if onchain == "skip":
        onchain_set: List[str] = []
        onchain_ok = None
    else:
        if onchain == "live":
            onchain_set = fetch_onchain_set_live(app_id, min_age_seconds=min_age_seconds)
        else:
            onchain_set = fetch_onchain_set_static(app_id)
        onchain_ok = compose in {h.lower() for h in onchain_set}
        if not onchain_ok:
            hint = f" (min_age={min_age_seconds}s)" if onchain == "live" and min_age_seconds else ""
            raise VerificationError(
                f"compose_hash 0x{compose} not in on-chain authorized set "
                f"for app_id 0x{app_id} ({len(onchain_set)} entries; mode={onchain}{hint})"
            )

    # ---- Inner closure: bind compose_manager_attestation to the requested model
    pin = MODEL_PINS.get(model_name)
    if not pin:
        raise VerificationError(f"no MODEL_PINS entry for {model_name!r}")
    cm = m.get("compose_manager_attestation") or {}
    actions = cm.get("actions") or []
    actions_hash = cm.get("actions_hash", "")
    cm_rd = cm.get("report_data", "")
    if cm_rd[:64].lower() != actions_hash.lower() or cm_rd[64:128] != nonce:
        raise VerificationError(
            f"compose_manager report_data does not bind actions_hash || nonce"
        )
    # Find the latest compose_up for the pinned yaml
    matching = [a for a in actions
                if a.get("action") == "compose_up" and a.get("file") == pin["yaml"]]
    if not matching:
        raise VerificationError(
            f"no compose_up action for {pin['yaml']!r} in actions log"
        )
    latest = matching[-1]
    if latest["commit"] != pin["commit"]:
        raise VerificationError(
            f"commit mismatch: actions[].commit={latest['commit']} expected={pin['commit']}"
        )
    if latest["file_sha256"] != pin["file_sha256"]:
        raise VerificationError(
            f"file_sha256 mismatch: actions[].file_sha256={latest['file_sha256']} "
            f"expected={pin['file_sha256']}"
        )

    return {
        "valid": True,
        "model_name": model_name,
        "signing_address": addr,
        "signing_public_key": spk,
        "app_id": "0x" + app_id,
        "compose_hash": "0x" + compose,
        "onchain_set_size": len(onchain_set),
        "onchain_check": onchain,
        "min_age_seconds": min_age_seconds if onchain == "live" else None,
        "inner_compose": {
            "yaml": latest["file"],
            "commit": latest["commit"],
            "file_sha256": latest["file_sha256"],
            "tag": latest.get("tag"),
            "timestamp": latest.get("timestamp"),
        },
    }


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    p.add_argument("--model", default="zai-org/GLM-5.1-FP8")
    p.add_argument("--base-url", default=DEFAULT_BASE_URL)
    p.add_argument("--api-key", default=os.environ.get("NEAR_API_KEY", ""))
    p.add_argument("--onchain", choices=["static", "live", "skip"], default="static")
    p.add_argument("--min-age-hours", type=float, default=0,
                   help="(live mode only) refuse compose hashes added <N hours ago")
    args = p.parse_args(argv)

    if not args.api_key:
        print("error: --api-key or NEAR_API_KEY required", file=sys.stderr)
        return 2
    try:
        result = verify(
            api_key=args.api_key,
            model_name=args.model,
            base_url=args.base_url,
            onchain=args.onchain,
            min_age_seconds=int(args.min_age_hours * 3600),
        )
    except VerificationError as e:
        print(f"❌ FAIL: {e}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    print(f"\n✅ {args.model} verified end-to-end "
          f"(on-chain={args.onchain}, signing_addr={result['signing_address']})",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
