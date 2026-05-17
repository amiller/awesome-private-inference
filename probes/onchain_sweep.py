"""On-chain sweep of NEAR's DstackApp registries on Base.

Enumerates `ComposeHashAdded(bytes32)` events for each known DstackApp +
DstackKms contract and writes `data/onchain-status.json`. Cross-references
against the hermes anchor (`hermes-agent/feat/near-ai-attestation`) and
flags any on-chain authorized compose_hash that isn't yet anchored — i.e.,
"the EOA owner authorized a new compose; hermes is refusing it until a
maintainer captures the preimage and adds it to the anchor."

This is the CT-style discovery layer: on-chain `ComposeHashAdded` is the
authoritative SET of permitted compose hashes; the hermes anchor is the
human-reviewed subset of preimages we've audited; this script is the diff.

Usage: `python -m probes.onchain_sweep`
"""
from __future__ import annotations

import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests

REPO_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = REPO_ROOT / "data"
RPC_URL = "https://mainnet.base.org"
RANGE_LIMIT = 9000  # public Base RPC caps eth_getLogs to 10000 blocks
PARALLEL = 4  # concurrent eth_getLogs requests; public Base RPC tolerates ~4 in-flight
RETRY_BASE_SLEEP = 1.5  # exponential backoff base for rate limiting

# keccak256("ComposeHashAdded(bytes32)")
COMPOSE_HASH_ADDED_TOPIC = "0xfecb34306dd9d8b785b54d65489d06afc8822a0893ddacedff40c50a4942d0af"

# Known DstackApp + DstackKms contracts on Base. Add new app_ids as NEAR deploys them.
CONTRACTS = [
    {"address": "0x2c0a0c96cb6dbd659bf1446e2f3fce58172ff91b", "label": "near-ai/models",          "anchor_relevant": True,  "_note": "shared by every NEAR AI model CVM (GLM, gpt-oss, deepseek/qwen, ...)"},
    {"address": "0xf550fdfb4eb8ad787c1bcd423f091cbb4a4431ae", "label": "near-ai/cloud-api",       "anchor_relevant": False, "_note": "gateway TD; pinned in awesome-private-inference verifier for backend_attested"},
    {"address": "0xf723e96ab11772f0166e5e4749e49a2113f63b0c", "label": "near-ai/chat-api",        "anchor_relevant": False},
    {"address": "0x000b2d32de3ed13d7e15b735997e7580ed6dea69", "label": "near-ai/dstack-ingress",  "anchor_relevant": False},
    {"address": "0xc5f76292a3df94d50056b08e57fc30fe1081ad40", "label": "near-ai/postgres",        "anchor_relevant": False},
    {"address": "0xe78c12915ad57900317b97bd16f59ae13f86f148", "label": "near-ai/vpc-server",      "anchor_relevant": False},
]

# Sweep window. Base = 2s/block ⇒ 1 day ≈ 43200 blocks. 2M ≈ 46 days, enough
# to catch the historical NEAR rotations we already audited (earliest at
# block 43883122, ~1.76M blocks before block 45643488 on 2026-05-06).
SWEEP_WINDOW_BLOCKS = 2_000_000

HERMES_ANCHOR_URL = (
    "https://raw.githubusercontent.com/amiller/hermes-agent/"
    "feat/near-ai-attestation/hermes_cli/anchors/nearai_mainnet.json"
)


def _rpc(method: str, params: list, max_attempts: int = 5) -> Any:
    payload = {"jsonrpc": "2.0", "method": method, "params": params, "id": 1}
    for attempt in range(max_attempts):
        try:
            r = requests.post(RPC_URL, json=payload, timeout=20)
            if r.status_code == 429:
                time.sleep(RETRY_BASE_SLEEP * (2 ** attempt))
                continue
            r.raise_for_status()
            j = r.json()
            if "error" in j:
                raise RuntimeError(j["error"])
            return j["result"]
        except requests.exceptions.RequestException:
            if attempt == max_attempts - 1:
                raise
            time.sleep(RETRY_BASE_SLEEP * (2 ** attempt))
    raise RuntimeError(f"{method} exhausted {max_attempts} retries")


def _block_number() -> int:
    return int(_rpc("eth_blockNumber", []), 16)


def _block_timestamp(block_hex: str, cache: Dict[str, int]) -> int:
    if block_hex in cache:
        return cache[block_hex]
    res = _rpc("eth_getBlockByNumber", [block_hex, False])
    ts = int(res["timestamp"], 16) if res else 0
    cache[block_hex] = ts
    return ts


def _logs_one_range(address: str, start: int, end: int, topic: str) -> List[Dict]:
    try:
        return _rpc("eth_getLogs", [{
            "address": address,
            "fromBlock": hex(start),
            "toBlock": hex(end),
            "topics": [topic],
        }])
    except RuntimeError as e:
        print(f"    {address[:8]}.. range {start}..{end}: {e}", file=sys.stderr)
        return []


def _logs_paginated(address: str, from_block: int, to_block: int, topic: str) -> List[Dict]:
    """Paginate eth_getLogs in parallel. Public Base RPC caps to ~10K blocks/range."""
    ranges = []
    cur = to_block
    while cur >= from_block:
        start = max(from_block, cur - RANGE_LIMIT)
        ranges.append((start, cur))
        cur = start - 1
    out: List[Dict] = []
    with ThreadPoolExecutor(max_workers=PARALLEL) as pool:
        futs = [pool.submit(_logs_one_range, address, s, e, topic) for s, e in ranges]
        for f in as_completed(futs):
            out.extend(f.result())
    return out


def sweep_contract(address: str, label: str, from_block: int, to_block: int) -> List[Dict]:
    """Returns event records WITHOUT timestamps (resolved only for first-seen hashes later)."""
    raw = _logs_paginated(address, from_block, to_block, COMPOSE_HASH_ADDED_TOPIC)
    print(f"  {label}: {len(raw)} events in blocks {from_block}..{to_block}", file=sys.stderr)
    events = [{
        "block": int(log["blockNumber"], 16),
        "compose_hash": log["data"][2:].lower(),
        "tx": log["transactionHash"],
    } for log in raw]
    events.sort(key=lambda e: e["block"])
    return events


def distinct_first_seen(events: List[Dict]) -> List[Dict]:
    """Distinct compose hashes by first-seen block, with timestamp resolved."""
    seen: Dict[str, Dict] = {}
    for e in events:
        h = e["compose_hash"]
        if h not in seen:
            seen[h] = {"compose_hash": h, "first_seen_block": e["block"]}
    # Resolve timestamps for the first-seen blocks only (small fan-out).
    cache: Dict[str, int] = {}
    out = []
    for d in seen.values():
        ts = _block_timestamp(hex(d["first_seen_block"]), cache)
        out.append({
            **d,
            "first_seen_timestamp": ts,
            "first_seen_date": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts)) if ts else "",
        })
    return out


def fetch_anchor() -> Optional[Dict]:
    try:
        r = requests.get(HERMES_ANCHOR_URL, timeout=10)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        print(f"  hermes anchor fetch failed ({e}); skipping cross-ref", file=sys.stderr)
        return None


def main() -> int:
    latest = _block_number()
    from_block = max(0, latest - SWEEP_WINDOW_BLOCKS)
    print(f"sweeping Base blocks {from_block}..{latest} for ComposeHashAdded events", file=sys.stderr)

    contracts_out = []
    for c in CONTRACTS:
        events = sweep_contract(c["address"], c["label"], from_block, latest)
        contracts_out.append({
            "address": c["address"],
            "label": c["label"],
            "anchor_relevant": c["anchor_relevant"],
            "_note": c.get("_note"),
            "event_count": len(events),
            "distinct_compose_hashes": distinct_first_seen(events),
            "events": events,
        })

    anchor = fetch_anchor()
    anchored_hashes: set = set()
    if anchor:
        for m in anchor.get("models", {}).values():
            for h in m.get("compose_hashes", []):
                anchored_hashes.add(h.lower().removeprefix("0x"))

    drift_alerts = []
    for c in contracts_out:
        if not c["anchor_relevant"] or anchor is None:
            c["new_since_anchor"] = None
            continue
        new = [d for d in c["distinct_compose_hashes"] if d["compose_hash"] not in anchored_hashes]
        c["new_since_anchor"] = new
        if new:
            drift_alerts.append((c, new))

    out = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "rpc": RPC_URL,
        "from_block": from_block,
        "to_block": latest,
        "hermes_anchor_url": HERMES_ANCHOR_URL,
        "anchored_compose_hash_count": len(anchored_hashes),
        "contracts": contracts_out,
    }
    out_path = DATA_DIR / "onchain-status.json"
    out_path.write_text(json.dumps(out, indent=2))
    print(f"wrote {out_path}", file=sys.stderr)

    if drift_alerts:
        print("", file=sys.stderr)
        print("⚠️  drift detected: on-chain authorized compose hashes not in hermes anchor:", file=sys.stderr)
        for c, new in drift_alerts:
            print(f"  {c['label']} ({c['address']}):", file=sys.stderr)
            for d in new:
                print(f"    0x{d['compose_hash']}  added {d['first_seen_date']} (block {d['first_seen_block']})", file=sys.stderr)
        print("", file=sys.stderr)
        print("→ capture the preimage from a live attestation, audit the diff, add to anchor.", file=sys.stderr)
        return 1
    print("anchor is in sync with on-chain authorized set ✅", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
