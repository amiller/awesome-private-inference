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

The authorized set is append-only, so the events are accumulated once into
`data/onchain-events.json` and each run scans only the blocks since the last
checkpoint. The previous version re-scanned a 2M-block sliding window every
run: ~1,334 eth_getLogs calls per invocation, and — worse — the window
outran the history it was sized for, so events aged out silently and
`first_seen_block` was measured from the window edge instead of from chain
history. See issue #10.

Usage: `python -m probes.onchain_sweep`
"""
from __future__ import annotations

import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import requests

REPO_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = REPO_ROOT / "data"
EVENTS_PATH = DATA_DIR / "onchain-events.json"
RPC_URL = "https://mainnet.base.org"
RANGE_LIMIT = 9000  # public Base RPC caps eth_getLogs to 10000 blocks
PARALLEL = 4  # concurrent eth_getLogs requests; public Base RPC tolerates ~4 in-flight
RETRY_BASE_SLEEP = 1.5  # exponential backoff base for rate limiting

# Re-scan this many blocks below the checkpoint each run so a reorg near the
# tip cannot strand an event behind the watermark.
REORG_OVERLAP = 300

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


def _block_timestamp(block: int, cache: Dict[int, int]) -> int:
    if block in cache:
        return cache[block]
    res = _rpc("eth_getBlockByNumber", [hex(block), False])
    ts = int(res["timestamp"], 16) if res else 0
    cache[block] = ts
    return ts


def _deployment_block(address: str, latest: int) -> int:
    """Binary-search the first block at which the contract has code (~25 calls, once)."""
    if _rpc("eth_getCode", [address, hex(latest)]) in ("0x", "0x0"):
        raise RuntimeError(f"{address} has no code at head {latest}")
    lo, hi = 0, latest
    while lo < hi:
        mid = (lo + hi) // 2
        if _rpc("eth_getCode", [address, hex(mid)]) in ("0x", "0x0"):
            lo = mid + 1
        else:
            hi = mid
    return lo


def _logs_one_range(address: str, start: int, end: int, topic: str) -> List[Dict]:
    """Raises on failure. A swallowed range would advance the checkpoint past
    blocks that were never actually scanned, permanently losing those events."""
    return _rpc("eth_getLogs", [{
        "address": address,
        "fromBlock": hex(start),
        "toBlock": hex(end),
        "topics": [topic],
    }])


def _logs_paginated(address: str, from_block: int, to_block: int, topic: str) -> List[Dict]:
    """Paginate eth_getLogs in parallel. Public Base RPC caps to ~10K blocks/range."""
    ranges, cur = [], to_block
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


def _load_store() -> Tuple[Dict[str, Dict], Dict[int, int]]:
    if not EVENTS_PATH.exists():
        return {}, {}
    raw = json.loads(EVENTS_PATH.read_text())
    # keys round-trip through JSON as strings
    return raw["contracts"], {int(k): v for k, v in raw.get("block_timestamps", {}).items()}


def _save_store(store: Dict[str, Dict], head: int, ts_cache: Dict[int, int]) -> None:
    """Written after every contract, not once at the end: the initial backfill takes
    tens of minutes, and a crash partway through should cost one contract's progress
    rather than all of it. Each contract carries its own watermark, so a partial
    store is resumable.

    Block timestamps are persisted alongside. A block's timestamp is immutable and
    first_seen_block never moves once recorded, so re-resolving them every run would be
    ~283 pointless eth_getBlockByNumber calls."""
    EVENTS_PATH.write_text(json.dumps(
        {"generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
         "head_block": head, "contracts": store,
         "block_timestamps": {str(k): v for k, v in sorted(ts_cache.items())}}, indent=2))


def _key(e: Dict) -> Tuple[int, str, str]:
    return (e["block"], e["tx"], e["compose_hash"])


def sync_contract(c: Dict, store: Dict[str, Dict], latest: int) -> Dict:
    """Bring one contract's accumulated event set up to `latest`. Append-only."""
    st = store.setdefault(c["label"], {"address": c["address"], "events": []})

    if st.get("genesis_block") is None:
        st["genesis_block"] = _deployment_block(c["address"], latest)
        print(f"  {c['label']}: deployed at block {st['genesis_block']}", file=sys.stderr)

    watermark = st.get("last_scanned_block")
    start = st["genesis_block"] if watermark is None else max(
        st["genesis_block"], watermark + 1 - REORG_OVERLAP)

    if start > latest:
        print(f"  {c['label']}: up to date at {watermark}", file=sys.stderr)
        return st

    raw = _logs_paginated(c["address"], start, latest, COMPOSE_HASH_ADDED_TOPIC)
    fresh = [{"block": int(l["blockNumber"], 16),
              "compose_hash": l["data"][2:].lower(),
              "tx": l["transactionHash"]} for l in raw]

    known: Set[Tuple] = {_key(e) for e in st["events"]}
    added = [e for e in fresh if _key(e) not in known]
    st["events"] = sorted(st["events"] + added, key=lambda e: e["block"])
    st["last_scanned_block"] = latest

    span = "backfill" if watermark is None else f"+{latest - watermark} blocks"
    print(f"  {c['label']}: {len(added)} new ({span}), {len(st['events'])} total",
          file=sys.stderr)
    return st


def distinct_first_seen(events: List[Dict], cache: Dict[int, int]) -> List[Dict]:
    """Distinct compose hashes by first-seen block over the FULL accumulated history.

    first_seen_* is absolute, not relative to a scan window — it is the continuity
    primitive the continuity log is built on, so a moving baseline would corrupt it.
    """
    seen: Dict[str, int] = {}
    for e in events:
        seen.setdefault(e["compose_hash"], e["block"])
    out = []
    for h, block in seen.items():
        ts = _block_timestamp(block, cache)
        out.append({
            "compose_hash": h,
            "first_seen_block": block,
            "first_seen_timestamp": ts,
            "first_seen_date": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts)) if ts else "",
        })
    return sorted(out, key=lambda d: d["first_seen_block"])


def fetch_anchor() -> Optional[Dict]:
    r = requests.get(HERMES_ANCHOR_URL, timeout=10)
    r.raise_for_status()
    return r.json()


def main() -> int:
    latest = _block_number()
    store, ts_cache = _load_store()
    print(f"syncing Base contracts to block {latest}", file=sys.stderr)

    for c in CONTRACTS:
        sync_contract(c, store, latest)
        _save_store(store, latest, ts_cache)

    anchor = fetch_anchor()
    anchored: Set[str] = {h.lower().removeprefix("0x")
                          for m in anchor.get("models", {}).values()
                          for h in m.get("compose_hashes", [])}

    contracts_out, drift_alerts = [], []
    for c in CONTRACTS:
        st = store[c["label"]]
        distinct = distinct_first_seen(st["events"], ts_cache)
        entry = {
            "address": c["address"],
            "label": c["label"],
            "anchor_relevant": c["anchor_relevant"],
            "_note": c.get("_note"),
            "genesis_block": st["genesis_block"],
            "last_scanned_block": st["last_scanned_block"],
            "event_count": len(st["events"]),
            "distinct_compose_hashes": distinct,
            "events": st["events"],
        }
        if c["anchor_relevant"]:
            new = [d for d in distinct if d["compose_hash"] not in anchored]
            entry["new_since_anchor"] = new
            if new:
                drift_alerts.append((entry, new))
        else:
            entry["new_since_anchor"] = None
        contracts_out.append(entry)

    out = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "rpc": RPC_URL,
        "head_block": latest,
        "hermes_anchor_url": HERMES_ANCHOR_URL,
        "anchored_compose_hash_count": len(anchored),
        # published so diffalert can tell "now anchored" from "vanished from our
        # own records", which the sliding window used to conflate (issue #10)
        "anchored_compose_hashes": sorted(anchored),
        "contracts": contracts_out,
    }
    _save_store(store, latest, ts_cache)  # persist any newly-resolved timestamps
    (DATA_DIR / "onchain-status.json").write_text(json.dumps(out, indent=2))
    print(f"wrote {DATA_DIR / 'onchain-status.json'}", file=sys.stderr)

    if drift_alerts:
        print("\n⚠️  drift detected: on-chain authorized compose hashes not in hermes anchor:",
              file=sys.stderr)
        for entry, new in drift_alerts:
            print(f"  {entry['label']} ({entry['address']}):", file=sys.stderr)
            for d in new:
                print(f"    0x{d['compose_hash']}  added {d['first_seen_date']} "
                      f"(block {d['first_seen_block']})", file=sys.stderr)
        print("\n→ capture the preimage from a live attestation, audit the diff, "
              "add to anchor.", file=sys.stderr)
        return 1
    print("anchor is in sync with on-chain authorized set ✅", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
