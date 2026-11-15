"""Appraise NEAR compose-manager's deployment log (teep #166).

NEAR's measured model compose runs only compose-manager. The serving code is
deployed after boot from nearai/cvm-compose-files, and compose-manager reports
what it deployed in a log bound to its own TDX quote (report_data =
sha256(canonical actions) || nonce; compose-manager src/main.rs:1236-1243).

The policy here: the log must hash to the quote, the quote must come from the
same CVM as the model quote, and every deployment still running must be a file
whose bytes are public at its commit and that our archive first saw at least
`min_age_s` ago.

Limits that no client check closes:
- dstack's GetQuote signs any caller-supplied report_data, and apps cannot
  extend RTMR3 since dstack 0.6.0. A co-resident container with the socket
  could serve a quote over a different log. The public commit history, not the
  quote, is the anchor that can't be forged.
- compose-manager does not log the env values interpolated into the file.
"""
from __future__ import annotations

import hashlib
import json
from functools import lru_cache
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, List

import requests

from . import dstack_tdx

REGISTERS = ("mrtd", "rtmr0", "rtmr1", "rtmr2", "rtmr3")
ARCHIVE_PATH = Path(__file__).resolve().parents[1] / "data" / "near-deployments-seen.json"
RAW_URL = "https://raw.githubusercontent.com/nearai/cvm-compose-files/{commit}/{file}"


def actions_hash(actions: List[Dict]) -> str:
    """compose-manager's canonical form: serde_json compact, keys sorted."""
    canon = json.dumps(actions, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canon.encode()).hexdigest()


def running_deployments(actions: List[Dict]) -> List[Dict]:
    """Replay compose_up/compose_down into the deployments still running.

    State is per (file, service); an action without `services` applies to the
    whole file.
    """
    state: Dict[str, Dict[str, Dict]] = {}
    for a in actions:
        kind, f = a["action"], a.get("file")
        if kind not in ("compose_up", "compose_down"):
            continue
        services = a.get("services") or ["*"]
        if kind == "compose_up":
            if services == ["*"]:
                state[f] = {}
            for s in services:
                state.setdefault(f, {})[s] = a
        elif services == ["*"]:
            state.pop(f, None)
        else:
            for s in services:
                state.get(f, {}).pop(s, None)
    out = {}
    for f, svcs in state.items():
        for s, a in svcs.items():
            key = (f, a["commit"], a.get("file_sha256"))
            out.setdefault(key, {"file": f, "commit": a["commit"], "tag": a.get("tag"),
                                 "file_sha256": a.get("file_sha256"), "services": []})
            out[key]["services"].append(s)
    return list(out.values())


@lru_cache(maxsize=None)
def public_file_sha256(commit: str, file: str) -> str:
    r = requests.get(RAW_URL.format(commit=commit, file=file), timeout=20)
    r.raise_for_status()
    return hashlib.sha256(r.content).hexdigest()


def load_archive(path: Path = ARCHIVE_PATH) -> Dict[str, Dict]:
    return json.loads(path.read_text()) if path.exists() else {}


def archive_key(d: Dict) -> str:
    return f"{d['commit']}:{d['file']}"


def appraise(cm: Dict, model_quote_hex: str, nonce: str, archive: Dict[str, Dict],
             min_age_s: int, now: datetime,
             fetch_sha256: Callable[[str, str], str] = public_file_sha256,
             verify_quote: Callable[[str], object] = dstack_tdx.dcap_verify) -> Dict:
    checks = {"cm_quote_verified": False, "cm_tcb_current": False,
              "actions_hash_recomputed": False, "report_data_binds_log_and_nonce": False,
              "same_cvm_as_model": False, "deployments_public": False,
              "deployments_aged": False}
    out = {"checks": checks, "deployments": [], "ok": False}
    intel = verify_quote(cm["quote"])
    checks["cm_quote_verified"] = intel.status in ("UpToDate", "OutOfDate")
    checks["cm_tcb_current"] = intel.status in dstack_tdx.TCB_CURRENT_STATUSES
    recomputed = actions_hash(cm["actions"])
    checks["actions_hash_recomputed"] = recomputed == cm["actions_hash"].lower()
    cmq, mq = dstack_tdx.parse_quote(cm["quote"]), dstack_tdx.parse_quote(model_quote_hex)
    checks["report_data_binds_log_and_nonce"] = cmq["report_data"].lower() == recomputed + nonce.lower()
    checks["same_cvm_as_model"] = all(cmq[r] == mq[r] for r in REGISTERS)

    deps = running_deployments(cm["actions"])
    cutoff = now.timestamp() - min_age_s
    for d in deps:
        seen = archive.get(archive_key(d))
        d["public_sha256_matches"] = bool(d["file_sha256"]) and fetch_sha256(d["commit"], d["file"]) == d["file_sha256"]
        d["first_seen"] = seen["first_seen"] if seen else None
        d["aged"] = bool(seen and seen["file_sha256"] == d["file_sha256"]
                         and datetime.fromisoformat(seen["first_seen"]).timestamp() <= cutoff)
    out["deployments"] = deps
    checks["deployments_public"] = bool(deps) and all(d["public_sha256_matches"] for d in deps)
    checks["deployments_aged"] = bool(deps) and all(d["aged"] for d in deps)
    out["ok"] = all(checks.values())
    out["min_age_s"] = min_age_s
    return out


def record(deployments: List[Dict], archive: Dict[str, Dict], now: datetime) -> int:
    """Add publicly verified deployments not yet seen. Returns how many were added."""
    added = 0
    for d in deployments:
        if d.get("public_sha256_matches") and archive_key(d) not in archive:
            archive[archive_key(d)] = {"file_sha256": d["file_sha256"], "tag": d["tag"],
                                       "first_seen": now.isoformat()}
            added += 1
    return added


def save_archive(archive: Dict[str, Dict], path: Path = ARCHIVE_PATH) -> None:
    path.write_text(json.dumps(dict(sorted(archive.items())), indent=2) + "\n")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)
