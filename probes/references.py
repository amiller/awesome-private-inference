"""Bounded, read-only captures of public reference publications and catalogs.

These are publication observations, not signature, quote, or client-policy verdicts.
Raw bodies are stored by SHA-256 so repeat runs never rewrite an observation.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import requests


MAX_BYTES = 2_000_000
USER_AGENT = "awesome-private-inference-reference-observatory/1.0"
MAPLE_CANONICAL = "https://raw.githubusercontent.com/MaplePrivacyLabs/Maple/master/services/opensecret/"
MAPLE_LEGACY = "https://raw.githubusercontent.com/OpenSecretCloud/opensecret/master/"


def sources() -> list[dict]:
    rows = []
    for name in ("pcrProd.json", "pcrProdHistory.json", "pcrDev.json", "pcrDevHistory.json"):
        rows.extend((
            {"id": f"maple-canonical-{name}", "provider": "maple", "url": MAPLE_CANONICAL + name, "kind": "pcr_publication"},
            {"id": f"maple-legacy-{name}", "provider": "maple", "url": MAPLE_LEGACY + name, "kind": "pcr_compatibility_mirror"},
        ))
    rows.extend([
        {"id": "maple-typescript-pcr-policy", "provider": "maple", "url": "https://raw.githubusercontent.com/MaplePrivacyLabs/Maple/master/sdk/src/lib/pcr.ts", "kind": "client_source_policy"},
        {"id": "maple-rust-pcr-policy", "provider": "maple", "url": "https://raw.githubusercontent.com/MaplePrivacyLabs/Maple/master/sdk/rust/src/pcr.rs", "kind": "client_source_policy"},
        {"id": "maple-research-client-config", "provider": "maple", "url": "https://raw.githubusercontent.com/MaplePrivacyLabs/Maple/master/apps/maple-research/frontend/src/config/openSecretClientConfig.ts", "kind": "client_source_policy"},
        {"id": "privatemode-manifest", "provider": "privatemode", "url": "https://cdn.confidential.cloud/privatemode/v2/manifest.json", "kind": "manifest"},
        {"id": "confidential-ai-allowlist", "provider": "confidential-ai", "url": "https://api.confidential.ai/allowlist", "kind": "allowlist"},
        {"id": "confidential-ai-releases", "provider": "confidential-ai", "url": "https://api.github.com/repos/confidential-dot-ai/confidential-inference/releases?per_page=10", "kind": "release_metadata"},
        {"id": "confidential-ai-observed-release", "provider": "confidential-ai", "url": "https://api.github.com/repos/confidential-dot-ai/confidential-inference/releases/tags/v0.13.28-rc.2", "kind": "observed_release_metadata"},
        {"id": "private-inference-catalog", "provider": "private-inference", "url": "https://privateinference.gg/v1/models", "kind": "model_catalog"},
        {"id": "private-inference-chat-html", "provider": "private-inference", "url": "https://privateinference.gg/chat", "kind": "browser_entrypoint"},
    ])
    return rows


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _safe_slug(source_id: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_.-]", "_", source_id)


def _portable_base(output_dir: Path) -> str | None:
    """Only repository-relative paths may enter tracked observation metadata."""
    root = Path(__file__).resolve().parents[1]
    try:
        return output_dir.resolve().relative_to(root).as_posix()
    except ValueError:
        return None


def _fetch(session: requests.Session, url: str, timeout: float, max_bytes: int = MAX_BYTES, headers: dict | None = None) -> tuple[int, bytes, str]:
    if urlparse(url).scheme != "https":
        raise ValueError("HTTPS required")
    with session.get(url, headers={"User-Agent": USER_AGENT, **(headers or {})}, timeout=timeout, stream=True, allow_redirects=True) as response:
        body = bytearray()
        for chunk in response.iter_content(chunk_size=65536):
            body.extend(chunk)
            if len(body) > max_bytes:
                raise ValueError(f"body exceeds {max_bytes} byte limit")
        return response.status_code, bytes(body), response.url


def _observe(source: dict, output_dir: Path, session: requests.Session, timeout: float, headers: dict | None = None) -> dict:
    row = {"source_id": source["id"], "provider": source["provider"], "kind": source["kind"], "raw_base": _portable_base(output_dir),
           "url": source["url"], "observed_at": _utc(), "status": "error", "verification": "not_performed"}
    try:
        code, body, final_url = _fetch(session, source["url"], timeout, headers=headers)
        if urlparse(final_url).scheme != "https":
            raise ValueError("redirect left HTTPS")
        row.update(http_status=code, final_url=final_url)
        if code != 200:
            row["error"] = f"HTTP {code}"
            return row
        digest = hashlib.sha256(body).hexdigest()
        raw_dir = output_dir / "raw"
        raw_dir.mkdir(parents=True, exist_ok=True)
        path = raw_dir / f"{_safe_slug(source['id'])}-{digest}.bin"
        if not path.exists():
            try:
                with path.open("xb") as archive:
                    archive.write(body)
            except FileExistsError:
                pass
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ValueError(f"stored archive hash mismatch: {source['id']}")
        row.update(status="observed", sha256=digest, bytes=len(body), raw_path=str(path.relative_to(output_dir)))
        if source["kind"] == "model_catalog":
            try:
                catalog = json.loads(body)
                models = catalog.get("data", catalog.get("models", []))
                identities = []
                for model in models:
                    if not isinstance(model, dict) or not model.get("id"):
                        continue
                    tiers = model.get("pricing", {})
                    routing = {tier: sorted(value.get("providers", [])) for tier, value in tiers.items()
                               if isinstance(value, dict) and value.get("providers")}
                    identities.append({"id": model["id"], "routing": routing})
                row["model_ids"] = sorted(item["id"] for item in identities)
                row["semantic_sha256"] = hashlib.sha256(json.dumps(sorted(identities, key=lambda x: x["id"]), sort_keys=True).encode()).hexdigest()
            except (ValueError, AttributeError, TypeError) as exc:
                row["parse_error"] = f"{type(exc).__name__}: {exc}"
        return row
    except (requests.RequestException, ValueError, OSError) as exc:
        row["error"] = f"{type(exc).__name__}: {exc}"
        return row


def _save_run(output_dir: Path, prefix: str, rows: list[dict]) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    payload = {"schema_version": "1", "captured_at": _utc(), "meaning": "read_only_publication_observation", "observations": rows}
    raw = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()
    digest = hashlib.sha256(raw).hexdigest()[:16]
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    path = output_dir / f"{prefix}-{stamp}-{digest}.json"
    path.write_bytes(raw)
    return path


def write_index(rows: list[dict], index_path: str | Path) -> dict:
    """Derive a stable latest view and immutable state-transition events.

    A failed attempt retains the last successful digest. Event IDs are content
    addressed and each event is written once for queue ingestion.
    """
    index_path = Path(index_path)
    old = json.loads(index_path.read_text()) if index_path.exists() else {}
    prior = {r["source_id"]: r for r in old.get("observations", [])}
    try:
        routes = json.loads((Path(__file__).resolve().parents[1] / "data/routes.json").read_text())["routes"]
    except (OSError, ValueError, KeyError):
        routes = []

    def emit(fact: dict) -> None:
        fact["kind"] = fact["type"]
        fact["route_id"] = "publication/" + fact["source_id"]
        fact["affected_routes"] = [route["id"] for route in routes if route.get("provider") == fact["provider"]]
        fact["priority"] = "high" if fact["type"] in ("publication_error", "publication_missing", "reference_mismatch") else "medium"
        event_id = hashlib.sha256(json.dumps(fact, sort_keys=True).encode()).hexdigest()
        event = {"event_id": event_id, **fact}
        events.append(event)
        path = index_path.parent / "events" / f"{event_id}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            if json.loads(path.read_text()) != event:
                raise ValueError(f"immutable event differs: {event_id}")
        else:
            with path.open("x") as output:
                output.write(json.dumps(event, indent=2, sort_keys=True) + "\n")

    current = []
    events = []
    for row in rows:
        previous = prior.get(row["source_id"])
        current_row = dict(row)
        if row["status"] == "observed":
            current_row["last_success"] = {k: row[k] for k in ("observed_at", "sha256", "bytes", "raw_base", "raw_path") if k in row}
        elif previous and previous.get("last_success"):
            current_row["last_success"] = previous["last_success"]
        current.append(current_row)
        if previous is None:
            continue  # first capture establishes a baseline, not a change event
        old_status, new_status = previous["status"], row["status"]
        old_hash = previous.get("last_success", {}).get("sha256")
        new_hash = row.get("sha256")
        old_semantic = previous.get("semantic_sha256")
        new_semantic = row.get("semantic_sha256")
        event_type = None
        if old_status == "observed" and new_status != "observed":
            event_type = "publication_missing" if row.get("http_status") in (404, 410) else "publication_error"
        elif old_status != "observed" and new_status != "observed" and previous.get("http_status") != row.get("http_status"):
            event_type = "publication_missing" if row.get("http_status") in (404, 410) else "publication_error"
        elif old_status != "observed" and new_status == "observed":
            event_type = "publication_recovered"
        elif old_status == "observed" and new_status == "observed":
            if previous.get("kind") == "model_catalog" and old_semantic and new_semantic:
                if old_semantic != new_semantic:
                    event_type = "catalog_changed"
            elif old_hash != new_hash:
                event_type = "publication_changed"
        if event_type:
            fact = {"source_id": row["source_id"], "provider": row["provider"], "type": event_type,
                    "timestamp": row["observed_at"], "previous_sha256": old_hash,
                    "current_sha256": new_hash, "previous_status": old_status, "current_status": new_status,
                    "url": row.get("url"), "verification": "not_performed"}
            emit(fact)
    # A source not polled in this run (for example a weekly catalog during a
    # daily publication pass) keeps its prior observation. Absence is not a
    # disappearance signal unless that named source was actually fetched.
    current.extend(r for source_id, r in prior.items() if source_id not in {x["source_id"] for x in rows})
    by_id = {r["source_id"]: r for r in current}
    agreements = {}
    for name in ("pcrProd.json", "pcrProdHistory.json", "pcrDev.json", "pcrDevHistory.json"):
        canonical = by_id.get(f"maple-canonical-{name}", {})
        legacy = by_id.get(f"maple-legacy-{name}", {})
        if canonical.get("status") == legacy.get("status") == "observed":
            matches = canonical["sha256"] == legacy["sha256"]
            agreements[name] = matches
            if not matches and old.get("mirror_agreements", {}).get(name) is not False:
                emit({"source_id": f"maple-mirror-{name}", "provider": "maple", "type": "reference_mismatch",
                      "timestamp": max(canonical["observed_at"], legacy["observed_at"]),
                      "previous_sha256": canonical["sha256"], "current_sha256": legacy["sha256"],
                      "previous_status": "canonical", "current_status": "legacy", "url": legacy["url"],
                      "verification": "byte_comparison_only"})
            elif matches and old.get("mirror_agreements", {}).get(name) is False:
                emit({"source_id": f"maple-mirror-{name}", "provider": "maple", "type": "reference_agreement_restored",
                      "timestamp": max(canonical["observed_at"], legacy["observed_at"]),
                      "previous_sha256": None, "current_sha256": canonical["sha256"],
                      "previous_status": "mismatch", "current_status": "match", "url": legacy["url"],
                      "verification": "byte_comparison_only"})
    summary = {}
    for row in current:
        counts = summary.setdefault(row["provider"], {"observed": 0, "error": 0})
        counts[row["status"]] = counts.get(row["status"], 0) + 1
    index = {"schema_version": "1", "generated_at": _utc(), "meaning": "publication observation only; no signature, quote, or client acceptance verification",
             "observations": current, "summaries": summary, "mirror_agreements": agreements, "changes": events}
    index_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = index_path.with_name(f".{index_path.name}.{uuid.uuid4().hex}.tmp")
    try:
        temporary.write_text(json.dumps(index, indent=2, sort_keys=True) + "\n")
        os.replace(temporary, index_path)
    finally:
        if temporary.exists():
            temporary.unlink()
    return index


def capture_publications(output_dir: str | Path, timeout: float = 15, session: requests.Session | None = None) -> list[dict]:
    """Capture every named small publication; retain per-source errors and raw bytes."""
    output_dir = Path(output_dir)
    own_session = session is None
    session = session or requests.Session()
    try:
        rows = [_observe(source, output_dir, session, timeout) for source in sources()]
        # Resolve one bounded import chain: page -> chat main -> private verifier.
        # Main is a shell asset and must never be compared with verifier code.
        entry = next(r for r in rows if r["source_id"] == "private-inference-chat-html")
        if entry["status"] == "observed":
            html = (output_dir / entry["raw_path"]).read_text(errors="replace")
            matches = re.findall(r'<script[^>]+type=["\']module["\'][^>]+src=["\'](/chat/js/[^"\'<>\s]+\.js)', html)
            if matches:
                asset = matches[0]
                main = _observe({"id": "private-inference-chat-main", "provider": "private-inference",
                                 "url": "https://privateinference.gg" + asset, "kind": "deployed_chat_entry_module"}, output_dir, session, timeout)
                rows.append(main)
                if main["status"] == "observed":
                    module = (output_dir / main["raw_path"]).read_text(errors="replace")
                    verifier_imports = sorted(set(re.findall(r'import\(["\']\./(browser-[a-zA-Z0-9_-]+\.js)["\']\)', module)))
                    if len(verifier_imports) == 1:
                        rows.append(_observe({"id": "private-inference-browser-verifier", "provider": "private-inference",
                                              "url": "https://privateinference.gg/chat/js/" + verifier_imports[0],
                                              "kind": "deployed_private_verifier_module"}, output_dir, session, timeout))
                    else:
                        rows.append({"source_id": "private-inference-browser-verifier", "provider": "private-inference",
                                     "kind": "deployed_private_verifier_module", "status": "error",
                                     "error": f"expected one private verifier import; found {len(verifier_imports)}",
                                     "observed_at": _utc(), "verification": "not_performed"})
            else:
                rows.append({"source_id": "private-inference-chat-main", "provider": "private-inference",
                             "kind": "deployed_chat_entry_module", "status": "error", "error": "module script absent from captured HTML",
                             "observed_at": _utc(), "verification": "not_performed"})
        for source_id, kind in (("private-inference-chat-main", "deployed_chat_entry_module"),
                                ("private-inference-browser-verifier", "deployed_private_verifier_module")):
            if not any(row["source_id"] == source_id for row in rows):
                rows.append({"source_id": source_id, "provider": "private-inference", "kind": kind,
                             "status": "error", "error": "import chain unavailable in this capture",
                             "observed_at": _utc(), "verification": "not_performed"})
        _save_run(output_dir, "publications", rows)
        return rows
    finally:
        if own_session:
            session.close()


CATALOGS = [
    {"id": "near-ai-models", "provider": "near-ai", "url": "https://cloud-api.near.ai/v1/models", "kind": "model_catalog", "env": "NEAR_API_KEY"},
    {"id": "chutes-models", "provider": "chutes", "url": "https://llm.chutes.ai/v1/models", "kind": "model_catalog", "env": "CHUTES_API_KEY"},
    {"id": "venice-models", "provider": "venice", "url": "https://api.venice.ai/api/v1/models", "kind": "model_catalog", "env": "VENICE_API_KEY"},
]


def discover_catalogs(output_dir: str | Path, api_keys: dict[str, str] | None = None,
                      timeout: float = 15, session: requests.Session | None = None) -> list[dict]:
    """Read model catalogs. Credentials are never serialized; no sentinels are changed."""
    output_dir = Path(output_dir)
    api_keys = api_keys or {}
    own_session = session is None
    session = session or requests.Session()
    rows = []
    try:
        for source in CATALOGS:
            key = api_keys.get(source["provider"]) or os.environ.get(source["env"], "")
            headers = {"Authorization": f"Bearer {key}"} if key else None
            row = _observe(source, output_dir, session, timeout, headers=headers)
            row["credential_used"] = bool(key)
            rows.append(row)
        _save_run(output_dir, "discovery", rows)
        return rows
    finally:
        if own_session:
            session.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", default="data/references/observations")
    parser.add_argument("--index", default="data/references/latest.json")
    parser.add_argument("--catalogs", action="store_true", help="also discover NEAR, Chutes and Venice catalogs")
    args = parser.parse_args()
    rows = capture_publications(args.output_dir)
    if args.catalogs:
        rows += discover_catalogs(args.output_dir)
    write_index(rows, args.index)
    for row in rows:
        print(f"{row['source_id']}: {row['status']} {row.get('sha256', row.get('error', ''))}")


if __name__ == "__main__":
    main()
